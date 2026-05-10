"""Vault: on-disk layout and high-level CRUD operations.

Layout
------

::

    ~/.cavern/
        master.gpg         # GPG-encrypted KEK
        master.json        # AES-GCM-encrypted master_key (wrapped under wrap_key)
        recipients         # plaintext list of GPG recipients (for re-encrypts)
        manifest           # AES-GCM-encrypted listing index (under master_key)
        store/
            <hmac32>       # one file per secret, AES-GCM with per-file DEK

The KEK lives only inside ``master.gpg`` (and, transiently, in the
session cache). The rotatable master key is stored separately in
``master.json``, wrapped under a key derived from the KEK. Filenames
under ``store/`` are HMAC-SHA256 of the secret name keyed by
``derive_filename_key(KEK)``, truncated to 16 bytes (32 hex chars).

The ``manifest`` file is an AES-GCM blob (under the master key, same
crypto as secrets) containing a JSON dict mapping ``hmac32 →
{"name": ..., "tags": [...]}``. It exists only to support fast
listing and tag search; lookup-by-name does not consult it.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import secrets as _secrets_module
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import crypto
from .crypto import (
    KEK_LENGTH,
    MASTER_KEY_LENGTH,
    WrappedMasterKey,
)
from .exceptions import (
    CryptoError,
    ManifestError,
    NotInitializedError,
    SecretExistsError,
    SecretNotFoundError,
    StoreError,
)

DEFAULT_VAULT_DIR = Path.home() / ".cavern"
MASTER_GPG = "master.gpg"
MASTER_JSON = "master.json"
RECIPIENTS_FILE = "recipients"
MANIFEST_FILE = "manifest"
STORE_DIR = "store"


def _time_now() -> int:
    """Wallclock seconds since epoch, as an integer.

    Wrapped so tests can monkeypatch a deterministic value when
    they need to assert on a generated filename.
    """
    return int(time.time())


@contextlib.contextmanager
def _vault_lock(lock_path: Path) -> Iterator[None]:
    """Exclusive flock-based mutual exclusion across processes.

    Used to serialize manifest read-modify-write cycles so two
    concurrent ``cavern insert`` calls cannot clobber each other's
    manifest update. The lock is held for the duration of the ``with``
    block; on POSIX, ``flock`` is released when the file descriptor
    closes, including on process death, so a crashed cavern leaves no
    stale lock.

    The lock file lives at ``<vault>/.lock`` and is created with 0o600.
    Note: ``flock`` is advisory — only cooperating processes (i.e.,
    cavern itself) honor it. Other tools editing the vault directory
    are not blocked.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# ---- Atomic write helper ---------------------------------------------------


def _atomic_write(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` atomically with restrictive permissions.

    A failed write leaves the original file untouched. The temp file is
    created in the destination directory (so ``os.replace`` is atomic
    on the same filesystem) with the final permissions already set,
    never with default 0o644.

    Durability: we ``fsync`` the file descriptor before rename so the
    bytes are on disk, and ``fsync`` the parent directory after rename
    so the rename itself is durable. A power loss after this call
    completes is guaranteed to either show the new file or the old
    file, never a half-written one. On filesystems where directory
    ``fsync`` isn't supported (rare; not POSIX-mandated), we ignore
    the error.

    Cleanup uses ``BaseException`` rather than ``Exception`` so that
    ``KeyboardInterrupt`` mid-write also cleans up the temp file
    instead of leaving ``.tmp.<random>`` debris in the vault.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_str = tempfile.mkstemp(dir=path.parent, prefix=".tmp.")
    tmp_path = Path(tmp_str)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise

    # Best-effort directory fsync to make the rename durable. Not
    # supported on every filesystem; we ignore errors here.
    try:
        dir_fd = os.open(path.parent, os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


# ---- Manifest --------------------------------------------------------------


@dataclass(frozen=True)
class ManifestEntry:
    """Immutable metadata for one secret.

    Attributes
    ----------
    name : str
        The original (plaintext) secret name.
    tags : tuple[str, ...]
        Lowercase, deduplicated tag list. A tuple (rather than a
        list) so the dataclass can be ``frozen``; we accept the
        small inconvenience at the call sites in exchange for
        immutability matching the rest of the codebase.
    """

    name: str
    tags: tuple[str, ...]


def _decode_manifest(blob: bytes) -> dict[str, ManifestEntry]:
    """Parse the decrypted manifest JSON into a dict keyed by hmac32."""
    try:
        payload = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"Manifest is corrupt: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ManifestError("Manifest has unknown version.")
    entries_raw = payload.get("entries", {})
    if not isinstance(entries_raw, dict):
        raise ManifestError("Manifest 'entries' must be a dict.")
    out: dict[str, ManifestEntry] = {}
    for stored, record in entries_raw.items():
        if not isinstance(record, dict):
            continue
        out[stored] = ManifestEntry(
            name=str(record.get("name", "")),
            tags=tuple(str(t) for t in record.get("tags", [])),
        )
    return out


def _encode_manifest(entries: dict[str, ManifestEntry]) -> bytes:
    payload = {
        "version": 1,
        "entries": {
            stored: {"name": entry.name, "tags": list(entry.tags)}
            for stored, entry in entries.items()
        },
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


# ---- Vault -----------------------------------------------------------------


@dataclass(frozen=True)
class UnlockedKeys:
    """The two keys produced by unlocking the vault.

    ``kek`` is what's actually decrypted from ``master.gpg`` (and what
    sits in the session cache). ``master_key`` is the rotatable inner
    key that wraps per-file DEKs and encrypts the manifest.
    """

    kek: bytes
    master_key: bytes


class Vault:
    """High-level operations on a cavern vault.

    Parameters
    ----------
    root : pathlib.Path or None, optional
        Vault root directory. Defaults to ``$CAVERN_VAULT_DIR`` when
        set, else ``~/.cavern``.
    """

    def __init__(self, root: Path | None = None) -> None:
        if root is not None:
            self.root = root
        else:
            env = os.environ.get("CAVERN_VAULT_DIR")
            self.root = Path(env) if env else DEFAULT_VAULT_DIR

        # Single-entry cache: most CLI invocations only ever see one
        # KEK. We key on the bytes themselves so cache invalidation
        # happens automatically when the caller passes a different KEK.
        self._filename_key_cache: tuple[bytes, bytes] | None = None

    def _filename_key_for(self, kek: bytes) -> bytes:
        """Return the filename HMAC key for ``kek``, caching the result.

        ``derive_filename_key`` is fast (HKDF-SHA256, microseconds) but
        gets called once per ``secret_path`` invocation, which adds up
        on bulk operations like rotation. Caching trades a tiny amount
        of memory for a measurable speedup on workloads that touch
        many secrets in one CLI invocation.
        """
        if self._filename_key_cache is not None:
            cached_kek, cached_fk = self._filename_key_cache
            if cached_kek == kek:
                return cached_fk
        fk = crypto.derive_filename_key(kek)
        self._filename_key_cache = (kek, fk)
        return fk

    # ---- Path helpers -----------------------------------------------------

    @property
    def master_gpg_path(self) -> Path:
        return self.root / MASTER_GPG

    @property
    def master_json_path(self) -> Path:
        return self.root / MASTER_JSON

    @property
    def recipients_path(self) -> Path:
        """Path to the plaintext list of GPG recipients.

        This file is **deliberately plaintext**: re-encrypting
        ``master.gpg`` after adding or removing a recipient requires
        knowing which keys to encrypt to, which is exactly what this
        file records. Anyone with read access to the vault directory
        can see who the GPG recipients are. For most threat models
        this is acceptable (the recipients are typically the user's
        own key plus maybe a backup key); if it isn't, store the
        recipients out-of-band and pass them on the command line each
        time.
        """
        return self.root / RECIPIENTS_FILE

    @property
    def manifest_path(self) -> Path:
        return self.root / MANIFEST_FILE

    @property
    def store_path(self) -> Path:
        return self.root / STORE_DIR

    @property
    def lock_path(self) -> Path:
        """Path of the advisory ``flock`` file.

        Lives in the vault root rather than under store/ so it
        doesn't show up next to encrypted secrets.
        """
        return self.root / ".lock"

    def lock(self) -> contextlib.AbstractContextManager[None]:
        """Take the per-vault exclusive lock.

        Used to serialize manifest read-modify-write cycles across
        concurrent ``cavern`` processes. Returns a context manager —
        callers should use ``with vault.lock():`` around any
        operation that updates the manifest.
        """
        return _vault_lock(self.lock_path)

    def is_initialized(self) -> bool:
        return self.master_gpg_path.is_file() and self.master_json_path.is_file()

    def recipients(self) -> list[str]:
        if not self.recipients_path.is_file():
            raise NotInitializedError(
                f"No vault at {self.root}. Run `cavern init <gpg-id>` first."
            )
        return [
            line.strip()
            for line in self.recipients_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    # ---- Lifecycle --------------------------------------------------------

    def init(self, recipients: list[str]) -> UnlockedKeys:
        """Create a new vault.

        Generates a fresh KEK and master key, GPG-encrypts the KEK to
        the recipients, wraps the master key under the KEK-derived
        wrap key, writes the empty manifest, and returns the keys so
        the caller can immediately use them (no GPG roundtrip needed
        for the very first operation).
        """
        if not recipients:
            raise StoreError("init requires at least one GPG recipient.")
        if self.is_initialized():
            raise StoreError(f"Vault already initialized at {self.root}.")

        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.store_path.mkdir(exist_ok=True)
        os.chmod(self.store_path, 0o700)

        kek = _secrets_module.token_bytes(KEK_LENGTH)
        master_key = _secrets_module.token_bytes(MASTER_KEY_LENGTH)

        # Persist GPG-encrypted KEK and JSON-encoded wrapped master key.
        gpg_blob = crypto.gpg_encrypt_to_recipients(kek, recipients)
        _atomic_write(self.master_gpg_path, gpg_blob)

        wrap_key = crypto.derive_wrap_key(kek)
        wrapped = crypto.wrap_master_key(master_key, wrap_key)
        _atomic_write(self.master_json_path, _serialize_wrapped(wrapped))

        _atomic_write(
            self.recipients_path,
            ("\n".join(recipients) + "\n").encode("utf-8"),
            mode=0o600,
        )

        # Empty manifest.
        empty = _encode_manifest({})
        _atomic_write(self.manifest_path, crypto.encrypt_secret(empty, master_key))

        return UnlockedKeys(kek=kek, master_key=master_key)

    def unlock_with_gpg(self) -> bytes:
        """Decrypt ``master.gpg`` and return the KEK.

        This always invokes GPG. Use :meth:`unlock` for a session-aware
        unlock that prefers the cached KEK.
        """
        if not self.is_initialized():
            raise NotInitializedError(f"No vault at {self.root}.")
        kek = crypto.gpg_decrypt(self.master_gpg_path)
        if len(kek) != KEK_LENGTH:
            raise CryptoError(
                f"Decrypted KEK is {len(kek)} bytes; expected {KEK_LENGTH}."
            )
        return kek

    def derive_keys(self, kek: bytes) -> UnlockedKeys:
        """Given a KEK, unwrap and return the master key alongside it."""
        wrapped = _deserialize_wrapped(self.master_json_path.read_bytes())
        wrap_key = crypto.derive_wrap_key(kek)
        master_key = crypto.unwrap_master_key(wrapped, wrap_key)
        return UnlockedKeys(kek=kek, master_key=master_key)

    # ---- Lookup-by-name (manifest-free) ----------------------------------

    def secret_path(self, kek: bytes, name: str) -> Path:
        """Return the on-disk path for ``name``, computed via HMAC.

        Does not consult the manifest. Strips leading/trailing
        whitespace so callers can pass ``"foo"`` and ``"foo "``
        interchangeably, then computes the HMAC over the normalized
        name to ensure both forms map to the same file.

        Resolves through the filesystem and verifies the resolved path
        is still under ``store/``. The HMAC output is hex (no ``/``,
        no ``..``) so traversal is unreachable in practice; the check
        is defense in depth against bugs and against an attacker who
        replaces an existing HMAC file with a symlink to elsewhere.
        """
        normalized = name.strip()
        if not normalized:
            raise StoreError("Secret name cannot be empty.")
        filename_key = self._filename_key_for(kek)
        stored = crypto.stored_filename(filename_key, normalized)
        path = (self.store_path / stored).resolve()
        if self.store_path.resolve() not in path.parents:
            raise StoreError(f"Path traversal detected for {name!r}.")
        return path

    def _normalize_name(self, name: str) -> str:
        """Return the canonical form of a secret name.

        Stripped of leading/trailing whitespace; raises
        :class:`StoreError` if empty after stripping. Use this at the
        boundary of every public method so the manifest, the HMAC,
        and what we display back to the user are all consistent.
        """
        normalized = name.strip()
        if not normalized:
            raise StoreError("Secret name cannot be empty.")
        return normalized

    # ---- CRUD -------------------------------------------------------------

    def insert(
        self,
        keys: UnlockedKeys,
        name: str,
        plaintext: bytes,
        *,
        force: bool = False,
    ) -> Path:
        """Encrypt and store a secret.

        Holds the vault lock for the duration so two concurrent
        ``cavern insert`` calls cannot race the manifest update.

        The secret name is normalized via :meth:`_normalize_name`
        before being used; the normalized form is what's stored in
        the manifest and what subsequent ``show``/``ls`` calls return.
        """
        normalized = self._normalize_name(name)
        with self.lock():
            path = self.secret_path(keys.kek, normalized)
            if path.exists() and not force:
                raise SecretExistsError(
                    f"Secret {normalized!r} already exists. Use --force to overwrite."
                )
            blob = crypto.encrypt_secret(plaintext, keys.master_key)
            _atomic_write(path, blob)
            self._manifest_set(keys, normalized, tags=None)
            return path

    def show(self, keys: UnlockedKeys, name: str) -> bytes:
        """Decrypt and return a secret's plaintext.

        No lock — reads are cheap and a concurrent mutation either
        completes before our ``read_bytes`` (we get the new content)
        or after (we get the old content). Either is consistent.
        """
        normalized = self._normalize_name(name)
        path = self.secret_path(keys.kek, normalized)
        if not path.is_file():
            raise SecretNotFoundError(f"Secret not found: {normalized!r}")
        blob = path.read_bytes()
        return crypto.decrypt_secret(blob, keys.master_key)

    def remove(self, keys: UnlockedKeys, name: str) -> None:
        normalized = self._normalize_name(name)
        with self.lock():
            path = self.secret_path(keys.kek, normalized)
            if not path.is_file():
                raise SecretNotFoundError(f"Secret not found: {normalized!r}")
            path.unlink()
            self._manifest_remove(keys, normalized)

    def move(
        self,
        keys: UnlockedKeys,
        source: str,
        target: str,
        *,
        force: bool = False,
    ) -> None:
        """Rename a secret. Moves the file (cheap) and updates the manifest."""
        source_norm = self._normalize_name(source)
        target_norm = self._normalize_name(target)
        with self.lock():
            src = self.secret_path(keys.kek, source_norm)
            if not src.is_file():
                raise SecretNotFoundError(f"Secret not found: {source_norm!r}")
            dst = self.secret_path(keys.kek, target_norm)
            if dst.exists() and not force:
                raise SecretExistsError(
                    f"Target {target_norm!r} already exists. "
                    "Use --force to overwrite."
                )
            src.rename(dst)

            # Carry tags forward.
            manifest = self._manifest_load(keys)
            filename_key = self._filename_key_for(keys.kek)
            old_stored = crypto.stored_filename(filename_key, source_norm)
            new_stored = crypto.stored_filename(filename_key, target_norm)
            old_tags = manifest.pop(old_stored, ManifestEntry(name="", tags=())).tags
            manifest[new_stored] = ManifestEntry(name=target_norm, tags=old_tags)
            self._manifest_save(keys, manifest)

    # ---- Listing & search (via manifest) ---------------------------------

    def list_names(self, keys: UnlockedKeys) -> list[str]:
        """Return all secret names, sorted.

        Reads the manifest only — does not scan the filesystem. Use
        :meth:`audit_drift` to detect divergence.
        """
        manifest = self._manifest_load(keys)
        return sorted(entry.name for entry in manifest.values() if entry.name)

    def find(self, keys: UnlockedKeys, pattern: str) -> list[str]:
        """Case-insensitive substring search over secret names."""
        needle = pattern.lower()
        return [name for name in self.list_names(keys) if needle in name.lower()]

    def search_by_tag(self, keys: UnlockedKeys, tag: str) -> list[str]:
        needle = tag.strip().lower()
        manifest = self._manifest_load(keys)
        return sorted(
            entry.name
            for entry in manifest.values()
            if entry.name and needle in entry.tags
        )

    def all_tags(self, keys: UnlockedKeys) -> list[str]:
        manifest = self._manifest_load(keys)
        seen: set[str] = set()
        for entry in manifest.values():
            seen.update(entry.tags)
        return sorted(seen)

    def set_tags(self, keys: UnlockedKeys, name: str, tags: list[str]) -> None:
        normalized_name = self._normalize_name(name)
        with self.lock():
            # Confirm the secret exists before recording tags.
            if not self.secret_path(keys.kek, normalized_name).is_file():
                raise SecretNotFoundError(f"Secret not found: {normalized_name!r}")
            normalized_tags = sorted(
                {tag.strip().lower() for tag in tags if tag.strip()}
            )
            self._manifest_set(keys, normalized_name, tags=normalized_tags)

    # ---- Drift detection -------------------------------------------------

    def audit_drift(self, keys: UnlockedKeys) -> tuple[list[str], list[str]]:
        """Return ``(orphans, missing)``.

        ``orphans`` are filenames present in ``store/`` but not in the
        manifest. ``missing`` are manifest entries whose backing file
        is gone. Both are signs of out-of-band edits and should be
        rare in practice.

        Returns ``([], [])`` if the vault is uninitialized; the caller
        gets a clean answer rather than a ``FileNotFoundError`` from
        ``iterdir``.
        """
        manifest = self._manifest_load(keys)
        if not self.store_path.is_dir():
            return [], sorted(entry.name for entry in manifest.values())
        on_disk = {p.name for p in self.store_path.iterdir() if p.is_file()}
        orphans = sorted(on_disk - manifest.keys())
        missing = sorted(
            entry.name for stored, entry in manifest.items() if stored not in on_disk
        )
        return orphans, missing

    def reindex(self, keys: UnlockedKeys) -> int:
        """Drop manifest entries whose files are gone. Returns count removed.

        We can't recover orphan files (their original names are lost
        when the manifest line for them is gone), but we can at least
        clean up dead entries.
        """
        with self.lock():
            manifest = self._manifest_load(keys)
            on_disk = {p.name for p in self.store_path.iterdir() if p.is_file()}
            before = len(manifest)
            manifest = {k: v for k, v in manifest.items() if k in on_disk}
            self._manifest_save(keys, manifest)
            return before - len(manifest)

    # ---- Master-key rotation --------------------------------------------

    def rotate_master_key(self, keys: UnlockedKeys) -> int:
        """Generate a new master key and re-wrap every file's DEK under it.

        Content ciphertexts of secrets are not re-encrypted, only the
        wrapped DEK in each file's header. The manifest and audit log
        ARE fully re-encrypted, since they're encrypted with the
        master key directly (no DEK indirection). Filenames don't
        change because they're derived from the KEK, not the master
        key.

        Crash safety
        ------------

        Each per-file rewrap is atomic via temp-file-and-rename, but
        the overall rotation is not transactional: a crash mid-loop
        can leave some files rewrapped under the new master key and
        some still under the old. To make recovery tractable, this
        method is **idempotent**: it tries decrypting each file with
        the new master key first, and only falls back to the old key
        when needed. Re-running ``rotate_master_key`` after a crash
        therefore safely completes whatever is left, provided
        ``master.json`` is still consistent with what the caller
        passed in via ``keys``.

        If the crash happened *after* every file was rewrapped but
        *before* ``master.json`` was updated, a fresh ``cavern unlock``
        will derive the *old* master key from ``master.json``, which
        no longer decrypts any file. Recovery in that narrow window
        requires manual intervention. We document the limitation
        rather than try to be clever.

        Returns the number of secret files actually rewrapped (not
        counting files that were already on the new key from a prior
        partial run).
        """
        with self.lock():
            return self._rotate_master_key_locked(keys)

    def _rotate_master_key_locked(self, keys: UnlockedKeys) -> int:
        """Body of :meth:`rotate_master_key`; assumes the lock is held."""
        new_master = _secrets_module.token_bytes(MASTER_KEY_LENGTH)
        old_master = keys.master_key

        rewrapped_count = 0
        for path in self.store_path.iterdir():
            if not path.is_file():
                continue
            blob = path.read_bytes()

            # Idempotency: if the file is already on the new master
            # key (from a prior partial rotation), leave it alone.
            try:
                crypto.decrypt_secret(blob, new_master)
                continue
            except CryptoError:
                pass

            new_blob = crypto.rewrap_master_key_in_blob(blob, old_master, new_master)
            _atomic_write(path, new_blob)
            rewrapped_count += 1

        # Re-encrypt the manifest under the new master key. Idempotent
        # via the same try-new-first pattern: if a partial rotation
        # already updated it, leave it alone.
        manifest_already_new = False
        if self.manifest_path.is_file():
            try:
                crypto.decrypt_secret(self.manifest_path.read_bytes(), new_master)
                manifest_already_new = True
            except CryptoError:
                pass
        if not manifest_already_new:
            manifest = self._manifest_load(keys)
            manifest_blob = _encode_manifest(manifest)
            _atomic_write(
                self.manifest_path,
                crypto.encrypt_secret(manifest_blob, new_master),
            )

        # Re-encrypt the audit log too. If it's unreadable under either
        # the old key (corrupt) we move it aside under a timestamped
        # name so we don't end up appending to a corrupt blob; the user
        # can investigate the renamed file later if they want.
        audit_path = self.root / "audit"
        if audit_path.is_file():
            audit_blob = audit_path.read_bytes()
            new_under_new = False
            try:
                crypto.decrypt_secret(audit_blob, new_master)
                new_under_new = True
            except CryptoError:
                pass

            if not new_under_new:
                try:
                    audit_plaintext = crypto.decrypt_secret(audit_blob, old_master)
                    _atomic_write(
                        audit_path,
                        crypto.encrypt_secret(audit_plaintext, new_master),
                    )
                except CryptoError:
                    # Corrupt under both keys — preserve evidence
                    # rather than silently leaving the bad blob in
                    # place (the next append would compound the
                    # corruption).
                    sidelined = self.root / f"audit.corrupt-{int(_time_now())}"
                    audit_path.rename(sidelined)

        # Persist the new wrapped master key. This is the commit
        # point: prior to this os.replace, a crash leaves master.json
        # pointing at the old key (but the secret files may already
        # be rewrapped under the new key).
        wrap_key = crypto.derive_wrap_key(keys.kek)
        wrapped = crypto.wrap_master_key(new_master, wrap_key)
        _atomic_write(self.master_json_path, _serialize_wrapped(wrapped))

        return rewrapped_count

    # ---- Manifest internals ---------------------------------------------

    def _manifest_load(self, keys: UnlockedKeys) -> dict[str, ManifestEntry]:
        if not self.manifest_path.is_file():
            return {}
        blob = self.manifest_path.read_bytes()
        plaintext = crypto.decrypt_secret(blob, keys.master_key)
        return _decode_manifest(plaintext)

    def _manifest_save(
        self, keys: UnlockedKeys, manifest: dict[str, ManifestEntry]
    ) -> None:
        plaintext = _encode_manifest(manifest)
        _atomic_write(
            self.manifest_path, crypto.encrypt_secret(plaintext, keys.master_key)
        )

    def _manifest_set(
        self,
        keys: UnlockedKeys,
        name: str,
        *,
        tags: list[str] | None,
    ) -> None:
        manifest = self._manifest_load(keys)
        filename_key = self._filename_key_for(keys.kek)
        stored = crypto.stored_filename(filename_key, name)
        existing = manifest.get(stored)
        # Construct a fresh entry rather than mutating; ManifestEntry
        # is frozen.
        new_tags = (
            tuple(tags)
            if tags is not None
            else (existing.tags if existing is not None else ())
        )
        manifest[stored] = ManifestEntry(name=name, tags=new_tags)
        self._manifest_save(keys, manifest)

    def _manifest_remove(self, keys: UnlockedKeys, name: str) -> None:
        manifest = self._manifest_load(keys)
        filename_key = self._filename_key_for(keys.kek)
        stored = crypto.stored_filename(filename_key, name)
        if stored in manifest:
            del manifest[stored]
            self._manifest_save(keys, manifest)


# ---- Wrapped-master-key serialization --------------------------------------


def _serialize_wrapped(wrapped: WrappedMasterKey) -> bytes:
    """JSON-encode a :class:`WrappedMasterKey` for ``master.json``."""
    payload = {
        "version": 1,
        "nonce": wrapped.nonce.hex(),
        "ciphertext": wrapped.ciphertext.hex(),
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _deserialize_wrapped(blob: bytes) -> WrappedMasterKey:
    """Parse a wrapped-master-key JSON blob."""
    try:
        payload: dict[str, Any] = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CryptoError(f"master.json is corrupt: {exc}") from exc
    if payload.get("version") != 1:
        raise CryptoError("master.json has unknown version.")
    return WrappedMasterKey(
        nonce=bytes.fromhex(payload["nonce"]),
        ciphertext=bytes.fromhex(payload["ciphertext"]),
    )
