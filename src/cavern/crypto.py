"""Cryptographic core for cavern.

This module is the heart of the design and is intentionally small and
self-contained so it can be audited as a unit. Nothing else in the
package implements cryptographic primitives; everything calls into
here.

Key hierarchy
-------------

::

    GPG passphrase
        └─ decrypts master.gpg
                └─ KEK (32 bytes, never rotates after init)
                        ├─ HKDF(KEK, "filename-v1") → filename_key
                        │       └─ HMAC(filename_key, name)[:16] → on-disk name
                        └─ HKDF(KEK, "wrap-v1")     → wrap_key
                                └─ wraps master_key (rotatable, 32 bytes)
                                        └─ wraps per-file content keys

The two-tier wrapping (KEK wraps master_key, master_key wraps per-file
DEKs) means master-key rotation only requires rewriting the small
header on each file, not re-encrypting the content. Filenames are
derived from the KEK rather than the rotatable master_key so rotation
does not rename files.

File format on disk
-------------------

Every secret file is a single binary blob:

::

    [magic: 4 bytes  = b"CVRN"]
    [version: 1 byte = 0x01]
    [wrapped_dek_nonce: 12 bytes]
    [wrapped_dek_ct:    32 bytes ciphertext + 16 bytes GCM tag]
    [content_nonce: 12 bytes]
    [bucket_size: 4 bytes big-endian uint32]
    [content_ct:  bucket_size bytes ciphertext + 16 bytes GCM tag]

The DEK is generated fresh per write via ``os.urandom(32)`` and never
exists on disk in plaintext. ``bucket_size`` records the padded
plaintext length so we know how much padding to strip on decrypt; it
leaks the bucket but not the precise length.

Padding strategy
----------------

Plaintext is padded with ISO/IEC 7816-4 padding (a single ``0x80``
byte followed by ``0x00`` bytes) to the smallest of: 256 B, 1 KiB,
4 KiB, 16 KiB. Plaintext larger than 16 KiB is padded up to the next
16 KiB multiple. This caps length leakage at one of four buckets for
~99% of real credentials.

Why these primitives
--------------------

- **AES-256-GCM** for authenticated encryption — IETF standard, hardware-
  accelerated on every modern CPU, fail-closed on tampering.
- **HKDF-SHA256** for key derivation — the canonical extract-then-
  expand KDF, well-suited to deriving multiple subkeys from one input.
- **HMAC-SHA256** for filenames — deterministic (so lookup-by-name
  doesn't need an index), preimage-resistant (so filenames don't leak
  the original name), and fast.
- **GPG** for the outer master.gpg only — its job is to translate "user
  has the right private key + passphrase" into "produce the KEK." We
  don't use GPG for any per-secret operation.
"""

from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .exceptions import CryptoError

# ---- Constants --------------------------------------------------------------

GPG_BINARY = "gpg"
GPG_AGENT_BINARY = "gpg-connect-agent"
GPGCONF_BINARY = "gpgconf"

# Substrings in ``gpg`` stderr that indicate a keyring-lock contention.
# Any one of these triggers the stale-lock recovery sequence in
# :func:`_run_gpg_with_lock_recovery`. The three appear together when
# the lockfile holder is unreachable (typically a daemon stranded on
# another host with a shared ``$GNUPGHOME``), but matching any one is
# sufficient for recovery to engage.
_LOCK_CONTENTION_INDICATORS = (
    "waiting for lock",
    "keydb_search failed",
    "Connection timed out",
)

KEK_LENGTH = 32  # bytes; AES-256
MASTER_KEY_LENGTH = 32
DEK_LENGTH = 32
GCM_NONCE_LENGTH = 12
GCM_TAG_LENGTH = 16  # appended by AESGCM, not separated
HMAC_FILENAME_BYTES = 16  # 128 bits → 32 hex chars; see note below
# 32 hex chars is far below filesystem limits (255 bytes on ext4/btrfs/
# APFS/NTFS) and 128 bits is well past the birthday bound for any
# realistic vault size: a 10,000-entry vault has ~10^-31 collision
# probability. We keep the truncation explicit so a future v2 wire
# format could lengthen it without ambiguity.
DERIVED_SUBKEY_LENGTH = 32  # filename_key, wrap_key — 32 bytes for AES-256/HMAC

FILE_MAGIC = b"CVRN"
FILE_VERSION = 0x01
HEADER_FIXED_LEN = (
    len(FILE_MAGIC)
    + 1  # version byte
    + GCM_NONCE_LENGTH  # wrapped_dek_nonce
    + DEK_LENGTH
    + GCM_TAG_LENGTH  # wrapped_dek ciphertext+tag
    + GCM_NONCE_LENGTH  # content_nonce
    + 4  # bucket_size uint32
)

# Domain separation strings for HKDF. The "-v1" suffix lets us migrate
# to v2 derivation without colliding with v1-derived material in a
# vault that already contains v1 ciphertexts.
_HKDF_INFO_FILENAME = b"cavern:filename-v1"
_HKDF_INFO_WRAP = b"cavern:wrap-v1"

# Padding buckets. Plaintext is padded up to the smallest bucket that
# fits; anything over the largest bucket is rounded up to the next
# multiple of the largest bucket.
_PADDING_BUCKETS = (256, 1024, 4096, 16384)


# ---- GPG outer layer --------------------------------------------------------


def ensure_gpg_available() -> None:
    """Verify that ``gpg`` is on ``PATH``, raising :class:`CryptoError` if not."""
    if shutil.which(GPG_BINARY) is None:
        raise CryptoError(
            "gpg not found on PATH. Install GnuPG (e.g. `apt install gnupg`)."
        )


def gpg_encrypt_to_recipients(plaintext: bytes, recipients: list[str]) -> bytes:
    """GPG-encrypt ``plaintext`` and return the ciphertext bytes.

    Used only for ``master.gpg``. Does not write to disk; the caller
    handles file placement so atomic-rename and chmod can be done at
    that layer.
    """
    if not recipients:
        raise CryptoError("At least one GPG recipient is required.")
    args = [GPG_BINARY, "--quiet", "--batch", "--yes", "--encrypt"]
    for recipient in recipients:
        args.extend(["--recipient", recipient])
    result = _run_gpg_with_lock_recovery(args, stdin=plaintext)
    if result.returncode != 0:
        raise CryptoError(
            f"gpg encrypt failed: {result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout


def gpg_decrypt(ciphertext_path: Path) -> bytes:
    """Decrypt a GPG-encrypted file and return the plaintext bytes.

    The user's ``gpg-agent`` handles passphrase prompting via pinentry.
    Cavern never sees the GPG passphrase.
    """
    if not ciphertext_path.is_file():
        raise CryptoError(f"GPG-encrypted file not found: {ciphertext_path}")
    args = [GPG_BINARY, "--quiet", "--decrypt", str(ciphertext_path)]
    result = _run_gpg_with_lock_recovery(args, stdin=None)
    if result.returncode != 0:
        raise CryptoError(
            f"gpg decrypt failed: {result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout


def gpg_reload_agent() -> None:
    """Tell ``gpg-agent`` to forget all cached passphrases (best-effort)."""
    if shutil.which(GPG_AGENT_BINARY) is None:
        return
    subprocess.run(
        [GPG_AGENT_BINARY, "reloadagent", "/bye"],
        capture_output=True,
        check=False,
    )


def gpg_has_secret_key(identity: str) -> bool:
    """Return True iff ``identity`` resolves to a usable secret key.

    Cavern's flow encrypts the master key *to* a recipient at init
    time and then decrypts it on every unlock, so the user needs both
    the public and private halves of the key. Checking for the secret
    key is sufficient: ``gpg`` cannot produce a secret-key listing
    without the matching public key, so a successful match here means
    encryption AND decryption will both work later.

    The check uses ``--list-secret-keys --with-colons``; exit code 0
    means at least one matching key was found. We swallow stderr to
    keep the error path silent — the caller decides what diagnostic
    to surface.
    """
    if not identity.strip():
        return False
    result = subprocess.run(
        [GPG_BINARY, "--list-secret-keys", "--with-colons", identity],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def gpg_list_local_identities() -> list[str]:
    """Return a short summary of every secret key in the local keyring.

    Used purely for diagnostic output when a recipient lookup fails —
    the user often just typed a name slightly wrong, and showing the
    keys they DO have makes the fix obvious. Best-effort: returns
    an empty list on any parsing trouble rather than raising.

    Output format per entry: ``"<long-keyid>  <primary-uid>"``.
    """
    result = subprocess.run(
        [GPG_BINARY, "--list-secret-keys", "--with-colons"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return []

    identities: list[str] = []
    current_keyid: str | None = None
    for line in result.stdout.decode(errors="replace").splitlines():
        # gpg's colon-delimited format: field 1 is the record type.
        # `sec` introduces a secret key (field 5 = long key ID).
        # `uid` is a user ID associated with the most recent key
        # (field 10 = user ID string).
        fields = line.split(":")
        if not fields:
            continue
        if fields[0] == "sec" and len(fields) > 4:
            current_keyid = fields[4]
        elif fields[0] == "uid" and current_keyid and len(fields) > 9:
            identities.append(f"{current_keyid}  {fields[9]}")
            current_keyid = None  # only take the primary uid
    return identities


def ensure_recipients_have_secret_keys(recipients: list[str]) -> None:
    """Verify every recipient resolves to a usable secret key.

    Raises :class:`CryptoError` if any are missing. The error message
    is formatted for direct display to the user: it lists the missing
    identities, shows what keys ARE in the keyring (so a typo is
    obvious), and points at concrete next steps.

    Call this BEFORE :func:`gpg_encrypt_to_recipients` to convert
    cryptic errors like ``gpg: alice: skipped: No public key`` into
    actionable diagnostics.
    """
    missing = [r for r in recipients if not gpg_has_secret_key(r)]
    if not missing:
        return

    available = gpg_list_local_identities()

    lines = [f"No GPG secret key found for: {', '.join(missing)}", ""]
    if available:
        lines.append("Keys available in your keyring:")
        for entry in available:
            lines.append(f"  - {entry}")
        lines.append("")
        lines.append(
            "If one of these is yours, re-run with that key ID or " "associated email."
        )
    else:
        lines.append("Your GPG keyring has no secret keys.")
    lines.extend(
        [
            "",
            "To fix this you can:",
            "  - Generate a new key:    gpg --full-generate-key",
            "  - Import an existing key: gpg --import <key.asc>",
        ]
    )
    raise CryptoError("\n".join(lines))


def gpg_run_keygen_wizard() -> int:
    """Spawn ``gpg --full-generate-key`` interactively and return its exit code.

    Inherits stdin/stdout/stderr from the current process so gpg can
    drive its own wizard (which uses curses/pinentry depending on
    setup). We do not touch the user's keyring directly — gpg owns
    that completely; we just provide a convenient on-ramp.
    """
    return subprocess.run([GPG_BINARY, "--full-generate-key"], check=False).returncode


# ---- GPG keyring-lock recovery ---------------------------------------------
#
# When ``~/.gnupg`` lives on a network filesystem (NFS, SMB, or any
# distributed filesystem shared across multiple machines), a session
# that ends ungracefully can leave a ``gpg-agent`` or ``keyboxd``
# daemon stranded on the prior machine still holding the keyring
# lock. The next gpg invocation from another machine waits for the
# unreachable holder and eventually fails with ``keydb_search
# failed: Connection timed out``. Without recovery, every fresh
# session fails until the stale lockfile is manually deleted.
#
# Recovery is deliberately conservative: only ``*.lock`` files are
# ever considered for removal (keyring databases such as
# ``pubring.kbx`` and ``pubring.db`` are never touched), and a lock
# held by a live process on the current host is left alone. The
# retry is bounded to one attempt so a persistent live lock cannot
# induce an unbounded loop.


def _is_lock_contention(stderr: str) -> bool:
    """Return True if ``stderr`` matches a GPG keyring-lock contention pattern."""
    return any(s in stderr for s in _LOCK_CONTENTION_INDICATORS)


def _pid_alive_on_this_host(pid: int) -> bool:
    """Return True if ``pid`` is a running process on the current host.

    Uses ``os.kill(pid, 0)`` as the canonical liveness probe. The
    answer is only meaningful for processes on the same host; a PID
    coincidence with a process on a different host would be
    misleading, so :func:`_is_lock_stale` gates this on hostname.
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists but owned by another user — still alive.
        return True
    return True


def _parse_dotlock(path: Path) -> tuple[int, str] | None:
    """Parse a GnuPG dotlock file. Return ``(pid, hostname)`` or ``None``.

    GnuPG's dotlock format is a single line ``<pid> <hostname>\\n``.
    Older variants omit the hostname. Anything that cannot be parsed
    returns ``None``, which callers conservatively treat as not
    stale.
    """
    try:
        content = path.read_text(errors="replace")
    except OSError:
        return None
    lines = content.strip().splitlines()
    if not lines:
        return None
    parts = lines[0].split()
    if not parts:
        return None
    try:
        pid = int(parts[0])
    except ValueError:
        return None
    hostname = parts[1] if len(parts) > 1 else ""
    return pid, hostname


def _same_host(recorded: str) -> bool:
    """Return True if ``recorded`` names the current host.

    Comparison is by exact string equality against
    ``socket.gethostname()``. GPG's dotlock implementation populates
    the hostname field by calling ``gethostname(2)``, the same
    syscall ``socket.gethostname()`` invokes; on the same host
    across runs the two values are bit-identical, so strict equality
    is the right primitive.

    Fuzzy matching (such as short-name normalization) would collide
    two different hosts that happen to share a short name. Strict
    equality keeps the contract simple: if the recorded value does
    not exactly match this host's hostname, the lock is treated as
    coming from a different host.

    An empty string is treated as the same host: older dotlock
    variants omit the hostname, and in that mode the PID-liveness
    check is the only signal available.
    """
    if not recorded:
        return True
    return recorded == socket.gethostname()


def _is_lock_stale(path: Path) -> bool:
    """Return True if a GPG dotlock is provably stale and safe to remove.

    A lock is *provably stale* when one of the following holds:

    1. The lockfile records the current host (or omits the
       hostname) and the recorded PID is not running on this host.
    2. The lockfile records a different host. The holder is
       unreachable from here, so waiting on it cannot make progress.

    Returns ``False`` conservatively when the lockfile cannot be
    parsed, or when the holder is alive on this host.
    """
    parsed = _parse_dotlock(path)
    if parsed is None:
        return False
    pid, hostname = parsed
    if _same_host(hostname):
        return not _pid_alive_on_this_host(pid)
    return True


def clean_stale_keyring_locks() -> list[Path]:
    """Remove provably-stale GPG dotlock files under ``$GNUPGHOME``.

    Returns
    -------
    list[Path]
        The paths actually removed. Empty if ``$GNUPGHOME`` is
        missing, no lockfiles are present, or none are provably
        stale.

    Notes
    -----
    Only files matching ``*.lock`` are ever considered. The keyring
    database files (``pubring.kbx``, ``pubring.db``, ``trustdb.gpg``,
    and so on) are never touched. Used as a recovery step by
    :func:`_run_gpg_with_lock_recovery`. Exposed as a module-level
    function so it remains independently testable.
    """
    home = Path(os.environ.get("GNUPGHOME") or (Path.home() / ".gnupg"))
    if not home.is_dir():
        return []
    removed: list[Path] = []
    for lock in home.rglob("*.lock"):
        if not _is_lock_stale(lock):
            continue
        try:
            lock.unlink()
        except FileNotFoundError:
            # Another process cleaned the same lock; benign race.
            pass  # noqa: S110 -- intentional: race is benign
        except OSError:
            # Permission, EBUSY, etc. — leave it and let the original
            # gpg error surface if the lock remains relevant.
            continue
        else:
            removed.append(lock)
    return removed


def _gpg_kill_local_daemons() -> None:
    """Ask ``gpgconf`` to terminate the calling user's GPG daemons.

    Handles the same-host stale-daemon case where ``gpg-agent`` or
    ``keyboxd`` is still running locally and just needs to release
    its handle on the keyring database. Silent no-op when
    ``gpgconf`` is unavailable.
    """
    if shutil.which(GPGCONF_BINARY) is None:
        return
    subprocess.run(
        [GPGCONF_BINARY, "--kill", "all"],
        capture_output=True,
        check=False,
    )


def _run_gpg_with_lock_recovery(
    args: list[str], *, stdin: bytes | None
) -> subprocess.CompletedProcess[bytes]:
    """Run a gpg subprocess; recover and retry once on a lock-contention failure.

    Recovery sequence on lock-contention stderr:

    1. ``gpgconf --kill all`` terminates the calling user's local
       GPG daemons (handles the same-host stale-daemon case).
    2. ``$GNUPGHOME/**/*.lock`` is swept and provably-stale entries
       are removed (handles cross-host staleness on shared
       ``$GNUPGHOME``).
    3. The gpg call is retried exactly once.

    Returned result:

    * If the first call succeeds, its :class:`CompletedProcess` is
      returned (no recovery happens).
    * If the first call fails with a non-lock-contention error, its
      :class:`CompletedProcess` is returned unchanged (no recovery).
    * If the first call fails with lock contention and the retry
      succeeds, the retry's :class:`CompletedProcess` is returned.
    * If the first call fails with lock contention and the retry
      also fails, the *first* :class:`CompletedProcess` is returned
      so the caller surfaces the original diagnostic. Recovery
      perturbs local state (terminated daemons, removed lockfiles)
      and the retry's stderr may reflect a downstream side effect
      rather than the failure the caller was trying to act on; if
      the original lock contention is still the relevant problem,
      reporting it directly is more useful than a derivative error.

    The retry is bounded to one attempt: a persistent live lock
    cannot induce an unbounded loop, and real failures are not
    masked by repeated retries.
    """
    first_result = subprocess.run(args, input=stdin, capture_output=True, check=False)
    if first_result.returncode == 0:
        return first_result
    stderr_text = first_result.stderr.decode(errors="replace")
    if not _is_lock_contention(stderr_text):
        return first_result
    _gpg_kill_local_daemons()
    removed = clean_stale_keyring_locks()
    if removed:
        # Use stderr so the message does not pollute stdout, which
        # carries the decrypted plaintext for :func:`gpg_decrypt`.
        paths_str = ", ".join(str(p) for p in removed)
        print(
            f"cavern: cleared {len(removed)} stale GPG keyring "
            f"lock(s) from a prior session: {paths_str}",
            file=sys.stderr,
        )
    retry_result = subprocess.run(args, input=stdin, capture_output=True, check=False)
    if retry_result.returncode == 0:
        return retry_result
    # Recovery did not resolve the failure. Preserve the original
    # diagnostic so the caller's :class:`CryptoError` reflects what
    # the gpg invocation actually failed on, not a side effect of
    # recovery (terminated agent, etc.).
    return first_result


# ---- Key hierarchy ----------------------------------------------------------


def _derive_subkey_from_kek(kek: bytes, *, info: bytes) -> bytes:
    """Derive a 32-byte subkey from the KEK using HKDF-SHA256.

    All cavern subkeys derived from the KEK go through this helper so
    the validation, output length, and HKDF parameters are consistent.
    Callers should use the named ``derive_filename_key`` /
    ``derive_wrap_key`` wrappers rather than calling this directly,
    so the ``info`` strings stay pinned to a single location.
    """
    if len(kek) != KEK_LENGTH:
        raise CryptoError(f"KEK must be {KEK_LENGTH} bytes, got {len(kek)}.")
    return _hkdf(kek, info=info, length=DERIVED_SUBKEY_LENGTH)


def derive_filename_key(kek: bytes) -> bytes:
    """Derive the filename HMAC key from the KEK.

    Depends only on the KEK, which never rotates, so filenames are
    stable across master-key rotations.
    """
    return _derive_subkey_from_kek(kek, info=_HKDF_INFO_FILENAME)


def derive_wrap_key(kek: bytes) -> bytes:
    """Derive the master-key-wrapping key from the KEK."""
    return _derive_subkey_from_kek(kek, info=_HKDF_INFO_WRAP)


def stored_filename(filename_key: bytes, secret_name: str) -> str:
    """Return the on-disk filename for a secret name.

    The filename is the hex of the first 16 bytes of
    ``HMAC-SHA256(filename_key, secret_name)``. Truncating to 128 bits
    is far past the birthday bound for any realistic vault size and
    keeps filenames short.

    Parameters
    ----------
    filename_key : bytes
        The HMAC key derived from the KEK via :func:`derive_filename_key`.
        Must be exactly :data:`DERIVED_SUBKEY_LENGTH` bytes; passing a
        wrong-length key is a programmer error and produces a
        :class:`CryptoError` rather than silently mapping to a wrong
        filesystem location.
    secret_name : str
        The user-facing secret name. Encoded as UTF-8 before hashing.

    Returns
    -------
    str
        Lowercase hex string of length :data:`HMAC_FILENAME_BYTES` * 2.
    """
    if len(filename_key) != DERIVED_SUBKEY_LENGTH:
        raise CryptoError(
            f"filename_key must be {DERIVED_SUBKEY_LENGTH} bytes, "
            f"got {len(filename_key)}."
        )
    hasher = hmac.HMAC(filename_key, hashes.SHA256())
    hasher.update(secret_name.encode("utf-8"))
    return hasher.finalize()[:HMAC_FILENAME_BYTES].hex()


def _hkdf(input_key: bytes, *, info: bytes, length: int) -> bytes:
    """Run HKDF-SHA256 with no salt (KEK already has full entropy)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(input_key)


# ---- Master key wrapping ----------------------------------------------------


@dataclass(frozen=True)
class WrappedMasterKey:
    """A master key encrypted under the wrap key.

    Stored as a small JSON blob alongside ``master.gpg``. We split the
    wrapped master key out from the GPG envelope so we can rotate it
    without touching ``master.gpg`` (and therefore without re-running
    GPG, which is the slow part).
    """

    nonce: bytes
    ciphertext: bytes  # includes the GCM tag


def wrap_master_key(master_key: bytes, wrap_key: bytes) -> WrappedMasterKey:
    """Encrypt ``master_key`` under ``wrap_key`` with AES-256-GCM."""
    if len(master_key) != MASTER_KEY_LENGTH:
        raise CryptoError("Master key must be 32 bytes.")
    nonce = os.urandom(GCM_NONCE_LENGTH)
    ct = AESGCM(wrap_key).encrypt(nonce, master_key, associated_data=None)
    return WrappedMasterKey(nonce=nonce, ciphertext=ct)


def unwrap_master_key(wrapped: WrappedMasterKey, wrap_key: bytes) -> bytes:
    """Decrypt a :class:`WrappedMasterKey` and return the master key.

    Raises :class:`CryptoError` on tag failure (wrong wrap key or
    tampered ciphertext). Other exceptions — wrong key length, wrong
    nonce length — are programmer errors and propagate as
    :class:`CryptoError` with a clear message rather than being
    swallowed.
    """
    if len(wrap_key) != DERIVED_SUBKEY_LENGTH:
        raise CryptoError(
            f"wrap_key must be {DERIVED_SUBKEY_LENGTH} bytes, " f"got {len(wrap_key)}."
        )
    if len(wrapped.nonce) != GCM_NONCE_LENGTH:
        raise CryptoError(
            f"Wrapped master key has wrong nonce length: {len(wrapped.nonce)}."
        )
    try:
        return AESGCM(wrap_key).decrypt(
            wrapped.nonce, wrapped.ciphertext, associated_data=None
        )
    except InvalidTag as exc:
        raise CryptoError(
            "Master key unwrap failed (wrong KEK or corruption)."
        ) from exc


# ---- Padding ----------------------------------------------------------------


def _bucket_for(plaintext_len: int) -> int:
    """Pick the smallest bucket that fits ``plaintext_len + 1`` (the 0x80 byte)."""
    needed = plaintext_len + 1  # ISO 7816-4 always adds at least one byte
    for bucket in _PADDING_BUCKETS:
        if needed <= bucket:
            return bucket
    # Larger than the largest bucket — round up to a multiple of it.
    largest = _PADDING_BUCKETS[-1]
    return ((needed + largest - 1) // largest) * largest


def _pad(plaintext: bytes) -> bytes:
    """ISO/IEC 7816-4 padding to the next bucket boundary."""
    bucket = _bucket_for(len(plaintext))
    pad_len = bucket - len(plaintext)
    # Always at least one byte (the 0x80 marker).
    return plaintext + b"\x80" + b"\x00" * (pad_len - 1)


def _unpad(padded: bytes) -> bytes:
    """Strip ISO/IEC 7816-4 padding, raising on malformed input."""
    # Find the trailing 0x80 by scanning back over 0x00s.
    end = len(padded)
    while end > 0 and padded[end - 1] == 0x00:
        end -= 1
    if end == 0 or padded[end - 1] != 0x80:
        raise CryptoError("Padding is malformed (missing 0x80 marker).")
    return padded[: end - 1]


# ---- Per-secret encrypt/decrypt --------------------------------------------


def encrypt_secret(plaintext: bytes, master_key: bytes) -> bytes:
    """Encrypt a secret and return the on-disk blob.

    Generates a fresh random DEK per call, wraps it under
    ``master_key``, and AES-GCM-encrypts the padded plaintext under
    the DEK. The DEK never appears on disk in plaintext.
    """
    if len(master_key) != MASTER_KEY_LENGTH:
        raise CryptoError("Master key must be 32 bytes.")

    dek = os.urandom(DEK_LENGTH)

    wrap_nonce = os.urandom(GCM_NONCE_LENGTH)
    wrapped_dek = AESGCM(master_key).encrypt(wrap_nonce, dek, associated_data=None)
    # wrapped_dek is DEK_LENGTH + GCM_TAG_LENGTH bytes.

    padded = _pad(plaintext)
    bucket_size = len(padded)
    content_nonce = os.urandom(GCM_NONCE_LENGTH)
    content_ct = AESGCM(dek).encrypt(content_nonce, padded, associated_data=None)

    return b"".join(
        [
            FILE_MAGIC,
            bytes([FILE_VERSION]),
            wrap_nonce,
            wrapped_dek,
            content_nonce,
            struct.pack(">I", bucket_size),
            content_ct,
        ]
    )


def decrypt_secret(blob: bytes, master_key: bytes) -> bytes:
    """Decrypt an on-disk blob and return the original plaintext.

    Raises :class:`CryptoError` on truncation, version mismatch, magic
    mismatch, GCM tag failure, or padding corruption.
    """
    if len(master_key) != MASTER_KEY_LENGTH:
        raise CryptoError(
            f"master_key must be {MASTER_KEY_LENGTH} bytes, got {len(master_key)}."
        )
    if len(blob) < HEADER_FIXED_LEN:
        raise CryptoError("Ciphertext is shorter than the fixed header.")

    if blob[: len(FILE_MAGIC)] != FILE_MAGIC:
        raise CryptoError("Bad magic — not a cavern secret file.")

    offset = len(FILE_MAGIC)
    version = blob[offset]
    offset += 1
    if version != FILE_VERSION:
        raise CryptoError(f"Unsupported on-disk version: {version}")

    wrap_nonce = blob[offset : offset + GCM_NONCE_LENGTH]
    offset += GCM_NONCE_LENGTH

    wrapped_dek_len = DEK_LENGTH + GCM_TAG_LENGTH
    wrapped_dek = blob[offset : offset + wrapped_dek_len]
    offset += wrapped_dek_len

    content_nonce = blob[offset : offset + GCM_NONCE_LENGTH]
    offset += GCM_NONCE_LENGTH

    bucket_size = struct.unpack(">I", blob[offset : offset + 4])[0]
    offset += 4

    expected_total = offset + bucket_size + GCM_TAG_LENGTH
    if len(blob) != expected_total:
        raise CryptoError(
            f"Ciphertext length mismatch: header says {expected_total}, "
            f"got {len(blob)}."
        )
    content_ct = blob[offset:]

    try:
        dek = AESGCM(master_key).decrypt(wrap_nonce, wrapped_dek, associated_data=None)
    except InvalidTag as exc:
        raise CryptoError(
            "DEK unwrap failed — wrong master key or corruption."
        ) from exc

    try:
        padded = AESGCM(dek).decrypt(content_nonce, content_ct, associated_data=None)
    except InvalidTag as exc:
        raise CryptoError(
            "Content decryption failed — corruption or tampering detected."
        ) from exc

    return _unpad(padded)


def rewrap_master_key_in_blob(
    blob: bytes, old_master_key: bytes, new_master_key: bytes
) -> bytes:
    """Rewrap a single secret's DEK under a new master key.

    This is the cheap O(n) part of master-key rotation: we touch only
    the wrapped DEK (48 bytes), not the content ciphertext.

    Raises
    ------
    CryptoError
        If the blob is malformed, the version is unrecognized, the
        old master key does not match, or either key is the wrong length.
    """
    if len(old_master_key) != MASTER_KEY_LENGTH:
        raise CryptoError(
            f"old_master_key must be {MASTER_KEY_LENGTH} bytes, "
            f"got {len(old_master_key)}."
        )
    if len(new_master_key) != MASTER_KEY_LENGTH:
        raise CryptoError(
            f"new_master_key must be {MASTER_KEY_LENGTH} bytes, "
            f"got {len(new_master_key)}."
        )
    if len(blob) < HEADER_FIXED_LEN:
        raise CryptoError("Ciphertext is shorter than the fixed header.")
    if blob[: len(FILE_MAGIC)] != FILE_MAGIC:
        raise CryptoError("Bad magic — not a cavern secret file.")
    if blob[len(FILE_MAGIC)] != FILE_VERSION:
        raise CryptoError(f"Unsupported on-disk version: {blob[len(FILE_MAGIC)]}")

    offset = len(FILE_MAGIC) + 1  # skip magic + version

    wrap_nonce = blob[offset : offset + GCM_NONCE_LENGTH]
    offset += GCM_NONCE_LENGTH
    wrapped_dek_len = DEK_LENGTH + GCM_TAG_LENGTH
    wrapped_dek = blob[offset : offset + wrapped_dek_len]
    after_dek = offset + wrapped_dek_len

    try:
        dek = AESGCM(old_master_key).decrypt(
            wrap_nonce, wrapped_dek, associated_data=None
        )
    except InvalidTag as exc:
        raise CryptoError("Old master key did not unwrap this DEK.") from exc

    new_wrap_nonce = os.urandom(GCM_NONCE_LENGTH)
    new_wrapped_dek = AESGCM(new_master_key).encrypt(
        new_wrap_nonce, dek, associated_data=None
    )

    # Splice the new wrap_nonce + wrapped_dek into the blob.
    return (
        blob[: len(FILE_MAGIC) + 1]
        + new_wrap_nonce
        + new_wrapped_dek
        + blob[after_dek:]
    )
    