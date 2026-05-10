"""Bulk transfer of secrets — encrypted dump/load and plaintext bulk-insert.

Three operations live here, distinct enough that they share only a
file header constants and conflict-handling logic:

1. :func:`dump_secrets` — serialize a (filtered) subset of vault
   secrets, encrypt the whole bundle under a passphrase-derived key,
   and write the result. Useful for transferring the vault between
   machines, emailing a credential set, or backing up independent of
   a specific GPG key.

2. :func:`load_secrets` — read a dump file, prompt for the
   passphrase, decrypt, and insert each secret into the current
   vault. Conflict handling is configurable.

3. :func:`bulk_insert_from_file` — read a plaintext JSON file and
   insert each entry. The file is plaintext by design (the use case
   is migration from other tools), so the caller is responsible for
   keeping it safe before and after the import.

Dump file format
----------------

::

    [magic:     8 bytes   = b"CVRNDUMP"]
    [version:   1 byte    = 0x01]
    [salt:     16 bytes   random per dump]
    [scrypt_n:  4 bytes   big-endian uint32, KDF cost]
    [scrypt_r:  4 bytes   big-endian uint32]
    [scrypt_p:  4 bytes   big-endian uint32]
    [nonce:    12 bytes   AES-GCM nonce]
    [ciphertext: ...      AES-GCM(payload) + 16-byte GCM tag]

The header is 49 bytes. The plaintext payload is a UTF-8-encoded JSON
document of the form::

    {
      "version": 1,
      "exported_at": <unix timestamp>,
      "secrets": [
        {"name": "work/aws", "tags": ["cloud"], "content": "<base64>"},
        ...
      ]
    }

Storing the scrypt parameters in the file makes the format
forward-compatible: future dumps can use stronger cost without
breaking older ones, and a load operation always uses the parameters
the dump was created with.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import struct
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .exceptions import CavernError
from .vault import UnlockedKeys, Vault

# ---- Dump format constants ------------------------------------------------

DUMP_MAGIC = b"CVRNDUMP"
DUMP_VERSION = 0x01
SALT_LENGTH = 16
GCM_NONCE_LENGTH = 12
DUMP_KEY_LENGTH = 32
HEADER_LENGTH = (
    len(DUMP_MAGIC) + 1 + SALT_LENGTH + 4 + 4 + 4 + GCM_NONCE_LENGTH
)  # 49 bytes

# Default scrypt parameters: N=2^15, r=8, p=1. ~32 MB memory, ~300 ms
# on a modern laptop. Strong against offline attack, light enough to
# not OOM constrained machines. Stored in the file so we can crank
# later without breaking compatibility.
DEFAULT_SCRYPT_N = 2**15
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1

# ASCII-armor markers for clipboard / email transfer.
ARMOR_BEGIN = b"-----BEGIN CAVERN DUMP-----"
ARMOR_END = b"-----END CAVERN DUMP-----"


# ---- Result dataclasses ---------------------------------------------------


@dataclass(frozen=True)
class DumpResult:
    """Summary returned by :func:`dump_secrets`."""

    secret_count: int
    bytes_written: int


@dataclass(frozen=True)
class LoadResult:
    """Summary returned by :func:`load_secrets` and :func:`bulk_insert_from_file`."""

    inserted: int
    skipped: int  # already-present secrets, not overwritten
    overwritten: int  # already-present secrets, replaced (when overwrite=True)


# ---- KDF wrapper ----------------------------------------------------------


def _derive_dump_key(
    passphrase: str,
    salt: bytes,
    *,
    n: int = DEFAULT_SCRYPT_N,
    r: int = DEFAULT_SCRYPT_R,
    p: int = DEFAULT_SCRYPT_P,
) -> bytes:
    """Stretch a passphrase to a 32-byte AES key via scrypt."""
    if not passphrase:
        raise CavernError("Passphrase cannot be empty.")
    kdf = Scrypt(salt=salt, length=DUMP_KEY_LENGTH, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


# ---- Filtering ------------------------------------------------------------


def _select_secrets(
    vault: Vault,
    keys: UnlockedKeys,
    *,
    prefix: str | None = None,
    tags: Iterable[str] | None = None,
) -> list[str]:
    """Return the names of secrets matching the given filters.

    Filters AND together: a secret is selected iff it matches the
    prefix (when given) AND has at least one of the given tags (when
    given).
    """
    names = vault.list_names(keys)
    if prefix is not None:
        names = [n for n in names if n.startswith(prefix)]

    tag_set = {t.strip().lower() for t in tags or [] if t.strip()}
    if tag_set:
        # Look up the manifest once to read tags efficiently.
        manifest = vault._manifest_load(keys)  # noqa: SLF001 - intentional, see comment
        # We only care about names that have at least one matching tag.
        # The manifest's keys are HMAC filenames, not real names, so we
        # build a name → tags lookup by inverting the manifest.
        name_to_tags = {entry.name: set(entry.tags) for entry in manifest.values()}
        names = [n for n in names if name_to_tags.get(n, set()) & tag_set]

    return sorted(names)


# ---- Dump -----------------------------------------------------------------


def dump_secrets(
    vault: Vault,
    keys: UnlockedKeys,
    passphrase: str,
    output: BinaryIO,
    *,
    prefix: str | None = None,
    tags: Iterable[str] | None = None,
    armor: bool = False,
) -> DumpResult:
    """Encrypt selected secrets under a passphrase and write to ``output``.

    Parameters
    ----------
    vault : Vault
        Source vault.
    keys : UnlockedKeys
        Unlocked keys for the vault, used to read secret content.
    passphrase : str
        Passphrase that protects the dump. Stretched via scrypt before
        use as an AES-256-GCM key. Must not be empty.
    output : BinaryIO
        Stream to write the dump to. Use ``sys.stdout.buffer`` to write
        to stdout, or ``open(path, "wb")`` for a file.
    prefix : str, optional
        If given, only secrets whose names start with this prefix are
        included.
    tags : iterable of str, optional
        If given, only secrets carrying at least one of these tags are
        included.
    armor : bool, optional
        If True, the output is base64-encoded with BEGIN/END markers
        (suitable for email or clipboard). Default False (raw binary).

    Returns
    -------
    DumpResult
        Count of secrets written and total bytes emitted.

    Raises
    ------
    CavernError
        If ``passphrase`` is empty or no secrets match the filters.
    """
    names = _select_secrets(vault, keys, prefix=prefix, tags=tags)
    if not names:
        raise CavernError("No secrets matched the given filters.")

    manifest = vault._manifest_load(keys)  # noqa: SLF001
    name_to_tags = {entry.name: list(entry.tags) for entry in manifest.values()}

    payload_secrets: list[dict[str, Any]] = []
    for name in names:
        plaintext = vault.show(keys, name)
        payload_secrets.append(
            {
                "name": name,
                "tags": name_to_tags.get(name, []),
                # base64 so the JSON is plain ASCII regardless of
                # whether the secret happens to be valid UTF-8.
                "content": base64.b64encode(plaintext).decode("ascii"),
            }
        )

    payload = {
        "version": 1,
        "exported_at": int(time.time()),
        "secrets": payload_secrets,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(GCM_NONCE_LENGTH)
    key = _derive_dump_key(
        passphrase,
        salt,
        n=DEFAULT_SCRYPT_N,
        r=DEFAULT_SCRYPT_R,
        p=DEFAULT_SCRYPT_P,
    )
    ciphertext = AESGCM(key).encrypt(nonce, payload_bytes, associated_data=None)

    blob = (
        DUMP_MAGIC
        + bytes([DUMP_VERSION])
        + salt
        + struct.pack(">III", DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P)
        + nonce
        + ciphertext
    )

    if armor:
        encoded = base64.b64encode(blob)
        # Wrap at 76 chars per RFC 7468 / classic PEM convention.
        wrapped = b"\n".join(encoded[i : i + 76] for i in range(0, len(encoded), 76))
        out_bytes = ARMOR_BEGIN + b"\n" + wrapped + b"\n" + ARMOR_END + b"\n"
    else:
        out_bytes = blob

    output.write(out_bytes)
    return DumpResult(secret_count=len(names), bytes_written=len(out_bytes))


# ---- Load -----------------------------------------------------------------


def _strip_armor(data: bytes) -> bytes:
    """If ``data`` is ASCII-armored, decode it; otherwise return as-is.

    Detection is by the BEGIN marker on the first non-empty line. We
    don't try to be clever about partial decoding — armor is all-or-
    nothing.
    """
    stripped = data.lstrip()
    if not stripped.startswith(ARMOR_BEGIN):
        return data

    # Find content between BEGIN and END markers.
    try:
        begin_end = stripped.index(b"\n", len(ARMOR_BEGIN)) + 1
        end_start = stripped.index(ARMOR_END)
    except ValueError as exc:
        raise CavernError("Armored dump is missing END marker.") from exc

    body = stripped[begin_end:end_start]
    # Remove all whitespace before base64 decoding.
    body_no_ws = b"".join(body.split())
    try:
        return base64.b64decode(body_no_ws, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CavernError(f"Armored dump body is not valid base64: {exc}") from exc


def _parse_header(blob: bytes) -> tuple[bytes, int, int, int, bytes, bytes]:
    """Validate and split a dump blob into ``(salt, n, r, p, nonce, ciphertext)``.

    Raises :class:`CavernError` on any structural issue (short blob,
    bad magic, wrong version).
    """
    if len(blob) < HEADER_LENGTH + 16:  # header + minimum GCM tag
        raise CavernError("Dump file is too short to be valid.")

    if blob[: len(DUMP_MAGIC)] != DUMP_MAGIC:
        raise CavernError("Bad magic — this is not a cavern dump file.")

    offset = len(DUMP_MAGIC)
    version = blob[offset]
    offset += 1
    if version != DUMP_VERSION:
        raise CavernError(f"Unsupported dump version: {version}.")

    salt = blob[offset : offset + SALT_LENGTH]
    offset += SALT_LENGTH

    n, r, p = struct.unpack(">III", blob[offset : offset + 12])
    offset += 12
    if n < 2 or n & (n - 1):
        raise CavernError(f"scrypt N parameter must be a power of 2, got {n}.")

    nonce = blob[offset : offset + GCM_NONCE_LENGTH]
    offset += GCM_NONCE_LENGTH

    ciphertext = blob[offset:]
    return salt, n, r, p, nonce, ciphertext


def load_secrets(
    vault: Vault,
    keys: UnlockedKeys,
    passphrase: str,
    input_data: bytes,
    *,
    overwrite: bool = False,
) -> LoadResult:
    """Decrypt a dump and insert each secret into the current vault.

    Parameters
    ----------
    vault : Vault
        Destination vault.
    keys : UnlockedKeys
        Unlocked keys for the destination vault.
    passphrase : str
        Passphrase used by the original ``dump_secrets`` call.
    input_data : bytes
        The raw dump blob, either binary or ASCII-armored.
    overwrite : bool, optional
        If True, secrets already in the vault are replaced. If False
        (the default), existing secrets are skipped.

    Returns
    -------
    LoadResult
        Count of secrets inserted, skipped, and overwritten.

    Raises
    ------
    CavernError
        If the dump is malformed, the passphrase is wrong, or the
        decrypted payload is not valid JSON of the expected shape.
    """
    if not passphrase:
        raise CavernError("Passphrase cannot be empty.")

    blob = _strip_armor(input_data)
    salt, n, r, p, nonce, ciphertext = _parse_header(blob)

    key = _derive_dump_key(passphrase, salt, n=n, r=r, p=p)
    try:
        payload_bytes = AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag as exc:
        raise CavernError(
            "Dump decryption failed — wrong passphrase or corrupted file."
        ) from exc

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CavernError(f"Dump payload is malformed: {exc}") from exc

    if not isinstance(payload, dict) or "secrets" not in payload:
        raise CavernError("Dump payload missing 'secrets' field.")
    secrets_list = payload["secrets"]
    if not isinstance(secrets_list, list):
        raise CavernError("Dump payload 'secrets' must be a list.")

    inserted = skipped = overwritten = 0

    for entry in secrets_list:
        if not isinstance(entry, dict):
            raise CavernError("Dump entry is not a JSON object.")
        name = entry.get("name")
        content_b64 = entry.get("content")
        tags = entry.get("tags") or []
        if not isinstance(name, str) or not isinstance(content_b64, str):
            raise CavernError("Dump entry missing 'name' or 'content'.")
        if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
            raise CavernError(f"Dump entry {name!r} has malformed 'tags'.")

        try:
            content = base64.b64decode(content_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise CavernError(
                f"Dump entry {name!r} has invalid base64 content: {exc}"
            ) from exc

        # Conflict handling.
        existing_path = vault.secret_path(keys.kek, name)
        already_present = existing_path.exists()
        if already_present and not overwrite:
            skipped += 1
            continue

        vault.insert(keys, name, content, force=True)
        if tags:
            vault.set_tags(keys, name, list(tags))

        if already_present:
            overwritten += 1
        else:
            inserted += 1

    return LoadResult(inserted=inserted, skipped=skipped, overwritten=overwritten)


# ---- Plaintext bulk insert -----------------------------------------------


def bulk_insert_from_file(
    vault: Vault,
    keys: UnlockedKeys,
    path: Path,
    *,
    overwrite: bool = False,
) -> tuple[LoadResult, list[str]]:
    """Read a plaintext JSON file and insert each entry.

    The file is **plaintext** — its security is entirely the caller's
    responsibility. The use case is migration from another tool. We
    recommend the file live on encrypted storage and be securely
    deleted (``shred`` on ext4, secure delete on encrypted volume)
    after a successful import. We do not delete it ourselves.

    Expected JSON format::

        [
          {"name": "work/aws", "value": "hunter2"},
          {"name": "work/github", "value": "...", "tags": ["work"]}
        ]

    Each entry must have a ``name`` (str) and ``value`` (str). ``tags``
    is optional. Unknown fields are ignored.

    Returns
    -------
    LoadResult
        Insertion summary.
    list of str
        Warning messages to surface to the user (e.g. about file
        permissions). Empty list means no concerns.

    Raises
    ------
    CavernError
        If the file is missing, not valid JSON, or any entry is
        structurally invalid.
    """
    warnings: list[str] = []
    if not path.is_file():
        raise CavernError(f"File not found: {path}")

    # Warn (don't refuse) if the file is world- or group-readable.
    # The user's choice; we just make the risk visible.
    mode = path.stat().st_mode
    if mode & 0o077:
        warnings.append(
            f"{path} has loose permissions (mode {mode & 0o777:o}). "
            "Anyone with read access to the file or its directory can "
            "see every secret it contains. Consider running on an "
            "encrypted volume and securely deleting the file after "
            "import completes."
        )

    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise CavernError(f"File is not valid UTF-8: {exc}") from exc

    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CavernError(f"File is not valid JSON: {exc}") from exc

    if not isinstance(entries, list):
        raise CavernError(
            "Top-level JSON must be a list of {name, value, tags?} objects."
        )

    inserted = skipped = overwritten = 0

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise CavernError(f"Entry {index} is not a JSON object.")
        name = entry.get("name")
        value = entry.get("value")
        tags = entry.get("tags") or []

        if not isinstance(name, str) or not name.strip():
            raise CavernError(f"Entry {index} has missing or empty 'name'.")
        if not isinstance(value, str):
            raise CavernError(
                f"Entry {index} ({name!r}) has missing or non-string 'value'."
            )
        if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
            raise CavernError(f"Entry {index} ({name!r}) has malformed 'tags'.")

        existing_path = vault.secret_path(keys.kek, name)
        already_present = existing_path.exists()
        if already_present and not overwrite:
            skipped += 1
            continue

        vault.insert(keys, name, value.encode("utf-8"), force=True)
        if tags:
            vault.set_tags(keys, name, list(tags))

        if already_present:
            overwritten += 1
        else:
            inserted += 1

    return (
        LoadResult(inserted=inserted, skipped=skipped, overwritten=overwritten),
        warnings,
    )


__all__ = [
    "DumpResult",
    "LoadResult",
    "bulk_insert_from_file",
    "dump_secrets",
    "load_secrets",
]
