"""Encrypted append-only audit log of vault operations.

Each record is one JSON line:

    {"ts": 1700000000.0, "action": "show", "name": "work/aws"}

The full log is encrypted under the vault's master key with the same
AES-GCM blob format used for secrets. Appending requires a
decrypt-modify-encrypt cycle, but write rate is human-paced (a few
per minute at most) so this is fine.

Why not GPG? The audit log is too noisy to want a GPG roundtrip per
operation — that would mean a pinentry prompt or a passphrase-cache
hit per ``cavern show``. Encrypting under the already-loaded master
key is much faster and equally strong (the master key itself is
protected by GPG via ``master.gpg``).

Size bound
----------

We cap the log at :data:`MAX_RECORDS` (default 10000) entries on
write. When the cap is exceeded, the oldest records are dropped. This
keeps the decrypt + re-encrypt cycle bounded — without it, a vault in
daily use would accumulate megabytes over a year and every operation
would slow down.
"""

from __future__ import annotations

import contextlib
import json
import time
from pathlib import Path
from typing import Any

from . import crypto
from .exceptions import CryptoError

AUDIT_FILENAME = "audit"
MAX_RECORDS = 10000
_RECENT_DEFAULT_LIMIT = 100


class AuditLog:
    """Encrypted append-only operation log.

    Parameters
    ----------
    vault_root : pathlib.Path
        Vault root directory.
    master_key : bytes
        The vault's master key, used for AES-GCM encryption.
    max_records : int, optional
        Soft cap on how many records to retain on disk. The oldest
        records past the cap are dropped on the next ``append``.
        Defaults to :data:`MAX_RECORDS`.
    """

    def __init__(
        self,
        vault_root: Path,
        master_key: bytes,
        *,
        max_records: int = MAX_RECORDS,
    ) -> None:
        if max_records <= 0:
            raise ValueError(f"max_records must be positive, got {max_records}.")
        self.vault_root = vault_root
        self.master_key = master_key
        self.max_records = max_records
        self._path = vault_root / AUDIT_FILENAME

    def append(self, action: str, name: str | None = None, **extra: Any) -> None:
        """Append a record, enforcing the size cap.

        Failures are swallowed so the CLI keeps working: a credential
        lookup must not fail because the audit log is unwritable.
        """
        record: dict[str, Any] = {"ts": time.time(), "action": action}
        if name is not None:
            record["name"] = name
        record.update(extra)
        record_bytes = json.dumps(record, separators=(",", ":")).encode("utf-8")

        existing = self._read_plaintext_if_any()
        new_blob = self._cap_records(existing) + record_bytes + b"\n"
        with contextlib.suppress(CryptoError):
            self._write_plaintext(new_blob)

    def recent(self, limit: int = _RECENT_DEFAULT_LIMIT) -> list[dict[str, Any]]:
        """Return the most recent ``limit`` records, newest first.

        Parses each JSON line independently; a corrupted record is
        skipped rather than aborting the whole read.
        """
        if limit <= 0:
            return []
        plaintext = self._read_plaintext_if_any()
        if not plaintext:
            return []

        records: list[dict[str, Any]] = []
        for raw in plaintext.split(b"\n"):
            if not raw:
                continue
            try:
                line = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue  # tolerate corruption mid-line
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        records.reverse()
        return records[:limit]

    # ---- Internals -------------------------------------------------------

    def _cap_records(self, existing_plaintext: bytes) -> bytes:
        """Trim ``existing_plaintext`` to the most recent ``max_records - 1`` lines.

        The "minus one" leaves room for the line about to be appended;
        the result + one new record stays under :attr:`max_records`.
        """
        if not existing_plaintext:
            return existing_plaintext

        # Split on newline; keep only non-empty lines so trailing
        # newlines don't inflate the count.
        lines = [chunk for chunk in existing_plaintext.split(b"\n") if chunk]
        if len(lines) < self.max_records:
            return existing_plaintext  # under cap; preserve as-is

        kept = lines[-(self.max_records - 1) :]
        return b"\n".join(kept) + b"\n"

    def _read_plaintext_if_any(self) -> bytes:
        """Return decrypted log bytes, or empty bytes if absent or corrupt."""
        if not self._path.is_file():
            return b""
        try:
            return crypto.decrypt_secret(self._path.read_bytes(), self.master_key)
        except CryptoError:
            return b""

    def _write_plaintext(self, plaintext: bytes) -> None:
        # Local import to break the audit ↔ vault circular dependency.
        from .vault import _atomic_write

        blob = crypto.encrypt_secret(plaintext, self.master_key)
        _atomic_write(self._path, blob)
