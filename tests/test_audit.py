"""Tests for ``cavern.audit``.

These tests use a synthetic master key and exercise the audit log
through its public API. The crypto layer round-trips correctly
(covered in test_crypto), so audit-level concerns are: ordering,
size capping, robust decode of corrupt data, and graceful failure
when the file is unreadable.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cavern import crypto
from cavern.audit import MAX_RECORDS, AuditLog
from cavern.crypto import MASTER_KEY_LENGTH


@pytest.fixture()
def vault_root(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture()
def master_key() -> bytes:
    return os.urandom(MASTER_KEY_LENGTH)


# ---- Basic ordering -------------------------------------------------------


def test_recent_returns_newest_first(vault_root: Path, master_key: bytes) -> None:
    log = AuditLog(vault_root, master_key)
    log.append("first")
    log.append("second")
    log.append("third")

    actions = [r["action"] for r in log.recent()]
    assert actions == ["third", "second", "first"]


def test_recent_respects_limit(vault_root: Path, master_key: bytes) -> None:
    log = AuditLog(vault_root, master_key)
    for i in range(5):
        log.append(f"event-{i}")
    assert len(log.recent(limit=3)) == 3


def test_recent_zero_limit_returns_empty(vault_root: Path, master_key: bytes) -> None:
    log = AuditLog(vault_root, master_key)
    log.append("anything")
    assert log.recent(limit=0) == []


def test_recent_on_empty_log_returns_empty(vault_root: Path, master_key: bytes) -> None:
    assert AuditLog(vault_root, master_key).recent() == []


def test_append_with_extras(vault_root: Path, master_key: bytes) -> None:
    log = AuditLog(vault_root, master_key)
    log.append("rotate-key", count=42)

    record = log.recent()[0]
    assert record["action"] == "rotate-key"
    assert record["count"] == 42
    assert "ts" in record


# ---- Size cap -------------------------------------------------------------


def test_append_enforces_max_records(vault_root: Path, master_key: bytes) -> None:
    """Once the cap is reached, the oldest records are dropped."""
    log = AuditLog(vault_root, master_key, max_records=10)
    for i in range(25):
        log.append(f"event-{i}")

    records = log.recent(limit=100)
    assert len(records) == 10
    # The newest 10 (events 15..24) survive; oldest 15 are gone.
    surviving_actions = sorted(r["action"] for r in records)
    assert surviving_actions == sorted(f"event-{i}" for i in range(15, 25))


def test_append_under_cap_preserves_all(vault_root: Path, master_key: bytes) -> None:
    """Below the cap, every record is retained."""
    log = AuditLog(vault_root, master_key, max_records=100)
    for i in range(50):
        log.append(f"event-{i}")

    assert len(log.recent(limit=200)) == 50


def test_zero_or_negative_max_records_rejected(
    vault_root: Path, master_key: bytes
) -> None:
    with pytest.raises(ValueError):
        AuditLog(vault_root, master_key, max_records=0)
    with pytest.raises(ValueError):
        AuditLog(vault_root, master_key, max_records=-1)


def test_default_max_records_is_module_constant() -> None:
    """Documented default; tests should fail loudly if it changes silently."""
    assert MAX_RECORDS == 10000


# ---- Corrupt / unreadable log --------------------------------------------


def test_recent_skips_corrupt_lines(vault_root: Path, master_key: bytes) -> None:
    """A garbled line in the middle of the log doesn't break the rest.

    We construct a plaintext blob with a valid record, a garbage line,
    and another valid record. The reader should return the two valid
    records and silently skip the third.
    """
    log = AuditLog(vault_root, master_key)
    plaintext = (
        b'{"ts":1.0,"action":"valid-1"}\n'
        b"this-is-not-json\n"
        b'{"ts":2.0,"action":"valid-2"}\n'
    )
    blob = crypto.encrypt_secret(plaintext, master_key)
    (vault_root / "audit").write_bytes(blob)
    os.chmod(vault_root / "audit", 0o600)

    actions = [r["action"] for r in log.recent()]
    assert actions == ["valid-2", "valid-1"]


def test_recent_skips_non_utf8_lines(vault_root: Path, master_key: bytes) -> None:
    """Bytes that cannot decode as UTF-8 are skipped, not raised."""
    log = AuditLog(vault_root, master_key)
    plaintext = (
        b'{"ts":1.0,"action":"good"}\n'
        b"\xff\xfe\xfd-not-utf8\n"
        b'{"ts":2.0,"action":"good-2"}\n'
    )
    blob = crypto.encrypt_secret(plaintext, master_key)
    (vault_root / "audit").write_bytes(blob)
    os.chmod(vault_root / "audit", 0o600)

    actions = [r["action"] for r in log.recent()]
    assert actions == ["good-2", "good"]


def test_recent_returns_empty_on_undecryptable_log(
    vault_root: Path, master_key: bytes
) -> None:
    """A log encrypted under a different key looks like garbage to us."""
    log = AuditLog(vault_root, master_key)
    other_key = os.urandom(MASTER_KEY_LENGTH)
    blob = crypto.encrypt_secret(b'{"ts":1.0,"action":"x"}\n', other_key)
    (vault_root / "audit").write_bytes(blob)
    os.chmod(vault_root / "audit", 0o600)

    assert log.recent() == []


def test_append_swallows_write_failure(
    vault_root: Path, master_key: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit-log failure must not propagate; CLI commands keep working."""
    log = AuditLog(vault_root, master_key)
    log.append("first")  # establish a starting point

    def boom(*_args: object, **_kwargs: object) -> None:
        raise crypto.CryptoError("simulated failure")

    monkeypatch.setattr(crypto, "encrypt_secret", boom)
    # Should not raise.
    log.append("second")
