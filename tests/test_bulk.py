"""Tests for ``cavern.bulk`` — dump/load and bulk-insert.

These tests exercise the bulk transfer paths end-to-end through the
public API: encrypt a real vault to a dump blob, decrypt it into a
fresh vault, and assert the round-trip preserves names, content, and
tags. Plus the failure modes: wrong passphrase, malformed input,
filter mismatches, and conflict handling.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from cavern.bulk import (
    DUMP_MAGIC,
    DUMP_VERSION,
    bulk_insert_from_file,
    dump_secrets,
    load_secrets,
)
from cavern.exceptions import CavernError
from cavern.vault import UnlockedKeys, Vault

# ---- Fixtures -------------------------------------------------------------


@pytest.fixture()
def vault_a(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Vault:
    """A vault under tmp_path/vault_a, isolated from the user's home."""
    monkeypatch.setenv("CAVERN_VAULT_DIR", str(tmp_path / "vault_a"))
    return Vault()


@pytest.fixture()
def vault_b(tmp_path: Path) -> Vault:
    """A second vault, used as the import destination."""
    return Vault(root=tmp_path / "vault_b")


@pytest.fixture()
def keys_a(vault_a: Vault) -> UnlockedKeys:
    """Initialize vault_a with a synthetic GPG-less setup.

    We bypass GPG by writing master.json directly with a freshly
    derived wrap key. This lets us test bulk operations without
    needing a real keyring.
    """
    return _bootstrap_vault(vault_a)


@pytest.fixture()
def keys_b(vault_b: Vault) -> UnlockedKeys:
    return _bootstrap_vault(vault_b)


def _bootstrap_vault(vault: Vault) -> UnlockedKeys:
    """Create a vault with a synthetic KEK and the on-disk metadata
    needed for normal CRUD."""
    from cavern import crypto
    from cavern.audit import AuditLog
    from cavern.vault import _atomic_write, _encode_manifest, _serialize_wrapped

    vault.root.mkdir(parents=True, exist_ok=True)
    os.chmod(vault.root, 0o700)
    vault.store_path.mkdir(exist_ok=True)
    os.chmod(vault.store_path, 0o700)

    kek = os.urandom(crypto.KEK_LENGTH)
    master_key = os.urandom(crypto.MASTER_KEY_LENGTH)

    # Touch master.gpg so is_initialized() returns True.
    (vault.root / "master.gpg").write_bytes(b"placeholder for tests")
    os.chmod(vault.root / "master.gpg", 0o600)

    # Write recipients (required by some paths).
    vault.recipients_path.write_text("test@cavern.local\n", encoding="utf-8")
    os.chmod(vault.recipients_path, 0o600)

    wrap_key = crypto.derive_wrap_key(kek)
    wrapped = crypto.wrap_master_key(master_key, wrap_key)
    _atomic_write(vault.master_json_path, _serialize_wrapped(wrapped))

    # Empty manifest, encoded in the canonical schema.
    empty_manifest_blob = _encode_manifest({})
    _atomic_write(
        vault.manifest_path, crypto.encrypt_secret(empty_manifest_blob, master_key)
    )

    # Empty audit log.
    AuditLog(vault.root, master_key).append("init")

    return UnlockedKeys(kek=kek, master_key=master_key)


# ---- Round trip ---------------------------------------------------------


def test_dump_load_round_trip(
    vault_a: Vault,
    keys_a: UnlockedKeys,
    vault_b: Vault,
    keys_b: UnlockedKeys,
) -> None:
    """A dump from vault A, when loaded into vault B, yields the same
    secrets with the same content and tags."""
    vault_a.insert(keys_a, "work/aws", b"hunter2")
    vault_a.insert(keys_a, "work/github", b"correct horse battery staple")
    vault_a.set_tags(keys_a, "work/aws", ["cloud", "production"])

    buffer = io.BytesIO()
    result = dump_secrets(vault_a, keys_a, "passphrase-XYZ", buffer)
    assert result.secret_count == 2

    load_result = load_secrets(vault_b, keys_b, "passphrase-XYZ", buffer.getvalue())
    assert load_result.inserted == 2
    assert load_result.skipped == 0
    assert load_result.overwritten == 0

    assert vault_b.show(keys_b, "work/aws") == b"hunter2"
    assert vault_b.show(keys_b, "work/github") == b"correct horse battery staple"
    assert sorted(vault_b.search_by_tag(keys_b, "cloud")) == ["work/aws"]


def test_dump_load_round_trip_armored(
    vault_a: Vault,
    keys_a: UnlockedKeys,
    vault_b: Vault,
    keys_b: UnlockedKeys,
) -> None:
    """ASCII-armored dumps round-trip through base64 successfully."""
    vault_a.insert(keys_a, "work/aws", b"hunter2")

    buffer = io.BytesIO()
    dump_secrets(vault_a, keys_a, "p", buffer, armor=True)
    armored = buffer.getvalue()
    assert armored.startswith(b"-----BEGIN CAVERN DUMP-----")
    assert armored.rstrip(b"\n").endswith(b"-----END CAVERN DUMP-----")

    load_secrets(vault_b, keys_b, "p", armored)
    assert vault_b.show(keys_b, "work/aws") == b"hunter2"


# ---- Filtering ----------------------------------------------------------


def test_dump_filters_by_prefix(
    vault_a: Vault,
    keys_a: UnlockedKeys,
    vault_b: Vault,
    keys_b: UnlockedKeys,
) -> None:
    vault_a.insert(keys_a, "work/aws", b"x")
    vault_a.insert(keys_a, "work/github", b"y")
    vault_a.insert(keys_a, "personal/bank", b"z")

    buffer = io.BytesIO()
    result = dump_secrets(vault_a, keys_a, "p", buffer, prefix="work/")
    assert result.secret_count == 2

    load_secrets(vault_b, keys_b, "p", buffer.getvalue())
    assert sorted(vault_b.list_names(keys_b)) == ["work/aws", "work/github"]


def test_dump_filters_by_tag(
    vault_a: Vault,
    keys_a: UnlockedKeys,
    vault_b: Vault,
    keys_b: UnlockedKeys,
) -> None:
    vault_a.insert(keys_a, "work/aws", b"x")
    vault_a.insert(keys_a, "work/github", b"y")
    vault_a.insert(keys_a, "work/jenkins", b"z")
    vault_a.set_tags(keys_a, "work/aws", ["production"])
    vault_a.set_tags(keys_a, "work/github", ["staging"])
    vault_a.set_tags(keys_a, "work/jenkins", ["production"])

    buffer = io.BytesIO()
    result = dump_secrets(vault_a, keys_a, "p", buffer, tags=["production"])
    assert result.secret_count == 2

    load_secrets(vault_b, keys_b, "p", buffer.getvalue())
    assert sorted(vault_b.list_names(keys_b)) == ["work/aws", "work/jenkins"]


def test_dump_combines_prefix_and_tag_with_and(
    vault_a: Vault,
    keys_a: UnlockedKeys,
) -> None:
    vault_a.insert(keys_a, "work/aws", b"x")
    vault_a.insert(keys_a, "personal/aws", b"y")
    vault_a.set_tags(keys_a, "work/aws", ["cloud"])
    vault_a.set_tags(keys_a, "personal/aws", ["cloud"])

    buffer = io.BytesIO()
    result = dump_secrets(vault_a, keys_a, "p", buffer, prefix="work/", tags=["cloud"])
    assert result.secret_count == 1


def test_dump_with_no_matches_raises(vault_a: Vault, keys_a: UnlockedKeys) -> None:
    vault_a.insert(keys_a, "work/aws", b"x")
    buffer = io.BytesIO()
    with pytest.raises(CavernError, match="No secrets matched"):
        dump_secrets(vault_a, keys_a, "p", buffer, prefix="nonexistent/")


# ---- Failure modes -------------------------------------------------------


def test_load_with_wrong_passphrase_raises(
    vault_a: Vault,
    keys_a: UnlockedKeys,
    vault_b: Vault,
    keys_b: UnlockedKeys,
) -> None:
    vault_a.insert(keys_a, "x", b"hunter2")
    buffer = io.BytesIO()
    dump_secrets(vault_a, keys_a, "right-passphrase", buffer)

    with pytest.raises(CavernError, match="wrong passphrase|corrupt"):
        load_secrets(vault_b, keys_b, "wrong-passphrase", buffer.getvalue())


def test_dump_with_empty_passphrase_raises(
    vault_a: Vault, keys_a: UnlockedKeys
) -> None:
    vault_a.insert(keys_a, "x", b"x")
    buffer = io.BytesIO()
    with pytest.raises(CavernError, match="empty"):
        dump_secrets(vault_a, keys_a, "", buffer)


def test_load_with_empty_passphrase_raises(
    vault_b: Vault, keys_b: UnlockedKeys
) -> None:
    fake_blob = DUMP_MAGIC + bytes([DUMP_VERSION]) + b"x" * 200
    with pytest.raises(CavernError, match="empty"):
        load_secrets(vault_b, keys_b, "", fake_blob)


def test_load_rejects_bad_magic(vault_b: Vault, keys_b: UnlockedKeys) -> None:
    fake_blob = b"NOTMAGIC" + bytes([DUMP_VERSION]) + b"x" * 200
    with pytest.raises(CavernError, match="magic"):
        load_secrets(vault_b, keys_b, "p", fake_blob)


def test_load_rejects_unknown_version(vault_b: Vault, keys_b: UnlockedKeys) -> None:
    fake_blob = DUMP_MAGIC + bytes([0xFF]) + b"x" * 200
    with pytest.raises(CavernError, match="version"):
        load_secrets(vault_b, keys_b, "p", fake_blob)


def test_load_rejects_truncated_blob(vault_b: Vault, keys_b: UnlockedKeys) -> None:
    # Just the magic and version — way too short.
    blob = DUMP_MAGIC + bytes([DUMP_VERSION])
    with pytest.raises(CavernError, match="too short"):
        load_secrets(vault_b, keys_b, "p", blob)


def test_load_rejects_armored_without_end_marker(
    vault_b: Vault, keys_b: UnlockedKeys
) -> None:
    blob = b"-----BEGIN CAVERN DUMP-----\nAAAA\n"  # no END
    with pytest.raises(CavernError, match="END marker"):
        load_secrets(vault_b, keys_b, "p", blob)


# ---- Conflict handling --------------------------------------------------


def test_load_skips_existing_by_default(
    vault_a: Vault,
    keys_a: UnlockedKeys,
    vault_b: Vault,
    keys_b: UnlockedKeys,
) -> None:
    vault_a.insert(keys_a, "work/aws", b"new-value")
    vault_b.insert(keys_b, "work/aws", b"existing-value")

    buffer = io.BytesIO()
    dump_secrets(vault_a, keys_a, "p", buffer)
    result = load_secrets(vault_b, keys_b, "p", buffer.getvalue())

    assert result.skipped == 1
    assert result.inserted == 0
    assert result.overwritten == 0
    # Existing value preserved.
    assert vault_b.show(keys_b, "work/aws") == b"existing-value"


def test_load_overwrite_replaces_existing(
    vault_a: Vault,
    keys_a: UnlockedKeys,
    vault_b: Vault,
    keys_b: UnlockedKeys,
) -> None:
    vault_a.insert(keys_a, "work/aws", b"new-value")
    vault_b.insert(keys_b, "work/aws", b"existing-value")

    buffer = io.BytesIO()
    dump_secrets(vault_a, keys_a, "p", buffer)
    result = load_secrets(vault_b, keys_b, "p", buffer.getvalue(), overwrite=True)

    assert result.overwritten == 1
    assert result.inserted == 0
    assert result.skipped == 0
    assert vault_b.show(keys_b, "work/aws") == b"new-value"


# ---- Plaintext bulk-insert ----------------------------------------------


def _write_json(path: Path, payload: object, *, mode: int = 0o600) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, mode)


def test_bulk_insert_from_file_inserts(
    vault_b: Vault, keys_b: UnlockedKeys, tmp_path: Path
) -> None:
    json_path = tmp_path / "import.json"
    _write_json(
        json_path,
        [
            {"name": "work/aws", "value": "hunter2"},
            {
                "name": "work/github",
                "value": "correct horse",
                "tags": ["work", "developer"],
            },
        ],
    )

    result, warnings = bulk_insert_from_file(vault_b, keys_b, json_path)
    assert result.inserted == 2
    assert warnings == []
    assert vault_b.show(keys_b, "work/aws") == b"hunter2"
    assert sorted(vault_b.search_by_tag(keys_b, "developer")) == ["work/github"]


def test_bulk_insert_warns_on_loose_perms(
    vault_b: Vault, keys_b: UnlockedKeys, tmp_path: Path
) -> None:
    """A world-readable input file gets a warning, not a refusal."""
    json_path = tmp_path / "import.json"
    _write_json(json_path, [{"name": "x", "value": "y"}], mode=0o644)

    result, warnings = bulk_insert_from_file(vault_b, keys_b, json_path)
    assert result.inserted == 1
    assert any("loose permissions" in w for w in warnings)


def test_bulk_insert_rejects_missing_file(
    vault_b: Vault, keys_b: UnlockedKeys, tmp_path: Path
) -> None:
    with pytest.raises(CavernError, match="not found"):
        bulk_insert_from_file(vault_b, keys_b, tmp_path / "nope.json")


def test_bulk_insert_rejects_malformed_json(
    vault_b: Vault, keys_b: UnlockedKeys, tmp_path: Path
) -> None:
    json_path = tmp_path / "broken.json"
    json_path.write_text("{not valid json", encoding="utf-8")
    os.chmod(json_path, 0o600)
    with pytest.raises(CavernError, match="not valid JSON"):
        bulk_insert_from_file(vault_b, keys_b, json_path)


def test_bulk_insert_rejects_top_level_object(
    vault_b: Vault, keys_b: UnlockedKeys, tmp_path: Path
) -> None:
    """Top-level must be a list, not a dict."""
    json_path = tmp_path / "wrong-shape.json"
    _write_json(json_path, {"name": "x", "value": "y"})
    with pytest.raises(CavernError, match="list"):
        bulk_insert_from_file(vault_b, keys_b, json_path)


def test_bulk_insert_rejects_entry_missing_name(
    vault_b: Vault, keys_b: UnlockedKeys, tmp_path: Path
) -> None:
    json_path = tmp_path / "missing-name.json"
    _write_json(json_path, [{"value": "no-name-here"}])
    with pytest.raises(CavernError, match="name"):
        bulk_insert_from_file(vault_b, keys_b, json_path)


def test_bulk_insert_rejects_entry_with_non_string_value(
    vault_b: Vault, keys_b: UnlockedKeys, tmp_path: Path
) -> None:
    json_path = tmp_path / "wrong-value.json"
    _write_json(json_path, [{"name": "x", "value": 12345}])
    with pytest.raises(CavernError, match="value"):
        bulk_insert_from_file(vault_b, keys_b, json_path)


def test_bulk_insert_skips_existing_by_default(
    vault_b: Vault, keys_b: UnlockedKeys, tmp_path: Path
) -> None:
    vault_b.insert(keys_b, "work/aws", b"existing")
    json_path = tmp_path / "import.json"
    _write_json(json_path, [{"name": "work/aws", "value": "new"}])

    result, _ = bulk_insert_from_file(vault_b, keys_b, json_path)
    assert result.skipped == 1
    assert result.inserted == 0
    assert vault_b.show(keys_b, "work/aws") == b"existing"


def test_bulk_insert_overwrite_replaces_existing(
    vault_b: Vault, keys_b: UnlockedKeys, tmp_path: Path
) -> None:
    vault_b.insert(keys_b, "work/aws", b"existing")
    json_path = tmp_path / "import.json"
    _write_json(json_path, [{"name": "work/aws", "value": "new"}])

    result, _ = bulk_insert_from_file(vault_b, keys_b, json_path, overwrite=True)
    assert result.overwritten == 1
    assert vault_b.show(keys_b, "work/aws") == b"new"


def test_bulk_insert_does_not_delete_input_file(
    vault_b: Vault, keys_b: UnlockedKeys, tmp_path: Path
) -> None:
    """The input file is the user's; we must NOT unlink it."""
    json_path = tmp_path / "import.json"
    _write_json(json_path, [{"name": "x", "value": "y"}])

    bulk_insert_from_file(vault_b, keys_b, json_path)
    assert json_path.is_file()  # still there
