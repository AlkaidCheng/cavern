"""Tests for ``cavern.vault``.

These tests skip the GPG layer by constructing the vault directly
through ``init`` (which we patch to bypass GPG when no real keyring
is set up) — actually, simpler: we call the lower-level helpers and
fabricate ``UnlockedKeys`` directly.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cavern import crypto
from cavern.crypto import KEK_LENGTH, MASTER_KEY_LENGTH
from cavern.exceptions import (
    SecretExistsError,
    SecretNotFoundError,
    StoreError,
)
from cavern.vault import (
    UnlockedKeys,
    Vault,
    _deserialize_wrapped,
    _serialize_wrapped,
)


@pytest.fixture()
def vault_root(tmp_path: Path) -> Path:
    return tmp_path / "vault"


@pytest.fixture()
def vault(vault_root: Path) -> Vault:
    return Vault(root=vault_root)


@pytest.fixture()
def keys() -> UnlockedKeys:
    """Synthesize a key pair without going through GPG."""
    kek = os.urandom(KEK_LENGTH)
    master_key = os.urandom(MASTER_KEY_LENGTH)
    return UnlockedKeys(kek=kek, master_key=master_key)


def _bootstrap(vault: Vault, keys: UnlockedKeys) -> None:
    """Set up just enough on-disk state to use a vault without invoking GPG.

    Mirrors what ``Vault.init`` does, but skips ``gpg_encrypt_to_recipients``
    (which would require a real keyring).
    """
    vault.root.mkdir(parents=True, exist_ok=True)
    os.chmod(vault.root, 0o700)
    vault.store_path.mkdir(exist_ok=True)
    os.chmod(vault.store_path, 0o700)

    # Fake GPG blob — never read in these tests.
    vault.master_gpg_path.write_bytes(b"fake-gpg-blob")

    wrap_key = crypto.derive_wrap_key(keys.kek)
    wrapped = crypto.wrap_master_key(keys.master_key, wrap_key)
    vault.master_json_path.write_bytes(_serialize_wrapped(wrapped))

    vault.recipients_path.write_text("test@example.com\n", encoding="utf-8")

    empty_manifest = b'{"version":1,"entries":{}}'
    vault.manifest_path.write_bytes(
        crypto.encrypt_secret(empty_manifest, keys.master_key)
    )


# ---- master.json round-trip -----------------------------------------------


def test_wrapped_master_key_serialization_roundtrip() -> None:
    kek = os.urandom(KEK_LENGTH)
    master_key = os.urandom(MASTER_KEY_LENGTH)
    wrap_key = crypto.derive_wrap_key(kek)
    wrapped = crypto.wrap_master_key(master_key, wrap_key)
    blob = _serialize_wrapped(wrapped)
    restored = _deserialize_wrapped(blob)
    assert restored.nonce == wrapped.nonce
    assert restored.ciphertext == wrapped.ciphertext
    assert crypto.unwrap_master_key(restored, wrap_key) == master_key


# ---- derive_keys via wrapped master key -----------------------------------


def test_derive_keys_unwraps_master_from_kek(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    derived = vault.derive_keys(keys.kek)
    assert derived.kek == keys.kek
    assert derived.master_key == keys.master_key


# ---- CRUD -----------------------------------------------------------------


def test_insert_show_roundtrip(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"hunter2")
    assert vault.show(keys, "work/aws") == b"hunter2"


def test_insert_creates_hmac_named_file(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"hunter2")

    files = [p.name for p in vault.store_path.iterdir() if p.is_file()]
    assert len(files) == 1
    # Must be 32 hex chars (16 bytes of HMAC, hex-encoded).
    assert len(files[0]) == 32
    assert all(c in "0123456789abcdef" for c in files[0])
    # And must NOT be the original name or any obvious encoding of it.
    assert "work" not in files[0]
    assert "aws" not in files[0]


def test_insert_rejects_duplicate(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"first")
    with pytest.raises(SecretExistsError):
        vault.insert(keys, "work/aws", b"second")


def test_insert_force_overwrites(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"first")
    vault.insert(keys, "work/aws", b"second", force=True)
    assert vault.show(keys, "work/aws") == b"second"


def test_show_missing_raises(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    with pytest.raises(SecretNotFoundError):
        vault.show(keys, "nope")


def test_remove(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"hunter2")
    vault.remove(keys, "work/aws")
    assert not list(vault.store_path.iterdir())
    with pytest.raises(SecretNotFoundError):
        vault.show(keys, "work/aws")


def test_move(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"hunter2")
    vault.set_tags(keys, "work/aws", ["cloud"])
    vault.move(keys, "work/aws", "work/aws/prod")

    assert vault.show(keys, "work/aws/prod") == b"hunter2"
    with pytest.raises(SecretNotFoundError):
        vault.show(keys, "work/aws")
    # Tags carried over.
    assert vault.search_by_tag(keys, "cloud") == ["work/aws/prod"]


def test_empty_name_rejected(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    with pytest.raises(StoreError):
        vault.insert(keys, "  ", b"x")


# ---- Listing --------------------------------------------------------------


def test_list_names_empty(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    assert vault.list_names(keys) == []


def test_list_names_after_inserts(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    for name in ["work/aws", "personal/email", "work/github"]:
        vault.insert(keys, name, b"x")
    assert vault.list_names(keys) == ["personal/email", "work/aws", "work/github"]


def test_find_substring(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    for name in ["work/aws", "personal/email", "work/github"]:
        vault.insert(keys, name, b"x")
    assert vault.find(keys, "work") == ["work/aws", "work/github"]
    assert vault.find(keys, "EMAIL") == ["personal/email"]


# ---- Tags -----------------------------------------------------------------


def test_tag_search(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"x")
    vault.insert(keys, "work/gcp", b"x")
    vault.insert(keys, "personal/email", b"x")
    vault.set_tags(keys, "work/aws", ["cloud", "production"])
    vault.set_tags(keys, "work/gcp", ["cloud"])

    assert vault.search_by_tag(keys, "cloud") == ["work/aws", "work/gcp"]
    assert vault.search_by_tag(keys, "production") == ["work/aws"]
    assert vault.search_by_tag(keys, "missing") == []


def test_set_tags_normalizes(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"x")
    # Whitespace, mixed case, duplicates.
    vault.set_tags(keys, "work/aws", ["  Cloud ", "CLOUD", "production", "  "])

    assert vault.all_tags(keys) == ["cloud", "production"]


def test_set_tags_for_missing_secret_raises(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    with pytest.raises(SecretNotFoundError):
        vault.set_tags(keys, "nope", ["x"])


# ---- Manifest does NOT leak names to disk --------------------------------


def test_manifest_blob_does_not_contain_plaintext_names(
    vault: Vault, keys: UnlockedKeys
) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "very-distinctive-name-12345", b"x")

    raw = vault.manifest_path.read_bytes()
    assert b"very-distinctive-name-12345" not in raw


# ---- Drift detection -----------------------------------------------------


def test_audit_drift_detects_orphan_file(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"x")
    # Drop a stray file directly into store/ with a plausible-looking name.
    (vault.store_path / ("deadbeef" * 4)).write_bytes(b"orphan")

    orphans, missing = vault.audit_drift(keys)
    assert "deadbeefdeadbeefdeadbeefdeadbeef" in orphans
    assert missing == []


def test_audit_drift_detects_missing_file(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"x")
    # Remove the file out-of-band, leaving the manifest entry stale.
    for p in vault.store_path.iterdir():
        p.unlink()

    orphans, missing = vault.audit_drift(keys)
    assert orphans == []
    assert missing == ["work/aws"]


def test_reindex_drops_dead_entries(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"x")
    vault.insert(keys, "personal/email", b"x")
    # Out-of-band remove.
    list(vault.store_path.iterdir())[0].unlink()

    removed = vault.reindex(keys)
    assert removed == 1
    assert len(vault.list_names(keys)) == 1


# ---- Rotation -----------------------------------------------------------


def test_rotate_master_key_preserves_secrets(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"hunter2")
    vault.insert(keys, "work/gcp", b"sekret")
    vault.set_tags(keys, "work/aws", ["cloud"])

    # Capture the on-disk filenames; they MUST NOT change after rotation.
    before_files = {p.name for p in vault.store_path.iterdir()}

    count = vault.rotate_master_key(keys)
    assert count == 2

    # Reload keys from the (newly rewrapped) master.json.
    new_keys = vault.derive_keys(keys.kek)
    assert new_keys.kek == keys.kek
    assert new_keys.master_key != keys.master_key

    after_files = {p.name for p in vault.store_path.iterdir()}
    assert before_files == after_files

    # Old keys can no longer decrypt; new keys can, including manifest.
    assert vault.show(new_keys, "work/aws") == b"hunter2"
    assert vault.show(new_keys, "work/gcp") == b"sekret"
    assert vault.search_by_tag(new_keys, "cloud") == ["work/aws"]


def test_rotation_does_not_touch_content_ciphertext(
    vault: Vault, keys: UnlockedKeys
) -> None:
    """Property test: only the wrapped DEK changes, not the content blob."""
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"hunter2")

    path = next(vault.store_path.iterdir())
    before = path.read_bytes()

    vault.rotate_master_key(keys)

    after = path.read_bytes()
    # First few bytes (magic + version) identical.
    assert after[:5] == before[:5]
    # Same total length.
    assert len(after) == len(before)

    # The tail (content_nonce + bucket_size + content_ct) must match.
    from cavern.crypto import (
        DEK_LENGTH,
        FILE_MAGIC,
        GCM_NONCE_LENGTH,
        GCM_TAG_LENGTH,
    )

    tail_start = len(FILE_MAGIC) + 1 + GCM_NONCE_LENGTH + DEK_LENGTH + GCM_TAG_LENGTH
    assert after[tail_start:] == before[tail_start:]


def test_rotation_preserves_audit_log(vault: Vault, keys: UnlockedKeys) -> None:
    """Regression: rotation must re-encrypt the audit log so its history
    survives the master-key change.

    Reproduces a bug found via end-to-end testing: the audit log is
    encrypted under the master key directly (no wrapped DEK), so
    rotation that only rewraps DEKs would leave the audit log
    unreadable with the new key, silently destroying history.
    """
    from cavern.audit import AuditLog

    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"x")

    log_before = AuditLog(vault.root, keys.master_key)
    log_before.append("custom-event", "work/aws")
    records_before = log_before.recent()
    assert any(r.get("action") == "custom-event" for r in records_before)

    vault.rotate_master_key(keys)
    new_keys = vault.derive_keys(keys.kek)

    log_after = AuditLog(vault.root, new_keys.master_key)
    records_after = log_after.recent()
    # The pre-rotation custom-event must still be there.
    assert any(r.get("action") == "custom-event" for r in records_after)


# ---- Concurrency ----------------------------------------------------------


def test_lock_serializes_mutations(vault: Vault, keys: UnlockedKeys) -> None:
    """Two writers contending for the lock must serialize cleanly.

    We run multiple threads that each call ``insert`` with a different
    name. Without the lock they could race the manifest read-modify-
    write cycle and one would silently overwrite the other's manifest
    entry. With the lock, every name must end up in the manifest.
    """
    import threading

    _bootstrap(vault, keys)

    errors: list[BaseException] = []

    def writer(name: str) -> None:
        try:
            vault.insert(keys, name, b"x")
        except BaseException as exc:  # noqa: BLE001  # surface anything
            errors.append(exc)

    threads = [
        threading.Thread(target=writer, args=(f"work/secret-{i}",)) for i in range(20)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    names = vault.list_names(keys)
    assert len(names) == 20
    for i in range(20):
        assert f"work/secret-{i}" in names


def test_lock_acquires_release_cleanly(vault: Vault, keys: UnlockedKeys) -> None:
    """Sequential lock acquisitions in the same process must not deadlock."""
    _bootstrap(vault, keys)
    with vault.lock():
        pass
    with vault.lock():
        pass  # if we got here, no deadlock


# ---- Name normalization ---------------------------------------------------


def test_insert_strips_whitespace_in_name(vault: Vault, keys: UnlockedKeys) -> None:
    """`'foo'` and `'foo '` map to the same secret.

    Without normalization, an HMAC over a whitespace-padded name would
    produce a different on-disk filename than the trimmed name, and
    the user could end up with two secrets they think are the same.
    """
    _bootstrap(vault, keys)
    vault.insert(keys, "  work/aws  ", b"hunter2")
    # Round-trip through the trimmed name.
    assert vault.show(keys, "work/aws") == b"hunter2"
    assert vault.show(keys, " work/aws") == b"hunter2"
    # And the manifest displays the canonical form.
    assert vault.list_names(keys) == ["work/aws"]


def test_remove_normalizes_name(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"x")
    vault.remove(keys, "  work/aws  ")
    assert vault.list_names(keys) == []


def test_whitespace_only_name_rejected(vault: Vault, keys: UnlockedKeys) -> None:
    _bootstrap(vault, keys)
    with pytest.raises(StoreError):
        vault.insert(keys, "   ", b"x")
    with pytest.raises(StoreError):
        vault.show(keys, "")


# ---- Drift detection on uninitialized vault ------------------------------


def test_audit_drift_handles_missing_store_dir(
    vault: Vault, keys: UnlockedKeys
) -> None:
    """Calling audit_drift on a vault whose store/ has been wiped
    must return cleanly rather than raising FileNotFoundError."""
    _bootstrap(vault, keys)
    vault.insert(keys, "work/aws", b"x")
    # Wipe the store directory out-of-band.
    import shutil

    shutil.rmtree(vault.store_path)

    orphans, missing = vault.audit_drift(keys)
    assert orphans == []
    assert missing == ["work/aws"]


# ---- _atomic_write durability ---------------------------------------------


def test_atomic_write_cleans_up_on_keyboardinterrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A KeyboardInterrupt mid-write must not leave .tmp.* debris."""
    from cavern.vault import _atomic_write

    target = tmp_path / "out"

    def boom(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    # Patch os.replace so the rename step raises.
    monkeypatch.setattr("cavern.vault.os.replace", boom)

    with pytest.raises(KeyboardInterrupt):
        _atomic_write(target, b"payload")

    # No leftover temp files.
    debris = [p.name for p in tmp_path.iterdir() if p.name.startswith(".tmp.")]
    assert debris == []
    # And the target was never created.
    assert not target.exists()
