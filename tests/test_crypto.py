"""Tests for the cryptographic core.

These are the most important tests in the package. If any of these
fail, secrets are at risk.
"""

from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path

import pytest

from cavern.crypto import (
    DEK_LENGTH,
    FILE_MAGIC,
    FILE_VERSION,
    GCM_NONCE_LENGTH,
    GCM_TAG_LENGTH,
    HMAC_FILENAME_BYTES,
    KEK_LENGTH,
    MASTER_KEY_LENGTH,
    _bucket_for,
    _is_lock_contention,
    _is_lock_stale,
    _pad,
    _parse_dotlock,
    _pid_alive_on_this_host,
    _run_gpg_with_lock_recovery,
    _unpad,
    clean_stale_keyring_locks,
    decrypt_secret,
    derive_filename_key,
    derive_wrap_key,
    encrypt_secret,
    rewrap_master_key_in_blob,
    stored_filename,
    unwrap_master_key,
    wrap_master_key,
)
from cavern.exceptions import CryptoError

# ---- Padding ---------------------------------------------------------------


@pytest.mark.parametrize(
    "plaintext_len, expected_bucket",
    [
        (0, 256),
        (1, 256),
        (255, 256),  # 255 + 1 marker = 256, fits exactly
        (256, 1024),  # 256 + 1 marker = 257, needs next bucket up
        (1023, 1024),
        (1024, 4096),
        (4095, 4096),
        (4096, 16384),
        (16383, 16384),
        (16384, 32768),  # > largest bucket, rounds to 2x
        (20000, 32768),
        (32768, 49152),  # > 32768 + 1, rounds to 3x largest
    ],
)
def test_bucket_selection(plaintext_len: int, expected_bucket: int) -> None:
    assert _bucket_for(plaintext_len) == expected_bucket


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        b"x",
        b"hunter2",
        b"a" * 100,
        b"a" * 256,
        b"a" * 1023,
        b"a" * 1024,
        b"a" * 5000,
        b"a" * 16384,
        os.urandom(20_480),
    ],
    # Without explicit ids, pytest renders each `bytes` parameter as
    # its repr — so a 20 480-byte random value produces a 100 KB test
    # name. Naming each case keeps `pytest -v` output compact and
    # actually informative.
    ids=[
        "empty",
        "1B",
        "7B",
        "100B",
        "256B",
        "1023B",
        "1024B",
        "5000B",
        "16KiB",
        "20KiB-random",
    ],
)
def test_padding_roundtrip(plaintext: bytes) -> None:
    assert _unpad(_pad(plaintext)) == plaintext


def test_padded_length_is_a_bucket() -> None:
    # Every padded output should have a length that's a recognized bucket
    # (or a multiple of the largest bucket for oversized inputs).
    for n in range(0, 5000, 17):
        padded = _pad(b"x" * n)
        bucket = len(padded)
        assert bucket in (256, 1024, 4096, 16384) or bucket % 16384 == 0


def test_unpad_rejects_missing_marker() -> None:
    with pytest.raises(CryptoError):
        _unpad(b"\x00" * 256)


def test_unpad_rejects_empty() -> None:
    with pytest.raises(CryptoError):
        _unpad(b"")


# ---- Key derivation --------------------------------------------------------


def test_filename_key_is_deterministic() -> None:
    kek = b"k" * KEK_LENGTH
    assert derive_filename_key(kek) == derive_filename_key(kek)


def test_filename_key_changes_with_kek() -> None:
    a = derive_filename_key(b"a" * KEK_LENGTH)
    b = derive_filename_key(b"b" * KEK_LENGTH)
    assert a != b


def test_filename_and_wrap_keys_differ() -> None:
    # Domain separation: same KEK must produce different subkeys.
    kek = os.urandom(KEK_LENGTH)
    assert derive_filename_key(kek) != derive_wrap_key(kek)


def test_derive_rejects_wrong_kek_length() -> None:
    with pytest.raises(CryptoError):
        derive_filename_key(b"short")
    with pytest.raises(CryptoError):
        derive_wrap_key(b"x" * 31)


# ---- Stored filenames ------------------------------------------------------


def test_stored_filename_is_deterministic() -> None:
    fk = derive_filename_key(os.urandom(KEK_LENGTH))
    assert stored_filename(fk, "work/aws") == stored_filename(fk, "work/aws")


def test_stored_filename_length() -> None:
    fk = derive_filename_key(os.urandom(KEK_LENGTH))
    name = stored_filename(fk, "work/aws")
    assert len(name) == HMAC_FILENAME_BYTES * 2  # hex
    assert all(c in "0123456789abcdef" for c in name)


def test_stored_filename_different_for_different_names() -> None:
    fk = derive_filename_key(os.urandom(KEK_LENGTH))
    assert stored_filename(fk, "a") != stored_filename(fk, "b")


def test_stored_filename_different_for_different_keys() -> None:
    name = "work/aws"
    a = stored_filename(derive_filename_key(b"a" * KEK_LENGTH), name)
    b = stored_filename(derive_filename_key(b"b" * KEK_LENGTH), name)
    assert a != b


# ---- Master key wrapping ---------------------------------------------------


def test_master_key_wrap_unwrap_roundtrip() -> None:
    wrap_key = os.urandom(32)
    master_key = os.urandom(MASTER_KEY_LENGTH)
    wrapped = wrap_master_key(master_key, wrap_key)
    assert unwrap_master_key(wrapped, wrap_key) == master_key


def test_master_key_unwrap_with_wrong_key_fails() -> None:
    wrap_key = os.urandom(32)
    master_key = os.urandom(MASTER_KEY_LENGTH)
    wrapped = wrap_master_key(master_key, wrap_key)
    with pytest.raises(CryptoError):
        unwrap_master_key(wrapped, os.urandom(32))


def test_wrap_rejects_wrong_master_key_length() -> None:
    with pytest.raises(CryptoError):
        wrap_master_key(b"too short", os.urandom(32))


def test_wrap_uses_fresh_nonces() -> None:
    # Wrapping the same master key twice must produce different ciphertexts —
    # otherwise we'd be leaking that the key hasn't changed.
    wrap_key = os.urandom(32)
    mk = os.urandom(MASTER_KEY_LENGTH)
    a = wrap_master_key(mk, wrap_key)
    b = wrap_master_key(mk, wrap_key)
    assert a.nonce != b.nonce
    assert a.ciphertext != b.ciphertext


# ---- Per-secret encrypt/decrypt -------------------------------------------


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        b"hunter2",
        b"a multiline\nsecret with\nnewlines",
        b"\x00\x01\x02\xff\xfe",  # binary
        b"a" * 50,
        b"a" * 500,
        b"a" * 5000,
        b"a" * 20_000,  # > 16 KiB bucket
    ],
    ids=[
        "empty",
        "ascii",
        "multiline",
        "binary-bytes",
        "50B",
        "500B",
        "5000B",
        "20000B",
    ],
)
def test_encrypt_decrypt_roundtrip(plaintext: bytes) -> None:
    master_key = os.urandom(MASTER_KEY_LENGTH)
    blob = encrypt_secret(plaintext, master_key)
    assert decrypt_secret(blob, master_key) == plaintext


def test_blob_starts_with_magic_and_version() -> None:
    blob = encrypt_secret(b"hello", os.urandom(MASTER_KEY_LENGTH))
    assert blob[: len(FILE_MAGIC)] == FILE_MAGIC
    assert blob[len(FILE_MAGIC)] == FILE_VERSION


def test_blob_size_falls_in_bucket() -> None:
    # A 10-byte secret should pad to the 256B bucket.
    master_key = os.urandom(MASTER_KEY_LENGTH)
    blob = encrypt_secret(b"x" * 10, master_key)

    # Header is fixed, content_ct = bucket + tag.
    overhead = (
        len(FILE_MAGIC)
        + 1  # version
        + GCM_NONCE_LENGTH  # wrap nonce
        + DEK_LENGTH
        + GCM_TAG_LENGTH  # wrapped DEK
        + GCM_NONCE_LENGTH  # content nonce
        + 4  # bucket_size
        + GCM_TAG_LENGTH  # content tag
    )
    content_size = len(blob) - overhead
    assert content_size == 256

    # And a 300-byte secret should pad to 1 KiB.
    blob = encrypt_secret(b"x" * 300, master_key)
    content_size = len(blob) - overhead
    assert content_size == 1024


def test_two_encrypts_of_same_plaintext_differ() -> None:
    # Same plaintext + same master key must produce different ciphertexts.
    # If they don't, something is using a static nonce.
    master_key = os.urandom(MASTER_KEY_LENGTH)
    a = encrypt_secret(b"hunter2", master_key)
    b = encrypt_secret(b"hunter2", master_key)
    assert a != b
    # And both must still decrypt correctly.
    assert decrypt_secret(a, master_key) == b"hunter2"
    assert decrypt_secret(b, master_key) == b"hunter2"


def test_decrypt_with_wrong_master_key_fails() -> None:
    blob = encrypt_secret(b"hunter2", os.urandom(MASTER_KEY_LENGTH))
    with pytest.raises(CryptoError):
        decrypt_secret(blob, os.urandom(MASTER_KEY_LENGTH))


def test_decrypt_detects_tampered_content() -> None:
    master_key = os.urandom(MASTER_KEY_LENGTH)
    blob = bytearray(encrypt_secret(b"hunter2", master_key))
    blob[-1] ^= 0x01  # flip a bit in the GCM tag
    with pytest.raises(CryptoError):
        decrypt_secret(bytes(blob), master_key)


def test_decrypt_detects_tampered_wrapped_dek() -> None:
    master_key = os.urandom(MASTER_KEY_LENGTH)
    blob = bytearray(encrypt_secret(b"hunter2", master_key))
    # Flip a bit inside the wrapped DEK area (after magic + version + wrap_nonce).
    pos = len(FILE_MAGIC) + 1 + GCM_NONCE_LENGTH
    blob[pos] ^= 0x01
    with pytest.raises(CryptoError):
        decrypt_secret(bytes(blob), master_key)


def test_decrypt_rejects_bad_magic() -> None:
    master_key = os.urandom(MASTER_KEY_LENGTH)
    blob = bytearray(encrypt_secret(b"hunter2", master_key))
    blob[0] = ord("X")
    with pytest.raises(CryptoError):
        decrypt_secret(bytes(blob), master_key)


def test_decrypt_rejects_unknown_version() -> None:
    master_key = os.urandom(MASTER_KEY_LENGTH)
    blob = bytearray(encrypt_secret(b"hunter2", master_key))
    blob[len(FILE_MAGIC)] = 0xFF
    with pytest.raises(CryptoError):
        decrypt_secret(bytes(blob), master_key)


def test_decrypt_rejects_truncation() -> None:
    master_key = os.urandom(MASTER_KEY_LENGTH)
    blob = encrypt_secret(b"hunter2", master_key)
    with pytest.raises(CryptoError):
        decrypt_secret(blob[:20], master_key)


# ---- Master-key rotation (rewrap) -----------------------------------------


def test_rewrap_preserves_plaintext() -> None:
    old_mk = os.urandom(MASTER_KEY_LENGTH)
    new_mk = os.urandom(MASTER_KEY_LENGTH)
    blob = encrypt_secret(b"hunter2", old_mk)

    rewrapped = rewrap_master_key_in_blob(blob, old_mk, new_mk)
    # Old key no longer works…
    with pytest.raises(CryptoError):
        decrypt_secret(rewrapped, old_mk)
    # …new key does, and recovers the original plaintext.
    assert decrypt_secret(rewrapped, new_mk) == b"hunter2"


def test_rewrap_preserves_content_ciphertext() -> None:
    """The expensive content_ct must be untouched — that's the whole point."""
    old_mk = os.urandom(MASTER_KEY_LENGTH)
    new_mk = os.urandom(MASTER_KEY_LENGTH)
    blob = encrypt_secret(b"hunter2", old_mk)
    rewrapped = rewrap_master_key_in_blob(blob, old_mk, new_mk)

    # Same length, and the tail (content_nonce + bucket_size + content_ct)
    # must be byte-identical.
    tail_start = len(FILE_MAGIC) + 1 + GCM_NONCE_LENGTH + DEK_LENGTH + GCM_TAG_LENGTH
    assert len(rewrapped) == len(blob)
    assert rewrapped[tail_start:] == blob[tail_start:]


def test_rewrap_with_wrong_old_key_fails() -> None:
    old_mk = os.urandom(MASTER_KEY_LENGTH)
    new_mk = os.urandom(MASTER_KEY_LENGTH)
    blob = encrypt_secret(b"hunter2", old_mk)
    with pytest.raises(CryptoError):
        rewrap_master_key_in_blob(blob, os.urandom(MASTER_KEY_LENGTH), new_mk)


# ---- Input validation ------------------------------------------------------


def test_stored_filename_rejects_wrong_key_length() -> None:
    """Passing a non-32-byte filename_key is a programmer error,
    not a silent miscomputation. We refuse rather than mapping the
    caller's secret to an unintended filesystem location."""
    from cavern.crypto import stored_filename

    with pytest.raises(CryptoError, match="filename_key"):
        stored_filename(b"too short", "work/aws")
    with pytest.raises(CryptoError, match="filename_key"):
        stored_filename(b"x" * 31, "work/aws")
    with pytest.raises(CryptoError, match="filename_key"):
        stored_filename(b"x" * 33, "work/aws")


def test_decrypt_secret_rejects_wrong_master_key_length() -> None:
    blob = encrypt_secret(b"hunter2", os.urandom(MASTER_KEY_LENGTH))
    with pytest.raises(CryptoError, match="master_key"):
        decrypt_secret(blob, b"too short")


def test_unwrap_master_key_rejects_wrong_wrap_key_length() -> None:
    """Validation surfaces programmer errors with a clear message."""
    from cavern.crypto import wrap_master_key

    wrap_key = os.urandom(32)
    master_key = os.urandom(MASTER_KEY_LENGTH)
    wrapped = wrap_master_key(master_key, wrap_key)
    with pytest.raises(CryptoError, match="wrap_key"):
        unwrap_master_key(wrapped, b"too short")


def test_rewrap_validates_master_key_lengths() -> None:
    """Bad-length master keys produce CryptoError, not a slice into garbage."""
    blob = encrypt_secret(b"hunter2", os.urandom(MASTER_KEY_LENGTH))
    with pytest.raises(CryptoError, match="old_master_key"):
        rewrap_master_key_in_blob(blob, b"x" * 16, os.urandom(MASTER_KEY_LENGTH))
    with pytest.raises(CryptoError, match="new_master_key"):
        rewrap_master_key_in_blob(blob, os.urandom(MASTER_KEY_LENGTH), b"x" * 16)


def test_rewrap_rejects_short_blob() -> None:
    """A truncated blob would otherwise slice into out-of-bounds bytes
    and produce silent garbage."""
    with pytest.raises(CryptoError, match="shorter than"):
        rewrap_master_key_in_blob(
            b"CVRN\x01short",
            os.urandom(MASTER_KEY_LENGTH),
            os.urandom(MASTER_KEY_LENGTH),
        )


def test_rewrap_rejects_bad_magic() -> None:
    blob = bytearray(encrypt_secret(b"x", os.urandom(MASTER_KEY_LENGTH)))
    blob[0] = ord("X")
    with pytest.raises(CryptoError, match="magic"):
        rewrap_master_key_in_blob(
            bytes(blob), os.urandom(MASTER_KEY_LENGTH), os.urandom(MASTER_KEY_LENGTH)
        )


def test_rewrap_rejects_unknown_version() -> None:
    blob = bytearray(encrypt_secret(b"x", os.urandom(MASTER_KEY_LENGTH)))
    blob[len(b"CVRN")] = 0xFF
    with pytest.raises(CryptoError, match="version"):
        rewrap_master_key_in_blob(
            bytes(blob), os.urandom(MASTER_KEY_LENGTH), os.urandom(MASTER_KEY_LENGTH)
        )


# ---- GPG keyring-lock recovery --------------------------------------------
#
# Exercises the stale-lock detection and recovery layer. We don't need a
# real gpg here -- the logic operates on filesystem state and PID
# liveness, both of which we control with a tmp $GNUPGHOME and a
# real-but-known-dead PID.


_THIS_HOST = socket.gethostname()


@pytest.fixture
def fake_gnupg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A throwaway ``$GNUPGHOME`` with the standard subdirs in place."""
    home = tmp_path / "gnupg"
    home.mkdir()
    (home / "public-keys.v1.d").mkdir()
    monkeypatch.setenv("GNUPGHOME", str(home))
    return home


# ---- _is_lock_contention ---


def test_lock_contention_matches_keyboxd_timeout_signature() -> None:
    # The three-line keyboxd timeout sequence: "waiting for lock" repeats
    # while gpg blocks, then "keydb_search failed: Connection timed out"
    # when the wait exhausts, then "public key decryption failed: No
    # secret key" because the keyring was never reachable. All three
    # appear in the typical stale-cross-host-lock failure.
    stderr = (
        "gpg: Note: database_open 134217901 waiting for lock (held by 1186029) ...\n"
        "gpg: keydb_search failed: Connection timed out\n"
        "gpg: public key decryption failed: No secret key\n"
    )
    assert _is_lock_contention(stderr)


@pytest.mark.parametrize(
    "indicator",
    ["waiting for lock", "keydb_search failed", "Connection timed out"],
)
def test_lock_contention_each_indicator_triggers(indicator: str) -> None:
    assert _is_lock_contention(f"prefix {indicator} suffix")


def test_lock_contention_unrelated_gpg_error_is_not_match() -> None:
    # The "No public key" failure mode is a separate diagnostic with
    # its own handling -- recovery must NOT fire here.
    assert not _is_lock_contention("gpg: alkaidc: skipped: No public key")


def test_lock_contention_empty_stderr_is_not_match() -> None:
    assert not _is_lock_contention("")


# ---- _parse_dotlock ---


def test_parse_dotlock_pid_and_hostname(fake_gnupg: Path) -> None:
    lock = fake_gnupg / "pubring.kbx.lock"
    lock.write_text("12345 host-a.example.com\n")
    assert _parse_dotlock(lock) == (12345, "host-a.example.com")


def test_parse_dotlock_pid_only(fake_gnupg: Path) -> None:
    lock = fake_gnupg / "pubring.kbx.lock"
    lock.write_text("12345\n")
    assert _parse_dotlock(lock) == (12345, "")


@pytest.mark.parametrize(
    "contents",
    ["", "not-a-pid\n", "garbage contents\n", "   \n"],
    ids=["empty", "non-numeric-pid", "garbage", "whitespace-only"],
)
def test_parse_dotlock_unparseable_returns_none(
    fake_gnupg: Path, contents: str
) -> None:
    lock = fake_gnupg / "pubring.kbx.lock"
    lock.write_text(contents)
    assert _parse_dotlock(lock) is None


# ---- _is_lock_stale ---


def test_lock_stale_dead_pid_same_host(fake_gnupg: Path) -> None:
    # PID 999_999 is exceedingly unlikely to exist; double-check before
    # relying on it as "definitely dead."
    assert not _pid_alive_on_this_host(999_999)
    lock = fake_gnupg / "pubring.kbx.lock"
    lock.write_text(f"999999 {_THIS_HOST}\n")
    assert _is_lock_stale(lock)


def test_lock_stale_live_pid_same_host_is_not_stale(fake_gnupg: Path) -> None:
    # The current process is, by definition, alive. We must never
    # declare a lock held by a live local process as stale -- doing
    # so could corrupt a concurrent keyring operation.
    lock = fake_gnupg / "pubring.kbx.lock"
    lock.write_text(f"{os.getpid()} {_THIS_HOST}\n")
    assert not _is_lock_stale(lock)


def test_lock_stale_different_host_is_stale_regardless_of_pid(
    fake_gnupg: Path,
) -> None:
    # Lock recorded by a different host -- the typical staleness mode
    # on a network-shared $GNUPGHOME. PID happens to be alive locally;
    # doesn't matter, host comparison wins.
    lock = fake_gnupg / "pubring.kbx.lock"
    lock.write_text(f"{os.getpid()} other-host.example.com\n")
    assert _is_lock_stale(lock)


def test_lock_stale_keyboxd_database_lock_with_unreachable_holder(
    fake_gnupg: Path,
) -> None:
    # The canonical stale-cross-host-lock layout: GPG 2.4+ keyboxd
    # creates pubring.db inside public-keys.v1.d/ and its dotlock
    # records the host the holder was on. When the holder is on a
    # different host (here, "host-a.example.com"), the lock is by
    # definition unreachable from the current process.
    lock = fake_gnupg / "public-keys.v1.d" / "pubring.db.lock"
    lock.write_text("1186029 host-a.example.com\n")
    assert _is_lock_stale(lock)


def test_lock_stale_colliding_short_name_is_still_different_host(
    fake_gnupg: Path,
) -> None:
    """Locks naming a different FQDN that happens to share our short
    name must be treated as a different host.

    This is the failure mode that short-name normalization would
    mask: ``worker-1.cluster-a.example.com`` vs
    ``worker-1.cluster-b.example.com`` on a $GNUPGHOME shared across
    administrative domains. Strict equality treats them as different,
    so a real remote lock on cluster-b is not incorrectly declared
    "same host with dead PID" just because we're on cluster-a.

    Here we synthesize the scenario by writing a hostname that
    differs from ``socket.gethostname()`` but isn't ``other-host`` --
    any string that isn't exactly the local hostname must be
    classified as different.
    """
    # Build a recorded hostname that overlaps with the local one if
    # short-name comparison were in effect, but is not exactly equal.
    fabricated = _THIS_HOST + ".another-domain.invalid"
    if fabricated == _THIS_HOST:  # impossible, but defensive
        pytest.skip("local hostname format does not permit this test")
    lock = fake_gnupg / "pubring.kbx.lock"
    # PID happens to be alive locally; under strict equality we
    # never reach the PID check because the host doesn't match.
    lock.write_text(f"{os.getpid()} {fabricated}\n")
    assert _is_lock_stale(lock)


def test_lock_stale_unparseable_is_not_stale(fake_gnupg: Path) -> None:
    # Conservative default: better to surface a real error than remove
    # a lock we can't reason about.
    lock = fake_gnupg / "pubring.kbx.lock"
    lock.write_text("garbage contents\n")
    assert not _is_lock_stale(lock)


def test_lock_stale_missing_hostname_treated_as_this_host(
    fake_gnupg: Path,
) -> None:
    # Old dotlock variants omit the hostname. Dead PID -> stale,
    # live PID -> NOT stale.
    dead = fake_gnupg / "a.lock"
    dead.write_text("999999\n")
    assert _is_lock_stale(dead)
    live = fake_gnupg / "b.lock"
    live.write_text(f"{os.getpid()}\n")
    assert not _is_lock_stale(live)


# ---- clean_stale_keyring_locks ---


def test_clean_removes_stale_locks_and_preserves_live_locks(
    fake_gnupg: Path,
) -> None:
    stale = fake_gnupg / "public-keys.v1.d" / "pubring.db.lock"
    stale.write_text("1186029 host-a.example.com\n")
    live = fake_gnupg / "trustdb.gpg.lock"
    live.write_text(f"{os.getpid()} {_THIS_HOST}\n")

    removed = clean_stale_keyring_locks()

    assert removed == [stale]
    assert not stale.exists()
    assert live.exists()


def test_clean_never_touches_non_lock_files(fake_gnupg: Path) -> None:
    """The load-bearing safety check: we must not remove the actual keyring.

    If this test ever fails, the recovery layer is dangerous and the
    feature must be disabled.
    """
    db = fake_gnupg / "public-keys.v1.d" / "pubring.db"
    db.write_bytes(b"this is the actual keyring; do not touch")
    kbx = fake_gnupg / "pubring.kbx"
    kbx.write_bytes(b"and neither is this")
    # Put a stale lock next to them to make sure the sweep actually runs.
    stale = fake_gnupg / "public-keys.v1.d" / "pubring.db.lock"
    stale.write_text("999999 other-host.example.com\n")

    clean_stale_keyring_locks()

    assert db.read_bytes() == b"this is the actual keyring; do not touch"
    assert kbx.read_bytes() == b"and neither is this"


def test_clean_missing_gnupg_home_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GNUPGHOME", "/nonexistent/path/xyz-cavern-test")
    assert clean_stale_keyring_locks() == []


def test_clean_unparseable_lock_is_kept(fake_gnupg: Path) -> None:
    lock = fake_gnupg / "pubring.kbx.lock"
    lock.write_text("totally garbled\n")
    assert clean_stale_keyring_locks() == []
    assert lock.exists()


# ---- _run_gpg_with_lock_recovery ---
#
# These tests use a fake subprocess.run so we don't depend on gpg
# being installed and don't risk touching the developer's real
# keyring. The wrapper's contract is precisely: "on a lock-contention
# failure, run recovery and retry exactly once" -- so that's what we
# verify, independent of any real gpg behavior.
#
# Monkeypatch note: we patch ``cavern.crypto.subprocess.run`` (the
# module attribute), not ``subprocess.run`` globally. pytest's
# monkeypatch undoes this at test teardown, so other tests in the
# same session never see the fake. Patching globally would risk
# bleeding into unrelated subprocess use elsewhere in the suite.


def _fake_completed(
    returncode: int, stderr: bytes = b"", stdout: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        args=["gpg"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def test_retry_passthrough_when_first_call_succeeds(
    fake_gnupg: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def fake_run(
        args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        return _fake_completed(0, stdout=b"plaintext")

    monkeypatch.setattr("cavern.crypto.subprocess.run", fake_run)

    result = _run_gpg_with_lock_recovery(["gpg", "--decrypt"], stdin=None)
    assert result.returncode == 0
    assert result.stdout == b"plaintext"
    assert len(calls) == 1  # no retry on success


def test_retry_does_not_fire_on_unrelated_gpg_error(
    fake_gnupg: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The "No public key" failure is a separate diagnostic; we must
    # NOT retry, because the recovery is irrelevant and the retry
    # would just produce the same error twice (wasting time and
    # potentially double-printing pinentry prompts).
    calls: list[list[str]] = []

    def fake_run(
        args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        return _fake_completed(2, stderr=b"gpg: alkaidc: skipped: No public key\n")

    monkeypatch.setattr("cavern.crypto.subprocess.run", fake_run)

    result = _run_gpg_with_lock_recovery(["gpg", "--encrypt"], stdin=b"x")
    assert result.returncode == 2
    assert len(calls) == 1  # no retry


def test_retry_recovers_when_lock_clears_after_cleanup(
    fake_gnupg: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end happy path for the recovery sequence.

    First gpg call returns the keyring-lock contention stderr.
    Recovery cleans the planted stale lock. Second gpg call succeeds.
    """
    # Plant a stale cross-node lock that recovery should clean up.
    (fake_gnupg / "public-keys.v1.d" / "pubring.db.lock").write_text(
        "1186029 host-a.example.com\n"
    )

    call_count = 0

    def fake_run(
        args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        # Distinguish our gpg call from the gpgconf --kill all helper.
        if args and args[0] == "gpgconf":
            return _fake_completed(0)
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _fake_completed(
                2,
                stderr=(
                    b"gpg: Note: database_open waiting for lock "
                    b"(held by 1186029) ...\n"
                    b"gpg: keydb_search failed: Connection timed out\n"
                ),
            )
        return _fake_completed(0, stdout=b"plaintext")

    monkeypatch.setattr("cavern.crypto.subprocess.run", fake_run)
    # gpgconf may not exist in the test environment; force the path.
    monkeypatch.setattr("cavern.crypto.shutil.which", lambda _: "/usr/bin/gpgconf")

    result = _run_gpg_with_lock_recovery(["gpg", "--decrypt"], stdin=None)
    assert result.returncode == 0
    assert result.stdout == b"plaintext"
    assert call_count == 2  # original failure + one retry


def test_retry_runs_exactly_once_no_infinite_loop(
    fake_gnupg: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the lock persists after recovery, we propagate the failure.

    This guards against a regression into retry-until-success, which
    would hang the CLI indefinitely against a real live local lock.
    """
    call_count = 0

    def fake_run(
        args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if args and args[0] == "gpgconf":
            return _fake_completed(0)
        nonlocal call_count
        call_count += 1
        return _fake_completed(
            2, stderr=b"gpg: keydb_search failed: Connection timed out\n"
        )

    monkeypatch.setattr("cavern.crypto.subprocess.run", fake_run)
    monkeypatch.setattr("cavern.crypto.shutil.which", lambda _: "/usr/bin/gpgconf")

    result = _run_gpg_with_lock_recovery(["gpg", "--decrypt"], stdin=None)
    assert result.returncode == 2
    assert call_count == 2  # exactly one retry, then propagate


def test_retry_logs_when_locks_are_cleaned(
    fake_gnupg: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Recovery prints to stderr when it actually cleared a lock.

    Without this message, an unexpected pause and slowdown would
    have no visible cause. The message names the cleared path(s) so
    a follow-up investigation has somewhere to start.
    """
    (fake_gnupg / "pubring.kbx.lock").write_text("1186029 host-a.example.com\n")

    calls = {"n": 0}

    def fake_run(
        args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if args and args[0] == "gpgconf":
            return _fake_completed(0)
        calls["n"] += 1
        if calls["n"] == 1:
            return _fake_completed(
                2, stderr=b"gpg: keydb_search failed: Connection timed out\n"
            )
        return _fake_completed(0, stdout=b"plaintext")

    monkeypatch.setattr("cavern.crypto.subprocess.run", fake_run)
    monkeypatch.setattr("cavern.crypto.shutil.which", lambda _: "/usr/bin/gpgconf")

    _run_gpg_with_lock_recovery(["gpg", "--decrypt"], stdin=None)
    captured = capsys.readouterr()
    assert "cleared 1 stale GPG keyring lock" in captured.err
    assert "from a prior session" in captured.err


def test_retry_no_log_when_lock_cleanup_finds_nothing(
    fake_gnupg: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """If the contention is real (live local lock) we don't claim to
    have cleaned anything we didn't actually clean.
    """
    # Live lock owned by current process -- recovery must leave it.
    (fake_gnupg / "pubring.kbx.lock").write_text(f"{os.getpid()} {_THIS_HOST}\n")

    def fake_run(
        args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if args and args[0] == "gpgconf":
            return _fake_completed(0)
        return _fake_completed(
            2, stderr=b"gpg: keydb_search failed: Connection timed out\n"
        )

    monkeypatch.setattr("cavern.crypto.subprocess.run", fake_run)
    monkeypatch.setattr("cavern.crypto.shutil.which", lambda _: "/usr/bin/gpgconf")

    _run_gpg_with_lock_recovery(["gpg", "--decrypt"], stdin=None)
    captured = capsys.readouterr()
    assert "cleared" not in captured.err
