"""Tests for the cryptographic core.

These are the most important tests in the package. If any of these
fail, secrets are at risk.
"""

from __future__ import annotations

import os

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
    _pad,
    _unpad,
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
        os.urandom(20_000),
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
