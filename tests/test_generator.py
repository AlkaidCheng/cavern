"""Tests for ``cavern.generator``."""

from __future__ import annotations

import string

import pytest

from cavern.exceptions import CavernError
from cavern.generator import (
    AMBIGUOUS_CHARS,
    PasswordPolicy,
    generate_password,
)

# ---- Defaults & length ---------------------------------------------------


def test_default_policy_yields_24_chars() -> None:
    assert len(generate_password()) == 24


@pytest.mark.parametrize("length", [4, 8, 16, 32, 128])
def test_length_is_honored(length: int) -> None:
    assert len(generate_password(PasswordPolicy(length=length))) == length


def test_length_must_be_positive() -> None:
    with pytest.raises(CavernError, match="at least 1"):
        generate_password(PasswordPolicy(length=0))
    with pytest.raises(CavernError, match="at least 1"):
        generate_password(PasswordPolicy(length=-5))


# ---- Class guarantees ----------------------------------------------------


def test_includes_at_least_one_of_each_enabled_class() -> None:
    """Every enabled class must contribute at least one character.

    We run several iterations to make accidental gaps statistically
    unlikely; the deterministic guarantee is asserted regardless.
    """
    for _ in range(20):
        password = generate_password(PasswordPolicy(length=8))
        assert any(ch in string.ascii_lowercase for ch in password)
        assert any(ch in string.ascii_uppercase for ch in password)
        assert any(ch in string.digits for ch in password)
        assert any(ch in string.punctuation for ch in password)


def test_no_symbols_excludes_punctuation() -> None:
    for _ in range(20):
        password = generate_password(PasswordPolicy(length=32, use_symbols=False))
        assert all(ch not in string.punctuation for ch in password)


def test_exclude_ambiguous_strips_ambiguous_chars() -> None:
    for _ in range(20):
        password = generate_password(PasswordPolicy(length=64, exclude_ambiguous=True))
        assert not (set(password) & AMBIGUOUS_CHARS)


# ---- Error paths ---------------------------------------------------------


def test_no_classes_raises() -> None:
    with pytest.raises(CavernError, match="character classes"):
        generate_password(
            PasswordPolicy(
                use_lowercase=False,
                use_uppercase=False,
                use_digits=False,
                use_symbols=False,
            )
        )


def test_length_too_short_for_required_classes_raises() -> None:
    """4 classes enabled, length 3 cannot guarantee one of each."""
    with pytest.raises(CavernError, match="too short"):
        generate_password(PasswordPolicy(length=3))


# ---- Randomness sanity ---------------------------------------------------


def test_consecutive_calls_differ() -> None:
    """Two calls must (with overwhelming probability) produce different output.

    A non-cryptographic RNG, or accidental seeding, would fail this
    test. ``secrets.SystemRandom`` is deterministic only on identical
    OS entropy, which is effectively never.
    """
    a = generate_password(PasswordPolicy(length=32))
    b = generate_password(PasswordPolicy(length=32))
    assert a != b
