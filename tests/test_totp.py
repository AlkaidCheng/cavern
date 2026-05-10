"""Tests for ``cavern.totp``.

Covers:
- The pure URI-scanning path that does NOT require pyotp.
- The lazy-import behavior so ``cavern.totp`` imports cleanly even
  when ``pyotp`` is unavailable.
- The helpful CavernError when a caller invokes a function that
  needs pyotp without pyotp installed.
- The full code-generation path when pyotp IS available.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from cavern.exceptions import CavernError
from cavern.totp import current_totp, find_otpauth_uri

# ---- Pure URI scanning (no pyotp needed) ---------------------------------


def test_find_otpauth_uri_extracts_first_match() -> None:
    plaintext = (
        b"my-password\n"
        b"otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example\n"
        b"some other note\n"
    )
    uri = find_otpauth_uri(plaintext)
    assert uri.startswith("otpauth://totp/Example")


def test_find_otpauth_uri_strips_surrounding_whitespace() -> None:
    plaintext = b"   otpauth://totp/Site:bob?secret=JBSWY3DPEHPK3PXP   \n"
    uri = find_otpauth_uri(plaintext)
    assert uri.startswith("otpauth://")
    assert not uri.endswith(" ")


def test_find_otpauth_uri_rejects_non_utf8() -> None:
    """Strict UTF-8 decode means binary garbage doesn't accidentally
    decode-as-replacement and produce a fake match."""
    with pytest.raises(CavernError, match="UTF-8"):
        find_otpauth_uri(b"\xff\xfe\xfd")


def test_find_otpauth_uri_raises_when_absent() -> None:
    with pytest.raises(CavernError, match="No otpauth"):
        find_otpauth_uri(b"just a regular password\n")


# ---- Lazy import behavior ------------------------------------------------


def test_totp_module_imports_without_pyotp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Importing ``cavern.totp`` must not require pyotp.

    We simulate pyotp being missing by injecting a finder that
    refuses to find it, then re-importing the totp module from
    scratch. The module should load cleanly; only the call to
    ``current_totp`` should raise.
    """
    # Drop pyotp from sys.modules and block re-imports.
    monkeypatch.delitem(sys.modules, "pyotp", raising=False)
    monkeypatch.delitem(sys.modules, "cavern.totp", raising=False)

    class _BlockPyotp:
        def find_module(
            self, fullname: str, path: object = None
        ) -> Any:  # pragma: no cover - trivial
            if fullname == "pyotp":
                return self
            return None

        def find_spec(
            self, fullname: str, path: object = None, target: object = None
        ) -> None:
            if fullname == "pyotp":
                raise ImportError("pyotp blocked by test")
            return

    blocker = _BlockPyotp()
    monkeypatch.setattr(sys, "meta_path", [blocker, *sys.meta_path])

    # The import itself must succeed.
    import cavern.totp as reloaded_totp  # noqa: F401  - importing is the test

    # And find_otpauth_uri must still work without pyotp.
    uri = reloaded_totp.find_otpauth_uri(
        b"otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP\n"
    )
    assert uri.startswith("otpauth://")


def test_current_totp_without_pyotp_raises_helpful_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When pyotp is missing, the error must point to the install fix."""
    from cavern import totp as totp_module

    def _fail() -> None:
        raise CavernError(
            "TOTP support requires the 'totp' extra. "
            "Install it with: pip install cavern[totp]"
        )

    monkeypatch.setattr(totp_module, "_load_pyotp", _fail)

    # Resolve current_totp through totp_module so the patch always
    # affects the same module object, regardless of any earlier test
    # that may have re-imported cavern.totp.
    with pytest.raises(CavernError, match=r"pip install cavern\[totp\]"):
        totp_module.current_totp(b"otpauth://totp/Example:u?secret=JBSWY3DPEHPK3PXP\n")


# ---- End-to-end with real pyotp -----------------------------------------


def test_current_totp_returns_a_code() -> None:
    """With pyotp available, current_totp produces a digit string."""
    pytest.importorskip("pyotp")
    plaintext = (
        b"password-on-line-one\n"
        b"otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example\n"
    )
    code = current_totp(plaintext)
    # Default URI has 6 digits but we don't enforce a fixed length —
    # only that we get a non-empty all-digit string back.
    assert code.isdigit()
    assert 6 <= len(code) <= 8


def test_current_totp_rejects_hotp_uri() -> None:
    """HOTP (counter-based) URIs are not supported."""
    pytest.importorskip("pyotp")
    plaintext = b"otpauth://hotp/Example:bob?secret=JBSWY3DPEHPK3PXP&counter=0\n"
    with pytest.raises(CavernError, match="time-based"):
        current_totp(plaintext)


def test_current_totp_rejects_malformed_uri() -> None:
    pytest.importorskip("pyotp")
    plaintext = b"otpauth://totp/Example:bob?nosecret=here\n"
    with pytest.raises(CavernError):
        current_totp(plaintext)
