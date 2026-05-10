"""TOTP code generation from secrets containing ``otpauth://`` URIs.

TOTP support is **optional**. The :mod:`pyotp` library is not a
required dependency; install it via the ``totp`` extra:

.. code-block:: bash

    pip install cavern[totp]

Importing this module without ``pyotp`` installed succeeds — the
import of ``pyotp`` itself is deferred until you actually call
:func:`current_totp`. At that point, if the library is missing, a
:class:`CavernError` is raised with a clear install hint instead of
a confusing ``ModuleNotFoundError``.

The ``pyotp`` parser respects the ``digits`` parameter in the URI
(typically 6, occasionally 8) and the ``period`` parameter (typically
30 seconds), so the returned code length and refresh interval match
the issuer's configuration.
"""

from __future__ import annotations

from types import ModuleType

from .exceptions import CavernError


def _load_pyotp() -> ModuleType:
    """Import ``pyotp`` on demand, with a helpful error if missing.

    Keeping the import inside this helper rather than at module level
    means that ``cavern.totp`` can be imported (and the rest of the
    package loaded) without ``pyotp`` installed. Only callers of the
    TOTP functions pay the install requirement.
    """
    try:
        import pyotp
    except ImportError as exc:
        raise CavernError(
            "TOTP support requires the 'totp' extra. "
            "Install it with: pip install cavern[totp]"
        ) from exc
    return pyotp


def find_otpauth_uri(plaintext: bytes) -> str:
    """Return the first ``otpauth://`` URI in ``plaintext``.

    Decodes strictly as UTF-8: a binary secret can't accidentally be
    interpreted as containing a URI just because some byte sequence
    decodes to one under ``errors="replace"``.

    Does not require ``pyotp`` — pure string scanning.

    Raises :class:`CavernError` if the plaintext is not valid UTF-8
    or contains no ``otpauth://`` line.
    """
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CavernError(
            f"Secret is not valid UTF-8; cannot scan for otpauth URI: {exc}"
        ) from exc

    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("otpauth://"):
            return line
    raise CavernError(
        "No otpauth:// URI found in this secret. "
        "Add a line like `otpauth://totp/Site:user?secret=...&issuer=Site`."
    )


def current_totp(plaintext: bytes) -> str:
    """Return the current TOTP code for the secret's URI.

    Requires the optional ``totp`` extra (i.e., ``pyotp``).

    The code is whatever digit-count the URI specifies — typically 6,
    sometimes 8 — so callers should not assume a fixed length. Any
    leading-zero padding from ``pyotp.TOTP.now`` is preserved.

    Raises :class:`CavernError` if ``pyotp`` is not installed, the
    plaintext contains no ``otpauth://`` URI, the URI is malformed,
    or the URI is for a non-time-based scheme (e.g. HOTP).
    """
    pyotp = _load_pyotp()
    uri = find_otpauth_uri(plaintext)
    try:
        otp = pyotp.parse_uri(uri)
    except ValueError as exc:
        raise CavernError(f"Invalid otpauth URI: {exc}") from exc
    if not isinstance(otp, pyotp.TOTP):
        raise CavernError("Only TOTP (time-based) URIs are supported.")
    return str(otp.now())
