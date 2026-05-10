"""Cavern — a metadata-hiding credential vault."""

from __future__ import annotations

import sys
from importlib import metadata as _metadata

if sys.platform == "win32":
    raise ImportError(
        "cavern is POSIX-only. It depends on POSIX file permissions, "
        "uid-aware paths, mlock(2), and detached subprocess sessions, "
        "none of which have direct Windows equivalents."
    )

# Read the version from the installed package metadata so it always
# matches `pyproject.toml` instead of being a duplicated literal that
# drifts out of sync at release time. The fallback covers the rare
# case of a source checkout that hasn't been pip-installed.
try:
    __version__ = _metadata.version("cavern")
except _metadata.PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0+unknown"

from .exceptions import (
    CavernError,
    ClipboardError,
    CryptoError,
    GitError,
    ManifestError,
    NotInitializedError,
    SecretExistsError,
    SecretNotFoundError,
    SessionError,
    StoreError,
)
from .generator import PasswordPolicy, generate_password
from .vault import UnlockedKeys, Vault

__all__ = [
    "CavernError",
    "ClipboardError",
    "CryptoError",
    "GitError",
    "ManifestError",
    "NotInitializedError",
    "PasswordPolicy",
    "SecretExistsError",
    "SecretNotFoundError",
    "SessionError",
    "StoreError",
    "UnlockedKeys",
    "Vault",
    "__version__",
    "generate_password",
]
