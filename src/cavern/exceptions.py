"""Exception hierarchy for cavern.

All cavern-internal errors derive from :class:`CavernError` so the CLI
can catch a single base class, render a clean one-line message, and
exit with a non-zero status without surfacing a traceback.
"""


class CavernError(Exception):
    """Base class for all cavern errors."""


class CryptoError(CavernError):
    """Raised when an encryption, decryption, or KDF operation fails.

    Includes GPG subprocess failures and authenticated-encryption tag
    verification failures (which indicate either corruption or
    tampering and are treated identically).
    """


class StoreError(CavernError):
    """Raised for store layout, path, or filesystem problems."""


class GitError(CavernError):
    """Raised when a git operation against the store fails."""


class ClipboardError(CavernError):
    """Raised when no usable clipboard backend is available."""


class SessionError(CavernError):
    """Raised when the session cache is missing, expired, or unreadable."""


class ManifestError(CavernError):
    """Raised when the encrypted manifest is corrupt, drifted, or stale."""


class NotInitializedError(StoreError):
    """Raised when an operation requires an initialized vault but none exists."""


class SecretNotFoundError(StoreError):
    """Raised when a requested secret name does not exist in the vault."""


class SecretExistsError(StoreError):
    """Raised when inserting a secret that already exists without ``--force``."""
