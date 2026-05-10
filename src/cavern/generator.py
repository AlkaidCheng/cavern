"""Password generator.

Uses :mod:`secrets` for cryptographically strong randomness — never
:mod:`random`. The character pool is built from the requested classes,
optionally with ambiguous characters removed, and the generator
guarantees that at least one character from each enabled class appears
in the output (so a policy of "must include digits" is actually
honored, even with low probability of self-correcting otherwise).
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

from .exceptions import CavernError

# Visually ambiguous characters routinely cause copy/paste errors
# from printed passwords or screenshots; strip them when asked.
AMBIGUOUS_CHARS = frozenset("0O1lI|`'\"")


@dataclass(frozen=True)
class PasswordPolicy:
    """Configuration for password generation.

    Attributes
    ----------
    length : int
        Total password length. Must be at least the number of enabled
        character classes.
    use_lowercase : bool
        Include ``a-z``.
    use_uppercase : bool
        Include ``A-Z``.
    use_digits : bool
        Include ``0-9``.
    use_symbols : bool
        Include punctuation.
    exclude_ambiguous : bool
        Strip visually ambiguous characters (``0O1lI|`` etc.).
    """

    length: int = 24
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False


def _pool_for(policy: PasswordPolicy) -> tuple[list[str], str]:
    """Return ``(class_pools, full_pool)`` for the given policy.

    ``class_pools`` is a list-of-strings, one per enabled class, used to
    seed the "at least one of each" guarantee. ``full_pool`` is the
    concatenation, used to fill the remaining length.
    """
    classes: list[str] = []
    if policy.use_lowercase:
        classes.append(string.ascii_lowercase)
    if policy.use_uppercase:
        classes.append(string.ascii_uppercase)
    if policy.use_digits:
        classes.append(string.digits)
    if policy.use_symbols:
        classes.append(string.punctuation)

    if policy.exclude_ambiguous:
        classes = [
            "".join(ch for ch in pool if ch not in AMBIGUOUS_CHARS) for pool in classes
        ]
        classes = [pool for pool in classes if pool]

    return classes, "".join(classes)


def generate_password(policy: PasswordPolicy | None = None) -> str:
    """Generate a password matching ``policy``.

    Parameters
    ----------
    policy : PasswordPolicy or None, optional
        Generation rules. Defaults to a 24-character password using
        all four character classes.

    Returns
    -------
    str
        A freshly generated password.

    Raises
    ------
    CavernError
        If the policy disables every character class, ``length`` is
        less than 1, or ``length`` is shorter than the number of
        enabled classes.
    """
    policy = policy or PasswordPolicy()
    if policy.length < 1:
        raise CavernError(f"Password length must be at least 1, got {policy.length}.")

    class_pools, full_pool = _pool_for(policy)

    if not full_pool:
        raise CavernError("Password policy enables no character classes.")
    if policy.length < len(class_pools):
        raise CavernError(
            f"Length {policy.length} is too short for "
            f"{len(class_pools)} required character classes."
        )

    # Guarantee at least one character from each enabled class…
    chars = [secrets.choice(pool) for pool in class_pools]
    # …then fill the remainder from the full pool.
    chars.extend(secrets.choice(full_pool) for _ in range(policy.length - len(chars)))

    # Cryptographic shuffle so the guaranteed chars aren't always at the front.
    # secrets.SystemRandom uses os.urandom — same source as secrets.choice.
    rng = secrets.SystemRandom()
    rng.shuffle(chars)
    return "".join(chars)
