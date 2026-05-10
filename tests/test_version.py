"""Tests for the package's version handling.

The ``__version__`` string is read at import time from the installed
package metadata (via ``importlib.metadata``) so it always matches
``pyproject.toml`` rather than being a duplicated literal that drifts
out of sync at release time.
"""

from __future__ import annotations

import re
import subprocess
import sys

import cavern


def test_version_attribute_is_set() -> None:
    assert isinstance(cavern.__version__, str)
    assert cavern.__version__  # non-empty


def test_version_is_pep440_or_fallback() -> None:
    """The version string is either a PEP 440 release version
    (digits with dots, optional pre/post/dev tags), or the explicit
    fallback used in source checkouts.

    The pattern is intentionally lenient — we accept things like
    ``0.1.0``, ``0.1.0a1``, ``0.1.0+local``, ``1.2.3.dev4``, plus
    the fallback ``0.0.0+unknown`` — but reject obviously broken
    values like an empty string, a path, or a literal ``None``.
    """
    pep440 = re.compile(
        r"^\d+(\.\d+)*"  # leading numeric release
        r"((a|b|rc)\d+)?"  # optional pre-release
        r"(\.post\d+)?"  # optional post-release
        r"(\.dev\d+)?"  # optional dev release
        r"(\+[A-Za-z0-9.]+)?$"  # optional local version
    )
    assert pep440.match(
        cavern.__version__
    ), f"Version {cavern.__version__!r} doesn't look like PEP 440."


def test_version_in_dunder_all() -> None:
    assert "__version__" in cavern.__all__


def test_cli_version_flag_prints_version() -> None:
    """`cavern --version` prints the same string accessible via the API.

    Uses ``python -m cavern`` rather than the entry-point script so
    the test works both in editable installs and after ``pip install``.
    """
    result = subprocess.run(
        [sys.executable, "-m", "cavern", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    output = (result.stdout + result.stderr).strip()
    assert cavern.__version__ in output
    assert output.startswith("cavern ")
