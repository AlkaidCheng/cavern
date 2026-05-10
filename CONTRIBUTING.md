# Contributing to cavern

Thanks for your interest in working on cavern! This document covers
the development setup, the quality gates, and what we look for in
patches.

## Development setup

```bash
git clone https://github.com/OWNER/cavern
cd cavern
pip install -e ".[dev]"
```

The `[dev]` extra pulls in pytest, pytest-cov, black, ruff, mypy,
and pyotp (so the full test suite — including TOTP tests — runs).

## Quality gates

Every PR must pass:

```bash
black --check src tests        # formatting
ruff check src tests           # lint
mypy src                       # strict type checking
pytest                         # 193 tests, ~2 seconds
```

CI runs these on every push and PR; see `.github/workflows/ci.yml`.
The matrix is `{ubuntu, macos} × {3.10, 3.11, 3.12, 3.13}`. Windows
is excluded because cavern's `__init__.py` raises `ImportError`
there — POSIX-only is intentional, not provisional.

## Code style

We follow PEP 8 with Black's defaults (88-char lines), strict mypy,
ruff with a focused selection of rules (`E,F,W,I,N,B,UP,S,RET,SIM`),
and NumPy-style docstrings on public functions.

Other conventions:

- New public functions need type hints on every parameter and the
  return.
- Validate inputs at the boundary (public functions); private
  helpers trust their callers.
- Catch specific exceptions, not bare `Exception`. The crypto layer
  in particular catches `cryptography.exceptions.InvalidTag`
  specifically rather than swallowing the world.
- Use `pathlib.Path`, not string path manipulation.
- Use `secrets` and `os.urandom` for randomness — never `random`.

## Tests

The test suite is structured one file per module:

```
tests/
    test_audit.py        # audit log: ordering, cap, corrupt-line tolerance
    test_cli.py          # argparse plumbing, command handlers
    test_crypto.py       # round-trip, tamper detection, validation
    test_generator.py    # PasswordPolicy, character classes, randomness
    test_git.py          # init, commit, .gitignore behavior
    test_session.py      # symlink defenses, TOCTOU, mlock contract
    test_totp.py         # URI scanning, lazy import, error paths
    test_vault.py        # CRUD, manifest, drift, rotation, concurrency
    test_version.py      # __version__ wiring, --version flag
```

When adding a feature, prefer a focused file-per-concern. When fixing
a bug, add a regression test that fails before your fix and passes
after.

## Architecture and security

Before making non-trivial changes to crypto, the file format, or the
session cache, read:

- [`docs/SECURITY.md`](./docs/SECURITY.md) — threat model and design
- [`docs/KNOWN_ISSUES.md`](./docs/KNOWN_ISSUES.md) — known caveats

Changes to the on-disk format require bumping `FILE_VERSION` in
`crypto.py` and adding migration handling — old vaults must remain
readable.

## Releasing

Releases are automated via `.github/workflows/release.yml`. To cut a
release:

1. Update `version` in `pyproject.toml` (single source of truth —
   `cavern.__version__` reads it via `importlib.metadata`).
2. Tag the commit and create a GitHub Release.
3. The workflow re-runs the test suite, builds an sdist + universal
   wheel, and publishes to PyPI via Trusted Publishing.

PyPI Trusted Publishing setup is documented in the comments of
`release.yml` (one-time configuration on PyPI's side).

## Reporting security issues

If you find a security issue, please report it privately rather than
opening a public GitHub issue. See [`docs/SECURITY.md`](./docs/SECURITY.md)
for the threat model so we can quickly tell which gaps are intentional
boundaries vs. real bugs.
