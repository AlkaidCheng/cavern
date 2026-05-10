"""Allow ``python -m cavern`` to invoke the CLI."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
