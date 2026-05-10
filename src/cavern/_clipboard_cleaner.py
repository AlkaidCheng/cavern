"""Detached cleaner invoked by :mod:`cavern.clipboard`.

Run as ``python -m cavern._clipboard_cleaner <delay_seconds>``. The
secret is passed via the ``CAVERN_CLIPBOARD_TEXT`` environment
variable to keep it off ``argv`` (where it would be visible to other
local users via ``ps``).

After sleeping, the cleaner reads the current clipboard contents and
overwrites them only if they still match the secret. If the
clipboard cannot be read (e.g., the X server has gone away in the
meantime), the cleaner clears unconditionally — refusing to clear is
the riskier failure mode for a credential tool.
"""

from __future__ import annotations

import os
import sys
import time

from .clipboard import copy_to_clipboard, read_clipboard
from .exceptions import ClipboardError


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        delay = float(sys.argv[1])
    except ValueError:
        return 2

    secret = os.environ.get("CAVERN_CLIPBOARD_TEXT")
    if secret is None:
        return 2

    time.sleep(delay)

    current = read_clipboard()
    # If the user copied something else in the meantime, leave it alone.
    if current and current != secret:
        return 0

    try:
        copy_to_clipboard("")
    except ClipboardError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
