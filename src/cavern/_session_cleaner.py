"""Detached cleaner invoked by :mod:`cavern.session`.

Run as ``python -m cavern._session_cleaner <path> <ttl_seconds> <token_hex>``.

After sleeping for ``ttl_seconds``, the cleaner reads the session
file's embedded token and unlinks the file *only if* the token
matches the one this cleaner was launched with. This is the
defense against the double-unlock race: an earlier cleaner cannot
delete a session file written by a later ``unlock`` call.

If the file is gone, the magic doesn't match, or the embedded token
doesn't match ours, the cleaner exits without touching the disk.
"""

from __future__ import annotations

import contextlib
import os
import sys
import time

# We keep the format constants in lockstep with session.py.
_MAGIC = b"CSES"
_TOKEN_LENGTH = 16
_HEADER_LENGTH = len(_MAGIC) + 1 + _TOKEN_LENGTH


def main() -> int:
    if len(sys.argv) != 4:
        return 2
    path = sys.argv[1]
    try:
        ttl = float(sys.argv[2])
    except ValueError:
        return 2
    try:
        expected_token = bytes.fromhex(sys.argv[3])
    except ValueError:
        return 2
    if len(expected_token) != _TOKEN_LENGTH:
        return 2

    time.sleep(ttl)

    try:
        with open(path, "rb") as fh:
            data = fh.read(_HEADER_LENGTH)
    except FileNotFoundError:
        return 0  # already gone, nothing to do
    except OSError:
        return 1

    if len(data) < _HEADER_LENGTH or data[: len(_MAGIC)] != _MAGIC:
        # Not our format — leave it alone.
        return 0

    on_disk_token = data[len(_MAGIC) + 1 : _HEADER_LENGTH]
    if on_disk_token != expected_token:
        # A later unlock has replaced the file; that session has its
        # own cleaner. We must NOT delete it.
        return 0

    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
