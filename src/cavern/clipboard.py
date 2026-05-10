"""Clipboard helpers with auto-clear.

This module wraps the platform's native clipboard binaries directly
rather than depending on ``pyperclip``. The supported backends are:

- **Linux (Wayland):** ``wl-copy`` / ``wl-paste``
- **Linux (X11):** ``xclip -selection clipboard`` / ``xclip -o -selection clipboard``
- **Linux (X11 alt):** ``xsel --clipboard --input`` / ``--output``
- **macOS:** ``pbcopy`` / ``pbpaste``

The first available backend wins, with Wayland preferred over X11 on
Linux because Wayland sessions usually have ``$WAYLAND_DISPLAY`` set
even if ``$DISPLAY`` is also defined for backwards compat.

Auto-clear
----------

``copy_with_autoclear`` copies the secret, then spawns a detached
child process that, after a delay, overwrites the clipboard *only if
its contents have not changed*. If the user copies something else in
the meantime, that copy is left alone.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .exceptions import ClipboardError

DEFAULT_CLEAR_AFTER = 45.0


@dataclass(frozen=True)
class _Backend:
    """One platform's pair of (copy, paste) commands.

    Each is an argv list ready for ``subprocess``. Copy reads stdin;
    paste writes to stdout.
    """

    name: str
    copy_argv: list[str]
    paste_argv: list[str]


def _detect_backend() -> _Backend:
    """Pick the best available clipboard backend, or raise."""
    candidates: list[_Backend] = []

    if sys.platform == "darwin":
        candidates.append(
            _Backend(name="pbcopy", copy_argv=["pbcopy"], paste_argv=["pbpaste"])
        )
    else:
        # Wayland first when WAYLAND_DISPLAY is set.
        if os.environ.get("WAYLAND_DISPLAY"):
            candidates.append(
                _Backend(
                    name="wl-copy",
                    copy_argv=["wl-copy"],
                    paste_argv=["wl-paste", "--no-newline"],
                )
            )
        candidates.append(
            _Backend(
                name="xclip",
                copy_argv=["xclip", "-selection", "clipboard"],
                paste_argv=["xclip", "-selection", "clipboard", "-o"],
            )
        )
        candidates.append(
            _Backend(
                name="xsel",
                copy_argv=["xsel", "--clipboard", "--input"],
                paste_argv=["xsel", "--clipboard", "--output"],
            )
        )
        # Fallback: wl-clipboard might be installed even without
        # WAYLAND_DISPLAY (e.g., XWayland sessions).
        candidates.append(
            _Backend(
                name="wl-copy",
                copy_argv=["wl-copy"],
                paste_argv=["wl-paste", "--no-newline"],
            )
        )

    for backend in candidates:
        if shutil.which(backend.copy_argv[0]):
            return backend

    raise ClipboardError(
        "No clipboard backend found. On Linux, install one of: "
        "wl-clipboard, xclip, xsel."
    )


def copy_to_clipboard(text: str) -> None:
    """Place ``text`` on the system clipboard via a native binary.

    Raises :class:`ClipboardError` on any failure.
    """
    backend = _detect_backend()
    try:
        proc = subprocess.run(
            backend.copy_argv,
            input=text.encode("utf-8"),
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise ClipboardError(f"clipboard copy failed: {exc}") from exc
    if proc.returncode != 0:
        raise ClipboardError(
            f"{backend.name} exited {proc.returncode}: "
            f"{proc.stderr.decode(errors='replace').strip()}"
        )


def read_clipboard() -> str:
    """Read the current clipboard contents.

    Used by the auto-clear cleaner to verify the secret is still
    there before wiping it. Returns an empty string on any error;
    the cleaner treats unreadable as "force clear" because refusing
    to clear is the riskier failure mode for a credential tool.
    """
    try:
        backend = _detect_backend()
    except ClipboardError:
        return ""
    try:
        proc = subprocess.run(backend.paste_argv, capture_output=True, check=False)
    except OSError:
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.decode("utf-8", errors="replace")


def copy_with_autoclear(text: str, clear_after: float = DEFAULT_CLEAR_AFTER) -> int:
    """Copy ``text`` and schedule a clipboard wipe after ``clear_after`` seconds.

    A detached subprocess runs the wipe so the parent CLI exits
    immediately. The subprocess only clears the clipboard if its
    current contents still equal ``text`` — so unrelated copies the
    user makes in the meantime are not clobbered.

    Returns the PID of the detached cleaner (useful in tests).
    """
    copy_to_clipboard(text)

    cleaner_script = Path(__file__).parent / "_clipboard_cleaner.py"
    args = [sys.executable, str(cleaner_script), str(clear_after)]
    env = {**os.environ, "CAVERN_CLIPBOARD_TEXT": text}

    process = subprocess.Popen(
        args,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    return process.pid
