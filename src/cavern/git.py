"""Git integration for the vault.

The vault directory is auto-committed on every mutation. Pushes are
manual via ``cavern git push``. We shell out to the system ``git``
binary directly — no GitPython dependency — so any modern git works.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .exceptions import GitError

GIT_BINARY = "git"


def is_repo(root: Path) -> bool:
    return (root / ".git").is_dir()


def _ensure_git_available() -> None:
    if shutil.which(GIT_BINARY) is None:
        raise GitError("git not found on PATH.")


def _run(
    args: list[str], cwd: Path, *, capture: bool = False
) -> subprocess.CompletedProcess[bytes]:
    _ensure_git_available()
    return subprocess.run(
        [GIT_BINARY, *args],
        cwd=str(cwd),
        capture_output=capture,
        check=False,
    )


def init(root: Path) -> None:
    """Initialize a git repository at the vault root. Idempotent."""
    if is_repo(root):
        return
    result = _run(["init", "--quiet"], cwd=root, capture=True)
    if result.returncode != 0:
        raise GitError(f"git init failed: {result.stderr.decode(errors='replace')}")

    # All cavern files are binary-friendly (encrypted blobs); mark them
    # binary so git doesn't try to diff them.
    gitattributes = root / ".gitattributes"
    if not gitattributes.exists():
        gitattributes.write_text("* binary\n", encoding="utf-8")

    # Local-only state that must not be committed:
    #   .lock           — flock file used to serialize CLI processes
    #   .tmp.*          — temp files from interrupted atomic writes
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text(".lock\n.tmp.*\n", encoding="utf-8")


def commit_all(root: Path, message: str) -> None:
    """Stage everything and commit. No-op if there are no changes."""
    if not is_repo(root):
        return
    add = _run(["add", "--all"], cwd=root, capture=True)
    if add.returncode != 0:
        raise GitError(f"git add failed: {add.stderr.decode(errors='replace')}")
    status = _run(["status", "--porcelain"], cwd=root, capture=True)
    if not status.stdout.strip():
        return
    commit = _run(["commit", "--quiet", "-m", message], cwd=root, capture=True)
    if commit.returncode != 0:
        raise GitError(f"git commit failed: {commit.stderr.decode(errors='replace')}")


def passthrough(root: Path, args: list[str]) -> int:
    """Run an arbitrary ``git`` command with ``cwd=root``."""
    result = _run(args, cwd=root, capture=False)
    return result.returncode
