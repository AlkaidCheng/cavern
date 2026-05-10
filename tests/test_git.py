"""Tests for ``cavern.git``.

These exercise the git wrappers without requiring network access:
local repo init, commit, status, and the gitattributes/gitignore
files we write at init time.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from cavern import git as cavern_git
from cavern.exceptions import GitError


@pytest.fixture(autouse=True)
def _git_identity(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Provide a git identity that's local to the test, never global."""
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Cavern Test")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "test@cavern.local")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Cavern Test")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "test@cavern.local")
    # Isolate git config — never read the developer's ~/.gitconfig.
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "no-such-config"))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(tmp_path / "no-such-config"))


def _git_available() -> bool:
    return shutil.which("git") is not None


pytestmark = pytest.mark.skipif(not _git_available(), reason="git binary not on PATH")


# ---- init -----------------------------------------------------------------


def test_init_creates_repo(tmp_path: Path) -> None:
    cavern_git.init(tmp_path)
    assert cavern_git.is_repo(tmp_path)


def test_init_writes_gitattributes_marking_files_binary(tmp_path: Path) -> None:
    cavern_git.init(tmp_path)
    attrs = (tmp_path / ".gitattributes").read_text(encoding="utf-8")
    assert "binary" in attrs


def test_init_writes_gitignore_for_local_state(tmp_path: Path) -> None:
    """Local-only state (.lock, .tmp.*) must not be committed."""
    cavern_git.init(tmp_path)
    ignore = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert ".lock" in ignore
    assert ".tmp.*" in ignore


def test_init_is_idempotent(tmp_path: Path) -> None:
    cavern_git.init(tmp_path)
    # Capture the existing .gitignore so we can confirm it's not clobbered.
    original = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    (tmp_path / ".gitignore").write_text(original + "# user-edited\n")

    cavern_git.init(tmp_path)  # second call must not overwrite
    assert "# user-edited" in (tmp_path / ".gitignore").read_text(encoding="utf-8")


# ---- commit_all -----------------------------------------------------------


def test_commit_all_no_op_outside_repo(tmp_path: Path) -> None:
    """Calling commit_all on a non-repo directory is a no-op, not an error."""
    cavern_git.commit_all(tmp_path, "irrelevant")  # no exception


def test_lock_file_is_not_tracked(tmp_path: Path) -> None:
    """The advisory lock file must not appear in commits.

    Reproduces the concern that git auto-commit would otherwise pick
    up the .lock file (which is local process-coordination state).
    """
    cavern_git.init(tmp_path)
    (tmp_path / ".lock").write_bytes(b"")
    (tmp_path / "real-secret").write_bytes(b"some-encrypted-bytes")

    cavern_git.commit_all(tmp_path, "Initial")

    listing = subprocess.run(
        ["git", "ls-files"], cwd=tmp_path, capture_output=True, check=True
    ).stdout.decode()
    assert ".lock" not in listing
    assert "real-secret" in listing


def test_commit_all_no_op_when_no_changes(tmp_path: Path) -> None:
    cavern_git.init(tmp_path)
    cavern_git.commit_all(tmp_path, "first")
    # Second call with no changes should not raise even though `git commit`
    # would normally exit non-zero on an empty commit.
    cavern_git.commit_all(tmp_path, "second")


def test_commit_all_after_real_change(tmp_path: Path) -> None:
    cavern_git.init(tmp_path)
    (tmp_path / "secret").write_bytes(b"data")
    cavern_git.commit_all(tmp_path, "Add secret")

    log = subprocess.run(
        ["git", "log", "--oneline"], cwd=tmp_path, capture_output=True, check=True
    ).stdout.decode()
    assert "Add secret" in log


# ---- error path ----------------------------------------------------------


def test_git_missing_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """If git is unavailable, _ensure_git_available raises GitError."""
    monkeypatch.setattr(cavern_git.shutil, "which", lambda _: None)
    with pytest.raises(GitError):
        cavern_git.init(tmp_path)
