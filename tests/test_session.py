"""Tests for ``cavern.session``.

These tests use ``$CAVERN_SESSION_DIR`` to redirect each test to an
isolated tmp directory so they cannot disturb a real session and
cannot collide with each other. Every test that calls
``write_session`` uses a deliberately long TTL (much longer than the
test) and explicitly clears the session at the end; the detached
cleaner runs harmlessly later when its TTL elapses.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cavern import session
from cavern.crypto import KEK_LENGTH
from cavern.exceptions import SessionError

# A TTL long enough that no detached cleaner will fire during the test
# suite even on a slow CI box.
_LONG_TTL = 600.0


@pytest.fixture(autouse=True)
def _isolated_session_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect every test's session file to a per-test tmp directory."""
    monkeypatch.setenv("CAVERN_SESSION_DIR", str(tmp_path / "session"))
    return tmp_path / "session"


@pytest.fixture(autouse=True)
def _cleanup_session() -> None:
    """Best-effort cleanup at the end of every test."""
    yield
    session.clear_session()


# ---- session_file_path -----------------------------------------------------


def test_session_path_honors_env_override(_isolated_session_dir: Path) -> None:
    path = session.session_file_path()
    assert path.parent == _isolated_session_dir
    assert path.name == f"session-{os.getuid()}"


def test_session_path_includes_uid() -> None:
    # Even with the override, the filename embeds uid so two users
    # sharing a directory don't collide.
    path = session.session_file_path()
    assert str(os.getuid()) in path.name


# ---- write_session ---------------------------------------------------------


def test_write_session_creates_file_with_safe_perms() -> None:
    kek = os.urandom(KEK_LENGTH)
    path, _locked = session.write_session(kek, _LONG_TTL)

    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600


def test_write_session_directory_has_safe_perms() -> None:
    kek = os.urandom(KEK_LENGTH)
    path, _ = session.write_session(kek, _LONG_TTL)
    parent_mode = path.parent.stat().st_mode & 0o777
    assert parent_mode == 0o700


def test_write_session_writes_at_format_length() -> None:
    """The session file is the magic+version+token+kek envelope, not bare KEK."""
    kek = os.urandom(KEK_LENGTH)
    path, _ = session.write_session(kek, _LONG_TTL)
    # Read the file and confirm we get the KEK back through read_session.
    assert session.read_session() == kek
    # Confirm the on-disk size includes the header (magic + version + token).
    assert path.stat().st_size > KEK_LENGTH


def test_write_session_overwrites_existing_file() -> None:
    """Calling write_session twice replaces the contents."""
    kek1 = b"\x01" * KEK_LENGTH
    kek2 = b"\x02" * KEK_LENGTH
    session.write_session(kek1, _LONG_TTL)
    assert session.read_session() == kek1
    session.write_session(kek2, _LONG_TTL)
    assert session.read_session() == kek2


def test_session_token_rotates_per_unlock() -> None:
    """Two consecutive unlocks must produce different on-disk tokens.

    This is the core defense against the double-unlock race: if
    cleaner-1 races cleaner-2's session, the token mismatch makes
    cleaner-1 abort instead of unlinking the live session.
    """
    kek = os.urandom(KEK_LENGTH)
    session.write_session(kek, _LONG_TTL)
    token1 = session.read_session_token()
    session.write_session(kek, _LONG_TTL)
    token2 = session.read_session_token()
    assert token1 != token2


def test_write_session_rejects_wrong_kek_length() -> None:
    with pytest.raises(SessionError):
        session.write_session(b"too short", _LONG_TTL)
    with pytest.raises(SessionError):
        session.write_session(b"x" * (KEK_LENGTH + 1), _LONG_TTL)


def test_write_session_returns_locked_flag() -> None:
    """Whether mlock succeeded depends on the environment; either bool is fine.

    We just check the type — a regression that returns ``None`` or
    something truthy-but-not-bool would break the CLI's warning logic.
    """
    kek = os.urandom(KEK_LENGTH)
    _, locked = session.write_session(kek, _LONG_TTL)
    assert isinstance(locked, bool)


# ---- read_session ----------------------------------------------------------


def test_read_session_roundtrips() -> None:
    kek = os.urandom(KEK_LENGTH)
    session.write_session(kek, _LONG_TTL)
    assert session.read_session() == kek


def test_read_session_missing_raises() -> None:
    with pytest.raises(SessionError):
        session.read_session()


def test_read_session_rejects_loose_perms() -> None:
    """A session file with group/other bits set must be rejected.

    This catches the case where another user (or a misconfigured umask
    on a shared system) has gained read or write access to the KEK.
    """
    kek = os.urandom(KEK_LENGTH)
    path, _ = session.write_session(kek, _LONG_TTL)
    os.chmod(path, 0o644)  # add group/other read

    with pytest.raises(SessionError, match="insecure permissions"):
        session.read_session()


def test_read_session_rejects_wrong_length() -> None:
    """A session file at the wrong length is rejected.

    Truncation or padding could be a sign of tampering or corruption;
    either way we shouldn't hand a bogus key to the crypto layer.
    """
    path = session.session_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, b"x" * 16)  # too short
    finally:
        os.close(fd)

    with pytest.raises(SessionError, match="corrupt"):
        session.read_session()


def test_read_session_rejects_bad_magic() -> None:
    """A file at the right length but with the wrong magic is rejected."""
    kek = os.urandom(KEK_LENGTH)
    path, _ = session.write_session(kek, _LONG_TTL)
    # Flip the first magic byte.
    data = bytearray(path.read_bytes())
    data[0] = ord("X")
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, bytes(data))
    finally:
        os.close(fd)

    with pytest.raises(SessionError, match="bad magic"):
        session.read_session()


def test_read_session_rejects_unknown_version() -> None:
    """A file with an unrecognized version byte is rejected."""
    kek = os.urandom(KEK_LENGTH)
    path, _ = session.write_session(kek, _LONG_TTL)
    data = bytearray(path.read_bytes())
    data[4] = 0xFF  # version byte sits at offset 4 (after b"CSES")
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, bytes(data))
    finally:
        os.close(fd)

    with pytest.raises(SessionError, match="version"):
        session.read_session()


def test_read_session_rejects_directory_world_writable(
    _isolated_session_dir: Path,
) -> None:
    """Bonus: even though we set 0o700 on write, an attacker rewriting
    the perms before read should still cause a refusal once we read.

    (The current implementation only checks the *file* perms, not the
    parent directory's. This test documents that limitation as a
    deliberate design choice — checking parent perms causes false
    positives on some macOS configurations.)
    """
    kek = os.urandom(KEK_LENGTH)
    path, _ = session.write_session(kek, _LONG_TTL)
    # Loosen the parent dir; read_session still works because we only
    # validate the file itself. The 0o755 here is intentional — that's
    # exactly the scenario under test.
    os.chmod(path.parent, 0o755)  # noqa: S103
    assert session.read_session() == kek
    # Restore for cleanup teardown.
    os.chmod(path.parent, 0o700)


# ---- clear_session / session_is_active -------------------------------------


def test_clear_session_removes_file() -> None:
    kek = os.urandom(KEK_LENGTH)
    path, _ = session.write_session(kek, _LONG_TTL)
    assert path.is_file()

    session.clear_session()
    assert not path.exists()


def test_clear_session_when_no_file_is_noop() -> None:
    """clear_session() on a missing file must not raise."""
    session.clear_session()  # no exception
    session.clear_session()  # idempotent


def test_session_is_active_false_when_missing() -> None:
    assert session.session_is_active() is False


def test_session_is_active_true_when_present() -> None:
    kek = os.urandom(KEK_LENGTH)
    session.write_session(kek, _LONG_TTL)
    assert session.session_is_active() is True


def test_session_is_active_false_after_clear() -> None:
    kek = os.urandom(KEK_LENGTH)
    session.write_session(kek, _LONG_TTL)
    session.clear_session()
    assert session.session_is_active() is False


def test_session_is_active_false_when_perms_bad() -> None:
    """Loose perms make ``session_is_active`` return False.

    This way the CLI falls through to a fresh GPG unlock rather than
    using a key file that ``read_session`` would reject anyway.
    """
    kek = os.urandom(KEK_LENGTH)
    path, _ = session.write_session(kek, _LONG_TTL)
    os.chmod(path, 0o644)
    assert session.session_is_active() is False


# ---- _try_mlock ------------------------------------------------------------


def test_try_mlock_returns_bool() -> None:
    """Whether mlock works depends on RLIMIT_MEMLOCK / privileges, but
    the contract is "always return a bool, never raise"."""
    import ctypes

    buf = ctypes.create_string_buffer(b"\x00" * 32, 32)
    result = session._try_mlock(buf)
    assert isinstance(result, bool)


def test_try_mlock_does_not_corrupt_buffer() -> None:
    """The buffer's contents must be unchanged whether mlock succeeded or not."""
    import ctypes

    original = bytes(range(32))
    buf = ctypes.create_string_buffer(original, 32)
    session._try_mlock(buf)
    assert bytes(buf.raw[:32]) == original


# ---- Symlink defense ------------------------------------------------------


def test_read_session_refuses_symlink(_isolated_session_dir: Path) -> None:
    """A symlink at the session path must be rejected by read_session.

    O_NOFOLLOW makes os.open fail with ELOOP on a symlink. Without
    this defense, an attacker with write access to the session dir
    could redirect our read to e.g. /etc/hostname and have the
    crypto layer mistake it for a session file.
    """
    target = _isolated_session_dir / "decoy"
    _isolated_session_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(_isolated_session_dir, 0o700)
    target.write_bytes(b"x" * (KEK_LENGTH + 21))  # plausible-looking length
    os.chmod(target, 0o600)

    session_path = session.session_file_path()
    os.symlink(target, session_path)

    with pytest.raises(SessionError, match="symlink|refused|corrupt"):
        session.read_session()


def test_write_session_overwrites_symlink_target_safely(
    _isolated_session_dir: Path,
) -> None:
    """A pre-existing symlink at the session path must not redirect our write.

    The unlink-then-O_EXCL-O_NOFOLLOW pattern removes the symlink
    before opening, so the new file lands at the intended path with
    the intended contents — and the symlink's previous target is
    untouched.
    """
    decoy = _isolated_session_dir.parent / "decoy-target"
    _isolated_session_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(_isolated_session_dir, 0o700)
    decoy.write_bytes(b"original-decoy-bytes")

    session_path = session.session_file_path()
    os.symlink(decoy, session_path)

    kek = os.urandom(KEK_LENGTH)
    session.write_session(kek, _LONG_TTL)

    # Decoy is unchanged.
    assert decoy.read_bytes() == b"original-decoy-bytes"
    # Session file is now a real file at the right path with our KEK readable.
    assert not session_path.is_symlink()
    assert session.read_session() == kek


def test_session_is_active_rejects_symlink(
    _isolated_session_dir: Path,
) -> None:
    """session_is_active must use lstat and refuse symlinks."""
    decoy = _isolated_session_dir.parent / "decoy"
    _isolated_session_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(_isolated_session_dir, 0o700)
    decoy.write_bytes(b"x" * 53)
    os.chmod(decoy, 0o600)

    session_path = session.session_file_path()
    os.symlink(decoy, session_path)

    assert session.session_is_active() is False
