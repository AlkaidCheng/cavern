"""Session manager: cache the unwrapped KEK across CLI invocations.

After ``cavern unlock``, the KEK is written to a session file with
``0o600`` permissions. A detached cleaner process deletes the file
after the requested TTL — but only if the cleaner's session token
still matches what's on disk, so a later ``unlock`` is never wiped
out by an earlier cleaner.

File format
-----------

::

    [magic:    4 bytes  = b"CSES"]
    [version:  1 byte   = 0x01]
    [token:   16 bytes  random per-unlock session token]
    [kek:     32 bytes  the unwrapped KEK]

Total: 53 bytes. The token defends against the double-unlock race:
unlock-1 spawns cleaner-1 with token T1; unlock-2 overwrites the
file with token T2 and spawns cleaner-2 with T2. When cleaner-1
wakes up, it reads the on-disk token, finds T2 != T1, and exits
without unlinking. Cleaner-2 fires later and matches T2.

Platform paths
--------------

Honors ``$CAVERN_SESSION_DIR`` if set. Otherwise:

- **Linux:** ``/dev/shm/cavern/`` — tmpfs, in-RAM, never paged.
- **macOS / other POSIX:** ``~/.cache/cavern/`` — backed by the regular
  filesystem. **This is a meaningful security gap on macOS:** the
  kernel can page the session file to disk regardless of any
  in-process precautions, so the KEK can end up in macOS swap. If
  this matters to you, run cavern under FileVault and accept the
  paging risk, or pass ``--no-cache`` to skip session caching
  entirely.

Memory hygiene caveats
----------------------

The KEK is held in a ``bytearray`` (mutable) so we can ``mlock`` it
and zero it after use. But:

1. **Python's memory model leaks copies.** When the KEK is passed to
   other modules — encrypted into ``master.json``, used to derive
   subkeys — the runtime may produce additional copies in pageable
   memory we cannot reach. ``mlock`` only pins the buffer we hand it;
   it cannot pin the entire transitive graph of derivative objects.
2. **mlock is best-effort.** It depends on ``RLIMIT_MEMLOCK`` and on
   ``cryptography``'s internal allocations. We treat any failure as a
   warning, not an error, and we surface the result to the CLI so the
   user knows whether the locking succeeded.

The honest summary: we reduce the surface area of plaintext-on-disk
through swap, but cannot eliminate it from a Python process. For a
hardened deployment, run on top of full-disk encryption.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import os
import secrets
import stat as stat_module
import subprocess
import sys
from pathlib import Path

from .crypto import KEK_LENGTH
from .exceptions import SessionError

# ---- File format constants ------------------------------------------------

_MAGIC = b"CSES"
_VERSION = 0x01
_TOKEN_LENGTH = 16
_HEADER_LENGTH = len(_MAGIC) + 1 + _TOKEN_LENGTH  # 21 bytes
_FILE_LENGTH = _HEADER_LENGTH + KEK_LENGTH  # 53 bytes


# ---- Path resolution ------------------------------------------------------


def session_file_path() -> Path:
    """Return the platform-appropriate session file path.

    Honors ``$CAVERN_SESSION_DIR`` if set (used by tests, and by users
    who want to point the session at e.g. an encrypted ramdisk of
    their own choosing). Otherwise:

    - **Linux:** ``/dev/shm/cavern/`` — tmpfs, in-RAM.
    - **macOS / other POSIX:** ``~/.cache/cavern/`` — disk-backed; see
      the module docstring for the security caveat this implies.
    """
    override = os.environ.get("CAVERN_SESSION_DIR")
    if override:
        directory = Path(override)
    # /dev/shm is the correct location for an in-memory session key on
    # Linux: it's a tmpfs, and we restrict perms to 0o700 on the
    # directory and 0o600 on the file. S108 doesn't apply here.
    elif sys.platform.startswith("linux") and Path("/dev/shm").is_dir():  # noqa: S108
        directory = Path("/dev/shm/cavern")  # noqa: S108
    else:
        directory = Path.home() / ".cache" / "cavern"
    return directory / f"session-{os.getuid()}"


# ---- mlock & memory hygiene ----------------------------------------------


def _try_mlock(buffer: ctypes.Array[ctypes.c_char]) -> bool:
    """Best-effort mlock of a ctypes buffer.

    Takes a ctypes array (e.g., ``ctypes.create_string_buffer``)
    rather than a Python ``bytes`` so the address is well-defined.
    Returns True on success, False on any failure (privileges,
    ulimit, no libc, mlock unsupported). Failure is treated as a soft
    warning by the caller — the file is still written with 0o600 and
    the data is still on a tmpfs on Linux.

    Note: this only pins the bytes in *this specific buffer*. Python
    runtime copies of the same data are not affected. See the module
    docstring for the broader limitation.
    """
    libc_name = ctypes.util.find_library("c")
    if libc_name is None:
        return False
    try:
        libc = ctypes.CDLL(libc_name, use_errno=True)
    except OSError:
        return False

    rc: int = libc.mlock(
        ctypes.cast(buffer, ctypes.c_void_p),
        ctypes.c_size_t(len(buffer)),
    )
    return rc == 0


def _zero_buffer(buffer: ctypes.Array[ctypes.c_char]) -> None:
    """Overwrite a ctypes buffer with zeros.

    Combined with the use of ctypes (rather than ``bytes``) for the
    KEK in flight, this lets us actually clear the buffer when we're
    done with it — modulo the runtime copies caveat in the module
    docstring.
    """
    ctypes.memset(buffer, 0, len(buffer))


# ---- Session file I/O ----------------------------------------------------


def write_session(kek: bytes, ttl_seconds: float) -> tuple[Path, bool]:
    """Write the KEK and a fresh token to the session file.

    Spawns a detached cleaner that deletes the file after
    ``ttl_seconds`` *only if* the on-disk session token still matches
    the one we just wrote (defending against the double-unlock race).

    Returns the session-file path and a boolean indicating whether
    the in-memory KEK buffer was successfully ``mlock``-ed. The CLI
    surfaces the boolean as a one-line warning when the lock fails.

    Symlink defense
    ---------------

    The path is unlinked before opening to remove any pre-existing
    file or symlink, and the new file is created with
    ``O_EXCL | O_NOFOLLOW`` so a racing attacker cannot point our
    write at an arbitrary location. ``O_CLOEXEC`` prevents the fd
    from leaking into our detached cleaner subprocess.
    """
    if len(kek) != KEK_LENGTH:
        raise SessionError(f"KEK must be {KEK_LENGTH} bytes, got {len(kek)}.")

    path = session_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)

    token = secrets.token_bytes(_TOKEN_LENGTH)

    # Build the file contents in a ctypes buffer so we can mlock and zero it.
    payload = _MAGIC + bytes([_VERSION]) + token + kek
    buffer = ctypes.create_string_buffer(payload, _FILE_LENGTH)
    locked = _try_mlock(buffer)

    # Remove any preexisting file (including symlinks); ignore-if-absent.
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)

    # O_EXCL: fail if a racer recreated the file in the meantime.
    # O_NOFOLLOW: fail if it's somehow a symlink despite our unlink.
    # O_CLOEXEC: don't leak the fd to the detached cleaner subprocess.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        _write_all(fd, bytes(buffer.raw[:_FILE_LENGTH]))
    finally:
        os.close(fd)

    # Best-effort zero of our local copy. The original ``kek`` argument
    # is a ``bytes`` object we cannot zero, but at least our serialized
    # buffer can be wiped.
    _zero_buffer(buffer)

    # Spawn the detached cleaner. Pass the token so it can verify
    # ownership at delete time.
    cleaner_script = Path(__file__).parent / "_session_cleaner.py"
    subprocess.Popen(
        [
            sys.executable,
            str(cleaner_script),
            str(path),
            str(ttl_seconds),
            token.hex(),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )

    return path, locked


def _write_all(fd: int, data: bytes) -> None:
    """Write all bytes to ``fd``, handling short writes.

    POSIX ``write(2)`` may return fewer bytes than requested even for
    regular files, in principle. Loop until everything is written.
    """
    written = 0
    while written < len(data):
        chunk = os.write(fd, data[written:])
        if chunk == 0:
            raise SessionError("Short write to session file (no progress).")
        written += chunk


def read_session() -> bytes:
    """Return the cached KEK, or raise :class:`SessionError`.

    Validates magic, version, length, file ownership, and permissions
    before returning. Open + fstat eliminates the symlink/TOCTOU
    window that path-based ``stat`` then ``read_bytes`` would have:
    we open with ``O_NOFOLLOW`` (so a symlink at the path fails
    immediately) then validate the same fd we read from.
    """
    path = session_file_path()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise SessionError("No active session. Run `cavern unlock` first.") from exc
    except OSError as exc:
        # ELOOP from O_NOFOLLOW when a symlink is at the path.
        raise SessionError(f"Session file refused (likely a symlink): {exc}") from exc

    try:
        st = os.fstat(fd)
        if st.st_uid != os.getuid():
            raise SessionError(
                f"Session file owned by uid {st.st_uid}; refusing to use."
            )
        if st.st_mode & 0o077:
            raise SessionError(
                "Session file has insecure permissions; run `cavern lock`."
            )
        # Read at most _FILE_LENGTH + 1 so a trailing-byte attempt is
        # still caught by the strict length check below.
        data = os.read(fd, _FILE_LENGTH + 1)
    finally:
        os.close(fd)

    if len(data) != _FILE_LENGTH:
        raise SessionError("Session file is corrupt (wrong length).")
    if data[: len(_MAGIC)] != _MAGIC:
        raise SessionError("Session file is corrupt (bad magic).")
    version = data[len(_MAGIC)]
    if version != _VERSION:
        raise SessionError(f"Unsupported session-file version: {version}.")

    return bytes(data[_HEADER_LENGTH:])


def read_session_token() -> bytes:
    """Return the on-disk session token (used by the cleaner only)."""
    path = session_file_path()
    data = path.read_bytes()
    if len(data) != _FILE_LENGTH or data[: len(_MAGIC)] != _MAGIC:
        raise SessionError("Session file is corrupt.")
    return bytes(data[len(_MAGIC) + 1 : _HEADER_LENGTH])


def clear_session() -> None:
    """Remove the session file. Idempotent."""
    path = session_file_path()
    with contextlib.suppress(FileNotFoundError):
        path.unlink()


def session_is_active() -> bool:
    """Cheap optimistic check: does a session file exist and look usable?

    This is a TOCTOU-prone helper used only to decide *whether to try*
    a cached unlock. The next ``read_session`` call does the
    authoritative validation; this function just spares us a GPG
    fallback path when we can already tell it would be wrong.

    Uses ``lstat`` rather than ``stat``: a symlink at the session path
    must always be treated as "not active" so we fall through to a
    fresh GPG unlock rather than to a tampered file.
    """
    path = session_file_path()
    try:
        st = os.lstat(path)
    except OSError:
        return False
    # Reject symlinks outright.
    if not stat_module.S_ISREG(st.st_mode):
        return False
    return st.st_uid == os.getuid() and not (st.st_mode & 0o077)
