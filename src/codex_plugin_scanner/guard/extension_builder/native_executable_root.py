"""Private, executable placement for verified native compiler bytes.

The verified compiler bytes are written to a fresh 0700 directory and run from
there, so the bytes that run are exactly the bytes that were verified. The
system temporary directory comes first. A host that mounts it noexec, such as
a container on a default tmpfs, runs them from a private folder in the Guard
home instead. That folder is used only while it, the Guard home and every
directory above the Guard home are closed to other accounts, so no second
account can swap the bytes between the write and the exec.

The copy is kept for the life of the process. Writing and first running a
new executable of over 100 MB takes seconds on Windows, where every new image
is scanned, and one control change asks native several times. Before each
run the copy is compared byte for byte with the freshly verified bytes, or
hashed against the digest a verification of unchanged packaged files admitted;
a copy that differs, is missing or sits in a directory that is no longer
private is replaced, never run. A replaced copy is removed as soon as no run is using
it.

A process that has opened a Guard home also keeps one copy in that home's
private folder, named by the SHA-256 of its bytes, for later processes. The
first run of a newly written executable costs over a second on macOS, which
assesses every new image, and on Windows, which scans it; a fresh copy per
process paid that on every cold start. A later process runs the kept copy only
after the same byte-for-byte comparison with the bytes it verified, and replaces
a copy that differs. Copies of other runtimes nobody has used for a day are
removed.

Windows keeps an executable's image locked for a moment after its process
exits, so each directory is removed at exit with a short backoff once that
lock is released. A single attempt left directories behind on Windows until
the disk filled. Each directory name carries its owner's process id, and a
process that writes a new copy removes the copies of owners that ended
without running their exit handlers.
"""

from __future__ import annotations

import atexit
import hashlib
import logging
import os
import shutil
import stat
import tempfile
import threading
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

_PRIVATE_ROOT_NAME = "native-exec"
_LOGGER = logging.getLogger(__name__)
_EXECUTABLE_NAME = "hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime"
_DIRECTORY_PREFIX = "hol-guard-source-compiler-"
# Every Guard home this process has opened, most recent first, so a store for
# one home never takes the fallback away from a store for another.
_private_roots: list[Path] = []
# Seconds to wait between removal attempts while Windows still holds the image.
_REMOVAL_BACKOFF = (0.05, 0.1, 0.2, 0.4, 0.8, 1.6)
_COMPARE_CHUNK = 1024 * 1024
_KEPT_PREFIX = "hol-guard-runtime-"
# A kept copy of another runtime unused for this long is removed.
_KEPT_IDLE_SECONDS = 24 * 60 * 60
_copies_lock = threading.Lock()


@dataclass
class _Copy:
    # None for a copy kept for later processes, which this process never removes.
    directory: tempfile.TemporaryDirectory[str] | None
    path: Path
    # The Guard-home private folder holding the copy, or None for the system temp.
    root: Path | None
    # Runs currently using the copy; a replaced copy is removed once none are.
    users: int = 0
    # When this process last marked a kept copy as in use.
    touched: float = 0.0


# The copy runs reuse, and replaced copies another thread is still running.
_current: _Copy | None = None
_retired: list[_Copy] = []


class ExecutableMaterializationError(OSError):
    """No private directory could run the verified compiler bytes."""


def use_guard_home(guard_home: Path) -> None:
    """Add a Guard home whose private folder can back a noexec temporary directory."""
    root = Path(guard_home) / _PRIVATE_ROOT_NAME
    with suppress(ValueError):
        _private_roots.remove(root)
    _private_roots.insert(0, root)


def _closed_directory(metadata: os.stat_result, *, open_bits: int) -> bool:
    return stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid() and not metadata.st_mode & open_bits


def _replaceable_by_another_account(directory: Path) -> bool:
    """Whether another account could rename a directory above this one away.

    Both the path as named and the path its links resolve to are checked. A
    link is only as safe as the directory holding it, which is checked as the
    next ancestor, so links are judged by owner alone.
    """
    resolved = Path(os.path.realpath(directory))
    for ancestor in (*directory.parents, *resolved.parents):
        metadata = ancestor.lstat()
        if metadata.st_uid not in (0, os.geteuid()):
            return True
        if stat.S_ISLNK(metadata.st_mode):
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            return True
        # The sticky bit limits renames to the entry's owner, as on /tmp.
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not metadata.st_mode & stat.S_ISVTX:
            return True
    return False


def _private_root_directory(root: Path) -> Path | None:
    if os.name == "nt":
        return _windows_root_directory(root)
    try:
        # Another account that can write the Guard home, or any directory
        # above it, could rename the private folder or the home away and put
        # its own in its place.
        if not _closed_directory(root.parent.lstat(), open_bits=stat.S_IWGRP | stat.S_IWOTH):
            return None
        if _replaceable_by_another_account(root.parent):
            return None
        with suppress(FileExistsError):
            root.mkdir(mode=0o700)
        if not _closed_directory(root.lstat(), open_bits=0o077):
            return None
    except OSError:
        return None
    return root


def _plain_windows_directory(path: Path) -> bool:
    """A directory that is not a link or junction, which could point it elsewhere."""
    metadata = path.lstat()
    reparse = getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISDIR(metadata.st_mode) and not reparse


def _inside_windows_profile(folder: Path) -> bool:
    """Whether `folder` sits in the user's profile through plain folders only.

    The profile's access list keeps other accounts out and its subfolders
    inherit it. A Guard home elsewhere, such as `C:\\guard`, may inherit a
    list that lets other accounts write, so it gets no private copies.
    """
    try:
        profile = Path.home().absolute()
        relative = folder.absolute().relative_to(profile)
    except (OSError, RuntimeError, ValueError):
        return False
    current = profile
    for part in relative.parts:
        current = current / part
        if not _plain_windows_directory(current):
            return False
    return True


def _windows_root_directory(root: Path) -> Path | None:
    """The Guard-home folder on Windows, when the user profile's access list keeps other accounts out."""
    try:
        if not _inside_windows_profile(root.parent):
            return None
        with suppress(FileExistsError):
            root.mkdir()
        if not _plain_windows_directory(root):
            return None
    except OSError:
        return None
    return root


def _write(directory: Path, raw: bytes) -> Path:
    path = directory / _EXECUTABLE_NAME
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o700)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            _ = handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if os.name != "nt":
        path.chmod(0o700)
    return path


def _candidate(raw: bytes, parent: Path | None) -> tuple[tempfile.TemporaryDirectory[str], Path] | None:
    try:
        directory = tempfile.TemporaryDirectory(
            prefix=f"{_DIRECTORY_PREFIX}{os.getpid()}-", dir=parent, ignore_cleanup_errors=True
        )
    except OSError:
        return None
    try:
        path = _write(Path(directory.name), raw)
    except OSError:
        directory.cleanup()
        return None
    # Linux answers X_OK with EACCES for a file on a noexec mount.
    if os.name != "nt" and not os.access(path, os.X_OK):
        directory.cleanup()
        return None
    return directory, path


def _remove_released(directory: Path) -> None:
    """Remove a directory whose executable may still be locked by the system."""
    for delay in (*_REMOVAL_BACKOFF, None):
        if not directory.exists():
            return
        try:
            shutil.rmtree(directory)
        except FileNotFoundError:
            return
        except OSError as exc:
            if delay is None:
                _LOGGER.warning("could not remove the source compiler directory %s: %s", directory, exc)
                return
            time.sleep(delay)
        else:
            return


def _owner_running(pid: int) -> bool:
    """Fail closed: an owner that cannot be proven gone counts as running."""
    if os.name == "nt":
        try:
            from ..windows_paths import windows_process_is_running

            return windows_process_is_running(pid)
        except Exception:
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _remove_abandoned(parent: Path) -> None:
    """Remove copies whose owner ended without running its exit handlers."""
    try:
        entries = list(os.scandir(parent))
    except OSError:
        return
    for entry in entries:
        owner, separator, _ = entry.name.removeprefix(_DIRECTORY_PREFIX).partition("-")
        if not entry.name.startswith(_DIRECTORY_PREFIX) or not separator or not owner.isdigit():
            continue
        if int(owner) in (0, os.getpid()):
            continue
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISDIR(metadata.st_mode) or (os.name != "nt" and metadata.st_uid != os.geteuid()):
            continue
        if not _owner_running(int(owner)):
            shutil.rmtree(entry.path, ignore_errors=True)


def _holds(copy: _Copy, size: int, same: Callable[[BinaryIO], bool]) -> bool:
    """Whether a kept copy is still private, executable, of this size and passes `same`."""
    path = copy.path
    if copy.directory is None and copy.root not in _private_roots:
        return False
    try:
        # The same checks that admitted the copy's directory when it was written.
        if copy.root is not None and _private_root_directory(copy.root) is None:
            return False
        if os.name == "nt":
            if not _plain_windows_directory(path.parent):
                return False
        elif not _closed_directory(path.parent.lstat(), open_bits=0o077) or not os.access(path, os.X_OK):
            return False
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != size:
                return False
            return same(handle)
    except OSError:
        return False


def _holds_exactly(copy: _Copy, raw: bytes) -> bool:
    """Whether a kept copy is still private, executable and exactly the verified bytes."""

    def same(handle: BinaryIO) -> bool:
        view = memoryview(raw)
        offset = 0
        while chunk := handle.read(_COMPARE_CHUNK):
            # A memoryview compares element by element, about fifty times slower than bytes.
            if view[offset : offset + len(chunk)].tobytes() != chunk:
                return False
            offset += len(chunk)
        return offset == len(raw)

    return _holds(copy, len(raw), same)


def _holds_digest(copy: _Copy, size: int, sha256: str) -> bool:
    """Whether a kept copy is still private, executable and the bytes with this SHA-256."""

    def same(handle: BinaryIO) -> bool:
        digest = hashlib.sha256()
        read = 0
        while read <= size and (chunk := handle.read(_COMPARE_CHUNK)):
            digest.update(chunk)
            read += len(chunk)
        return read == size and digest.hexdigest() == sha256

    return _holds(copy, size, same)


def _materialize(raw: bytes) -> _Copy:
    candidate, root = _candidate(raw, None), None
    if os.name != "nt":
        for private_root in tuple(_private_roots):
            if candidate is not None:
                break
            if (directory := _private_root_directory(private_root)) is not None:
                candidate, root = _candidate(raw, directory), private_root
    if candidate is None:
        raise ExecutableMaterializationError("no private directory can run the verified source compiler")
    _remove_abandoned(Path(candidate[0].name).parent)
    return _Copy(*candidate, root=root)


def _remove_idle_kept(directory: Path, keep: str) -> None:
    """Remove kept copies of other runtimes that no process has used for a day."""
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return
    for entry in entries:
        if not entry.name.startswith(_KEPT_PREFIX) or entry.name == keep:
            continue
        with suppress(OSError):
            if time.time() - entry.stat(follow_symlinks=False).st_mtime > _KEPT_IDLE_SECONDS:
                shutil.rmtree(entry.path, ignore_errors=True)


def _kept(raw: bytes, sha256: str | None) -> _Copy | None:
    """The copy kept in a private Guard-home folder for later processes, holding exactly `raw`.

    Only a Guard home's private folder holds one; without an open Guard home
    every process writes its own copy as before. A kept copy that differs is
    replaced, and the new copy is written under a private name and renamed into
    place, so no process ever runs a partly written copy.
    """
    # The name only finds the copy; its bytes are still compared with `raw` before any run.
    plain_hex = sha256 is not None and len(sha256) == 64 and all(c in "0123456789abcdef" for c in sha256)
    digest = sha256 if plain_hex else None
    name = _KEPT_PREFIX + (digest if digest is not None else hashlib.sha256(raw).hexdigest())
    for private_root in tuple(_private_roots):
        if (directory := _private_root_directory(private_root)) is None:
            continue
        copy = _Copy(directory=None, path=directory / name / _EXECUTABLE_NAME, root=private_root)
        if not _holds_exactly(copy, raw) and not _place(copy, raw, directory):
            continue
        _touch(copy, force=True)
        _remove_abandoned(directory)
        _remove_idle_kept(directory, name)
        return copy
    return None


def _place(copy: _Copy, raw: bytes, directory: Path) -> bool:
    """Write the kept copy under a private name and rename it into place.

    Another process starting at the same moment may place the same copy
    first. What is in the way is removed only after a fresh look shows it
    still differs from `raw`, so a copy another process just placed is kept.
    """
    made = _candidate(raw, directory)
    if made is None:
        return False
    written, _path = made
    try:
        for _attempt in range(2):
            try:
                os.rename(written.name, copy.path.parent)
            except OSError:
                if _holds_exactly(copy, raw):
                    return True
                if os.path.islink(copy.path.parent):
                    with suppress(OSError):
                        os.unlink(copy.path.parent)
                elif os.path.lexists(copy.path.parent):
                    _remove_released(copy.path.parent)
                continue
            return _holds_exactly(copy, raw)
        return False
    finally:
        written.cleanup()


_TOUCH_SECONDS = 60 * 60


def _touch(copy: _Copy, *, force: bool = False) -> None:
    """Mark a kept copy as in use, at most hourly, so idle cleanup in other processes leaves it."""
    if copy.directory is not None:
        return
    now = time.monotonic()
    if not force and now - copy.touched < _TOUCH_SECONDS:
        return
    copy.touched = now
    with suppress(OSError):
        os.utime(copy.path.parent)


def _remove(copies: list[_Copy]) -> None:
    for copy in copies:
        if copy.directory is None:
            continue
        copy.directory.cleanup()
        _remove_released(Path(copy.directory.name))


def _take_idle_retired() -> list[_Copy]:
    """Detach replaced copies no run is using. Caller holds the lock."""
    idle = [copy for copy in _retired if copy.users == 0]
    _retired[:] = [copy for copy in _retired if copy.users]
    return idle


def release_copies() -> None:
    """Remove every private copy this process made. Runs at exit."""
    global _current
    with _copies_lock:
        copies = [*_retired, *([_current] if _current is not None else [])]
        _retired.clear()
        _current = None
    _remove(copies)


atexit.register(release_copies)


@contextmanager
def verified_executable(raw: bytes, sha256: str | None = None) -> Generator[Path]:
    """Yield a private copy holding exactly the verified bytes.

    `sha256`, when the caller already checked `raw` against it, names a Guard
    home's kept copy without hashing the bytes again.
    """
    global _current
    with _copies_lock:
        if _current is None or not _holds_exactly(_current, raw):
            replacement = _kept(raw, sha256) or _materialize(raw)
            if _current is not None:
                _retired.append(_current)
            _current = replacement
        copy = _current
        copy.users += 1
        _touch(copy)
        idle = _take_idle_retired()
    _remove(idle)
    try:
        yield copy.path
    finally:
        with _copies_lock:
            copy.users -= 1
            idle = _take_idle_retired()
        _remove(idle)


@contextmanager
def reused_executable(size: int, sha256: str) -> Generator[Path | None]:
    """Yield the kept copy if it still holds exactly the bytes with this size and SHA-256.

    It yields None instead of writing a copy, so the caller verifies the
    packaged bytes again and hands them to `verified_executable`.
    """
    with _copies_lock:
        copy = _current if _current is not None and _holds_digest(_current, size, sha256) else None
        if copy is not None:
            copy.users += 1
            _touch(copy)
    if copy is None:
        yield None
        return
    try:
        yield copy.path
    finally:
        with _copies_lock:
            copy.users -= 1
            idle = _take_idle_retired()
        _remove(idle)
