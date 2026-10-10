"""Cross-process barrier for replacing the package-bound native runtime."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import time
from collections.abc import Generator
from contextlib import contextmanager, suppress
from pathlib import Path

from .native_policy_snapshot_windows_support import _runtime_state_directory

RESIDENT_UPDATE_LOCK_NAME = "resident-update.v1.lock"
_MAX_RUNTIME_BYTES = 128 * 1024 * 1024
_MAX_MARKER_BYTES = 128
_DEFAULT_TIMEOUT_SECONDS = 30.0


class NativeResidentUpdateLockError(RuntimeError):
    """The native resident update barrier could not be established safely."""

    reason_code: str

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class NativeResidentUpdateLock:
    """An exclusive updater lease on the native-runtime replacement barrier."""

    _descriptor: int
    _released: bool

    def __init__(self, descriptor: int) -> None:
        self._descriptor = descriptor
        self._released = False

    @property
    def active(self) -> bool:
        return not self._released

    def publish_runtime_digest(self, executable: Path) -> str:
        digest = _runtime_digest(executable)
        if digest is None:
            raise NativeResidentUpdateLockError("update_native_resident_lock_finalize_failed")
        _write_marker(self._descriptor, digest)
        return digest

    def release(self) -> None:
        if self._released:
            return
        try:
            _unlock(self._descriptor)
        except OSError as error:
            raise NativeResidentUpdateLockError("update_native_resident_lock_release_failed") from error
        finally:
            try:
                os.close(self._descriptor)
            finally:
                self._released = True

    def __enter__(self) -> NativeResidentUpdateLock:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        if not self._released:
            self.release()


def _runtime_digest(executable: Path) -> str | None:
    try:
        metadata = executable.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return None
        if metadata.st_size > _MAX_RUNTIME_BYTES:
            return None
        if os.name != "nt":
            uid = getattr(metadata, "st_uid", None)
            if uid not in {os.geteuid(), 0} or stat.S_IMODE(metadata.st_mode) & 0o022:
                return None
        digest = hashlib.sha256()
        with executable.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, RuntimeError, ValueError):
        return None


def _open_lock_file(guard_home: Path) -> int:
    try:
        state_dir = _runtime_state_directory(guard_home.expanduser().resolve())
        path = state_dir / RESIDENT_UPDATE_LOCK_NAME
        if os.name == "nt":
            from .native_policy_snapshot import _windows_open_private_fd

            descriptor = _windows_open_private_fd(path, maximum_bytes=_MAX_MARKER_BYTES)
        else:
            flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(path, flags, 0o600)
            metadata = os.fstat(descriptor)
            path_metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or metadata.st_dev != path_metadata.st_dev
                or metadata.st_ino != path_metadata.st_ino
            ):
                os.close(descriptor)
                raise NativeResidentUpdateLockError("update_native_resident_lock_invalid")
        return descriptor
    except NativeResidentUpdateLockError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise NativeResidentUpdateLockError("update_native_resident_lock_open_failed") from error


def _try_lock(descriptor: int) -> None:
    if os.name == "nt":
        from .native_command_control_windows_lock import try_lock_authority_file

        try_lock_authority_file(descriptor, shared=False)
        return
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _is_lock_contention(error: OSError) -> bool:
    if isinstance(error, BlockingIOError):
        return True
    if error.errno in {errno.EACCES, errno.EAGAIN}:
        return True
    return getattr(error, "winerror", None) == 33


def _unlock(descriptor: int) -> None:
    if os.name == "nt":
        from .native_command_control_windows_lock import unlock_authority_file

        unlock_authority_file(descriptor)
        return
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_UN)


def _pwrite_all(descriptor: int, data: bytes) -> None:
    _ = os.lseek(descriptor, 0, os.SEEK_SET)
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("native resident update marker write failed")
        offset += written


def _read_marker_bytes(descriptor: int) -> bytes:
    _ = os.lseek(descriptor, 0, os.SEEK_SET)
    return os.read(descriptor, _MAX_MARKER_BYTES + 1)


def _write_marker(descriptor: int, digest: str) -> None:
    """Replace the marker without ever leaving it truncated.

    The marker file is also the flock identity, so a tmp+rename swap would
    detach the barrier from every process holding the old inode. Instead the
    new value overwrites the old one in place, in one write, and the file is
    only shrunk afterwards (shrinking cannot hit ENOSPC). A failed write
    restores the previous bytes and length so a full disk cannot leave an
    empty or torn marker behind.
    """

    encoded = f"{digest}\n".encode("ascii") if digest else b""
    previous: bytes | None = None
    try:
        previous = _read_marker_bytes(descriptor)
        _pwrite_all(descriptor, encoded)
        if len(previous) > len(encoded):
            os.ftruncate(descriptor, len(encoded))
        os.fsync(descriptor)
    except OSError as error:
        if previous is not None and len(previous) <= _MAX_MARKER_BYTES:
            try:
                _pwrite_all(descriptor, previous)
                os.ftruncate(descriptor, len(previous))
                os.fsync(descriptor)
            except OSError:
                pass
        raise NativeResidentUpdateLockError("update_native_resident_lock_write_failed") from error


def _valid_marker(raw: bytes) -> str | None:
    text = raw[:-1] if raw.endswith(b"\n") else raw
    if len(text) != 64 or not all(byte in b"0123456789abcdefABCDEF" for byte in text):
        return None
    return text.decode("ascii")


def repair_stale_resident_update_marker(guard_home: Path, runtime_executable: Path) -> dict[str, object]:
    """Re-point a marker left behind by an interrupted update at the installed runtime.

    The marker is only touched while this process holds the exclusive updater
    lease (non-blocking), so no update is in progress and no resident client
    holds the shared lease. A marker that is empty or already names the
    installed runtime is left alone. Otherwise it is rewritten to the installed
    runtime digest, exactly what a completed update publishes, so runtimes
    superseded by that update still fail closed; the marker is never cleared.
    """

    try:
        descriptor = _open_lock_file(guard_home)
    except NativeResidentUpdateLockError as error:
        return {"status": "unavailable", "reason_code": error.reason_code}
    try:
        try:
            _try_lock(descriptor)
        except OSError as error:
            if _is_lock_contention(error):
                return {"status": "update_in_progress"}
            return {"status": "unavailable", "reason_code": "update_native_resident_lock_failed"}
        try:
            installed = _runtime_digest(runtime_executable)
            if installed is None:
                return {"status": "unavailable", "reason_code": "update_native_resident_lock_finalize_failed"}
            try:
                observed = _read_marker_bytes(descriptor)
            except OSError:
                return {"status": "unavailable", "reason_code": "update_native_resident_lock_read_failed"}
            if not observed.strip():
                return {"status": "current"}
            marker = _valid_marker(observed)
            if marker is not None and marker.lower() == installed:
                return {"status": "current"}
            try:
                _write_marker(descriptor, installed)
            except NativeResidentUpdateLockError as error:
                return {"status": "unavailable", "reason_code": error.reason_code}
            return {"status": "repaired", "previous_marker_valid": marker is not None}
        finally:
            with suppress(OSError):
                _unlock(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def hold_native_resident_update_lock(
    guard_home: Path,
    *,
    initial_executable: Path | None = None,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> Generator[NativeResidentUpdateLock, None, None]:
    """Hold the exclusive barrier while the installed native binary changes."""

    descriptor = _open_lock_file(guard_home)
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while True:
        try:
            _try_lock(descriptor)
            break
        except OSError as error:
            if not _is_lock_contention(error):
                os.close(descriptor)
                raise NativeResidentUpdateLockError("update_native_resident_lock_failed") from error
            if time.monotonic() >= deadline:
                os.close(descriptor)
                raise NativeResidentUpdateLockError("update_native_resident_lock_busy") from error
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
    lock = NativeResidentUpdateLock(descriptor)
    try:
        current_digest = _runtime_digest(initial_executable) if initial_executable is not None else None
        if current_digest is not None:
            _write_marker(descriptor, current_digest)
        yield lock
    finally:
        if lock.active:
            lock.release()


__all__ = [
    "RESIDENT_UPDATE_LOCK_NAME",
    "NativeResidentUpdateLock",
    "NativeResidentUpdateLockError",
    "hold_native_resident_update_lock",
    "repair_stale_resident_update_marker",
]
