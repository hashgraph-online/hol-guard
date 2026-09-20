"""Owner-private, handle-bound files and interoperable control mutation locks."""

from __future__ import annotations

import os
import secrets
import stat
import threading
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path

from .native_command_control_authority import AUTHORITY_LOCK_NAME
from .native_policy_snapshot_constants import NativePolicySnapshotError

_LOCKS = threading.local()


class NativeCommandControlMutationRequiredError(NativePolicySnapshotError):
    def __init__(self) -> None:
        super().__init__("native_command_control_authority_mutation_required")


def require_command_control_mutation_lease(guard_home: Path) -> None:
    active = getattr(_LOCKS, "active", {})
    key = os.path.normcase(os.path.abspath(guard_home))
    if getattr(_LOCKS, "process_id", None) == os.getpid() and active.get(key) is True:
        raise NativeCommandControlMutationRequiredError()


def _invalid() -> NativePolicySnapshotError:
    return NativePolicySnapshotError("native_command_control_authority_path_invalid")


def _validate_file(descriptor: int, *, maximum_bytes: int, repair_mode: bool = False) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes or metadata.st_nlink != 1:
        raise _invalid()
    if os.name != "nt":
        if metadata.st_uid != os.geteuid():
            raise _invalid()
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            if not repair_mode:
                raise _invalid()
            # Existing installations created this retained lock with the
            # process umask. Tighten the already verified owned inode only.
            os.fchmod(descriptor, 0o600)
    return metadata


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


@contextmanager
def _unix_directory(path: Path, *, private: bool) -> Iterator[int]:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & (0o077 if private else 0o022):
            raise _invalid()
        if not _same_file(metadata, path.lstat()):
            raise _invalid()
        yield descriptor
        if not _same_file(metadata, path.lstat()):
            raise _invalid()
    finally:
        os.close(descriptor)


@contextmanager
def _unix_state_directory(guard_home: Path) -> Iterator[int]:
    from .native_policy_snapshot_windows_support import _runtime_state_directory

    state = _runtime_state_directory(guard_home)
    with (
        _unix_directory(guard_home, private=False) as home_descriptor,
        _unix_directory(state, private=True) as state_descriptor,
    ):
        opened = os.fstat(state_descriptor)
        if not _same_file(opened, os.stat(state.name, dir_fd=home_descriptor, follow_symlinks=False)):
            raise _invalid()
        yield state_descriptor
        if not _same_file(opened, os.stat(state.name, dir_fd=home_descriptor, follow_symlinks=False)):
            raise _invalid()


def read_private_state(guard_home: Path, name: str, maximum_bytes: int) -> bytes | None:
    if Path(name).name != name or name in {"", ".", ".."}:
        raise _invalid()
    if os.name == "nt":
        from . import native_policy_snapshot as api

        with api._windows_private_state_binding(guard_home) as binding:
            return api._windows_read_snapshot_bytes(binding.path / name, maximum_bytes=maximum_bytes)
    with _unix_state_directory(guard_home) as directory:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=directory)
        except FileNotFoundError:
            return None
        try:
            metadata = _validate_file(descriptor, maximum_bytes=maximum_bytes)
            content = bytearray()
            while len(content) <= maximum_bytes:
                chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            if len(content) != metadata.st_size or len(content) > maximum_bytes:
                raise _invalid()
            if not _same_file(metadata, os.stat(name, dir_fd=directory, follow_symlinks=False)):
                raise _invalid()
            return bytes(content)
        finally:
            os.close(descriptor)


def write_private_state(guard_home: Path, name: str, payload: bytes, maximum_bytes: int) -> None:
    if not payload or len(payload) > maximum_bytes or Path(name).name != name or name in {"", ".", ".."}:
        raise _invalid()
    temporary = f".{name}.{secrets.token_hex(16)}.tmp"
    if os.name == "nt":
        from . import native_policy_snapshot as api

        with api._windows_private_state_binding(guard_home) as binding:
            api._windows_write_private_file_atomic(
                parent_path=binding.path,
                parent_handle=binding.handle,
                directory_handles=binding.handles,
                temporary_name=temporary,
                destination_name=name,
                payload=payload,
                maximum_bytes=maximum_bytes,
                kind="command_control_authority",
            )
        return
    with _unix_state_directory(guard_home) as directory:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
        try:
            position = 0
            while position < len(payload):
                written = os.write(descriptor, payload[position:])
                if written <= 0:
                    raise _invalid()
                position += written
            os.fsync(descriptor)
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
            if not _same_file(os.fstat(descriptor), os.stat(name, dir_fd=directory, follow_symlinks=False)):
                raise _invalid()
        finally:
            os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=directory)


@contextmanager
def hold_command_control_authority_lock(
    guard_home: Path, *, timeout_seconds: float = 30.0, shared: bool = False
) -> Iterator[None]:
    """Retain one exclusive inode; native readers take an overlapping shared lease.

    Same-thread authority reads are reentrant so the publisher can verify
    controls and commit their marker in one lock interval. Other threads and
    processes still acquire the OS lock, including different GuardStore objects.
    """

    key = os.path.normcase(os.path.abspath(guard_home))
    process_id = os.getpid()
    if getattr(_LOCKS, "process_id", None) != process_id:
        # A fork inherits Python thread-local values, not an independently
        # acquired authority lease. Never grant its child reentrant ownership.
        _LOCKS.active = {}
        _LOCKS.process_id = process_id
    active: dict[str, bool] = getattr(_LOCKS, "active", {})
    if key in active:
        if active[key] and not shared:
            raise NativeCommandControlMutationRequiredError()
        yield
        return
    with ExitStack() as resources:
        directory: int | None = None
        if os.name == "nt":
            from . import native_policy_snapshot as api

            binding = resources.enter_context(api._windows_private_directory_binding(guard_home))
            descriptor = api._windows_open_private_fd(binding.path / AUTHORITY_LOCK_NAME, maximum_bytes=1)
        else:
            directory = resources.enter_context(_unix_directory(guard_home, private=False))
            descriptor = os.open(
                AUTHORITY_LOCK_NAME,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=directory,
            )
        resources.callback(os.close, descriptor)
        metadata = _validate_file(descriptor, maximum_bytes=1, repair_mode=True)
        if metadata.st_size == 0:
            os.write(descriptor, b"0")
            os.fsync(descriptor)
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        while True:
            try:
                if os.name == "nt":
                    from .native_command_control_windows_lock import try_lock_authority_file

                    try_lock_authority_file(descriptor, shared=shared)
                else:
                    import fcntl

                    fcntl.flock(descriptor, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
                break
            except OSError as error:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Timed out waiting for the extension control authority lock.") from error
                time.sleep(min(0.01, remaining))
        if directory is not None and not _same_file(
            metadata, os.stat(AUTHORITY_LOCK_NAME, dir_fd=directory, follow_symlinks=False)
        ):
            raise _invalid()
        _LOCKS.active = {**active, key: shared}
        try:
            yield
            if directory is not None and not _same_file(
                metadata, os.stat(AUTHORITY_LOCK_NAME, dir_fd=directory, follow_symlinks=False)
            ):
                raise _invalid()
        finally:
            if os.getpid() == process_id:
                _LOCKS.active = active
                if os.name == "nt":
                    from .native_command_control_windows_lock import unlock_authority_file

                    unlock_authority_file(descriptor)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            # After fork, closing only the child's inherited descriptor keeps
            # the parent's open-file-description lock intact. An explicit
            # LOCK_UN in that child would revoke the parent's live lease.
