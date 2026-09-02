"""Windows verifier-key persistence using one verified handle."""

from __future__ import annotations

import hmac
import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path
from typing import Any

from .native_policy_snapshot_codec import derive_native_policy_verifier_key
from .native_policy_snapshot_constants import (
    _VERIFIER_KEY_BYTES,
    NATIVE_POLICY_VERIFIER_KEY_NAME,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_windows_acl import _windows_verify_private_dacl
from .native_policy_snapshot_windows_atomic import _windows_write_private_file_atomic
from .native_policy_snapshot_windows_io import (
    _windows_close_handle,
    _windows_open_handle,
    _windows_repair_private_file,
)
from .native_policy_snapshot_windows_state import _windows_private_state_binding
from .native_policy_snapshot_windows_support import (
    _runtime_state_directory,
    _windows_owner_sid,
)


def _windows_read_key(path: Path, expected: bytes) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32, handle, information = _windows_open_handle(path, directory=False)
    try:
        owner_sid = _windows_owner_sid()
        _windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
        size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
        if size != _VERIFIER_KEY_BYTES:
            raise NativePolicySnapshotError("native_policy_verifier_key_invalid")
        read_file = kernel32.ReadFile
        read_file.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        read_file.restype = wintypes.BOOL
        buffer = (ctypes.c_ubyte * (_VERIFIER_KEY_BYTES + 1))()
        count = wintypes.DWORD()
        if (
            not read_file(
                handle,
                buffer,
                _VERIFIER_KEY_BYTES + 1,
                ctypes.byref(count),
                None,
            )
            or count.value != _VERIFIER_KEY_BYTES
        ):
            raise NativePolicySnapshotError("native_policy_verifier_key_read_failed")
        if not hmac.compare_digest(bytes(buffer[: count.value]), expected):
            raise NativePolicySnapshotError("native_policy_verifier_key_mismatch")
    finally:
        _windows_close_handle(kernel32, handle)


def _windows_provision_verifier_key(
    path: Path,
    derived: bytes,
    *,
    parent_path: Path,
    parent_handle: Any,
) -> Path:
    with suppress(FileNotFoundError):
        _windows_repair_private_file(path)
    try:
        _windows_read_key(path, derived)
        return path
    except FileNotFoundError:
        pass
    temporary_name = f".{NATIVE_POLICY_VERIFIER_KEY_NAME}.{secrets.token_hex(16)}.tmp"
    try:
        _windows_write_private_file_atomic(
            parent_path=parent_path,
            parent_handle=parent_handle,
            temporary_name=temporary_name,
            destination_name=path.name,
            payload=derived,
            maximum_bytes=_VERIFIER_KEY_BYTES,
            kind="verifier_key",
            replace_existing=False,
        )
    except FileExistsError:
        _windows_read_key(path, derived)
        return path
    except NativePolicySnapshotError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise NativePolicySnapshotError("native_policy_verifier_key_write_failed") from error
    return path


def provision_native_policy_verifier_key(
    guard_home: Path,
    policy_integrity_key: bytes,
) -> Path:
    """Provision the owner-private derived key consumed by the Rust resident.

    Creation uses ``O_EXCL`` and never replaces an existing key. A changed
    policy master is therefore a safe failure requiring explicit repair rather
    than an implicit verifier reset that could invalidate the resident floor.
    """

    derived = derive_native_policy_verifier_key(policy_integrity_key)
    if os.name == "nt":
        # Keep the verified guard-home/runtime ancestry open while the key is
        # read, repaired, or created. This prevents a path swap from redirecting
        # the Windows key operation after validation.
        with _windows_private_state_binding(guard_home) as binding:
            path = binding.path / NATIVE_POLICY_VERIFIER_KEY_NAME
            return _windows_provision_verifier_key(
                path,
                derived,
                parent_path=binding.path,
                parent_handle=binding.handle,
            )
    state_dir = _runtime_state_directory(guard_home)
    path = state_dir / NATIVE_POLICY_VERIFIER_KEY_NAME
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_verifier_key_stat_failed") from error

    if metadata is not None:
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise NativePolicySnapshotError("native_policy_verifier_key_invalid")
        if metadata.st_size != _VERIFIER_KEY_BYTES:
            raise NativePolicySnapshotError("native_policy_verifier_key_invalid")
        if os.name != "nt" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise NativePolicySnapshotError("native_policy_verifier_key_not_private")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise NativePolicySnapshotError("native_policy_verifier_key_read_failed") from error
        try:
            opened = os.fstat(descriptor)
            existing = os.read(descriptor, _VERIFIER_KEY_BYTES + 1)
        finally:
            os.close(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != _VERIFIER_KEY_BYTES
            or len(existing) != _VERIFIER_KEY_BYTES
            or not hmac.compare_digest(existing, derived)
        ):
            raise NativePolicySnapshotError("native_policy_verifier_key_mismatch")
        return path

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        # Another process won the race. Re-enter the validation path without
        # replacing or weakening its key.
        return provision_native_policy_verifier_key(guard_home, policy_integrity_key)
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_verifier_key_write_failed") from error
    try:
        written = 0
        while written < len(derived):
            written += os.write(descriptor, derived[written:])
        os.fsync(descriptor)
    except OSError as error:
        raise NativePolicySnapshotError("native_policy_verifier_key_write_failed") from error
    finally:
        os.close(descriptor)
    if os.name != "nt":
        try:
            path.chmod(0o600)
            directory_descriptor = os.open(
                state_dir,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError as error:
            raise NativePolicySnapshotError("native_policy_verifier_key_sync_failed") from error
    return path
