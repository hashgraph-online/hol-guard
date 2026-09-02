"""Handle-bound Windows atomic replacement primitives for native state."""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path
from typing import Any

from ..safe_output_windows import _FileDispositionInformation, _FileRenameInfo, _IoStatusBlock
from .native_policy_snapshot_constants import (
    _WINDOWS_ERROR_ALREADY_EXISTS,
    _WINDOWS_ERROR_FILE_EXISTS,
    NativePolicySnapshotError,
)

_WINDOWS_FILE_RENAME_INFORMATION = 10
_WINDOWS_FILE_DISPOSITION_INFO = 4


def _snapshot_api() -> Any:
    """Resolve façade hooks lazily, preserving established monkeypatch seams."""

    from . import native_policy_snapshot

    return native_policy_snapshot


def _windows_handle_value(handle: Any) -> int:
    value = getattr(handle, "value", handle)
    if not isinstance(value, int) or value < 0:
        raise NativePolicySnapshotError("native_policy_windows_handle_invalid")
    return value


def _windows_child_name(name: str) -> str:
    if not name or name in {".", ".."} or any(character in name for character in ("/", "\\", ":", "\x00")):
        raise NativePolicySnapshotError("native_policy_windows_path_invalid")
    return name


def _windows_rename_file_handle(
    kernel32: Any,
    handle: Any,
    parent_handle: Any,
    name: str,
    *,
    replace_if_exists: bool = True,
) -> None:
    """Rename an open file relative to an already verified parent handle."""

    import ctypes

    _ = kernel32
    encoded_name = _windows_child_name(name).encode("utf-16-le")
    file_name_offset = _FileRenameInfo.file_name.offset
    buffer = ctypes.create_string_buffer(ctypes.sizeof(_FileRenameInfo) + len(encoded_name))
    info = ctypes.cast(buffer, ctypes.POINTER(_FileRenameInfo)).contents
    info.replace_if_exists = replace_if_exists
    info.root_directory = _windows_handle_value(parent_handle)
    info.file_name_length = len(encoded_name)
    ctypes.memmove(ctypes.addressof(buffer) + file_name_offset, encoded_name, len(encoded_name))
    native_library = ctypes.WinDLL("ntdll", use_last_error=True)
    native_library.NtSetInformationFile.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_IoStatusBlock),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    native_library.NtSetInformationFile.restype = ctypes.c_long
    native_library.RtlNtStatusToDosError.argtypes = [ctypes.c_long]
    native_library.RtlNtStatusToDosError.restype = ctypes.c_uint32
    status_block = _IoStatusBlock()
    status = int(
        native_library.NtSetInformationFile(
            ctypes.c_void_p(_windows_handle_value(handle)),
            ctypes.byref(status_block),
            buffer,
            ctypes.sizeof(buffer),
            _WINDOWS_FILE_RENAME_INFORMATION,
        )
    )
    if status < 0:
        ctypes.set_last_error(int(native_library.RtlNtStatusToDosError(status)))
        if not replace_if_exists and ctypes.get_last_error() in {
            _WINDOWS_ERROR_FILE_EXISTS,
            _WINDOWS_ERROR_ALREADY_EXISTS,
        }:
            raise FileExistsError(name)
        raise NativePolicySnapshotError("native_policy_windows_replace_failed")


def _windows_delete_file_handle(kernel32: Any, handle: Any) -> None:
    """Delete a temporary only through its still-open, identity-bound handle."""

    import ctypes
    from ctypes import wintypes

    disposition = _FileDispositionInformation(delete_file=True)
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    set_information.restype = wintypes.BOOL
    if not set_information(
        handle,
        _WINDOWS_FILE_DISPOSITION_INFO,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        raise NativePolicySnapshotError("native_policy_windows_temporary_cleanup_failed")


def _windows_file_identity(information: Any) -> tuple[int, int, int] | None:
    fields = ("dwVolumeSerialNumber", "nFileIndexHigh", "nFileIndexLow")
    if not all(hasattr(information, field) for field in fields):
        return None
    return (
        int(information.dwVolumeSerialNumber),
        int(information.nFileIndexHigh),
        int(information.nFileIndexLow),
    )


def _windows_prepare_replace_destination(
    *,
    api: Any,
    parent_path: Path,
    destination_name: str,
    descriptor: Any,
    dacl: Any,
    owner_sid: str,
    replace_existing: bool,
) -> Path:
    """Verify an existing destination, then close it so rename can replace it."""

    target_path = parent_path / destination_name
    try:
        target_kernel32, target_handle, _target_information = api._windows_open_handle(
            target_path,
            directory=False,
            repair=True,
            share_delete=True,
            rename_source=True,
        )
    except FileNotFoundError:
        return target_path
    try:
        api._windows_verify_private_owner(target_handle, owner_sid=owner_sid)
        api._windows_apply_private_dacl(target_kernel32, target_handle, descriptor, dacl, False)
        api._windows_verify_private_dacl(target_handle, owner_sid=owner_sid, directory=False)
        if not replace_existing:
            raise FileExistsError(str(target_path))
    finally:
        api._windows_close_handle(target_kernel32, target_handle)
    return target_path


def _windows_rename_releasing_barrier(
    *,
    api: Any,
    kernel32: Any,
    source_handle: Any,
    parent_path: Path,
    parent_handle: Any,
    destination_name: str,
    replace_existing: bool,
    directory_handles: list[tuple[Any, Any]] | None,
) -> None:
    """Rename through a share-delete parent after releasing the exclusive barrier."""

    rename_kernel32 = None
    rename_handle = None
    released = False
    try:
        root_handle = parent_handle
        if directory_handles is not None:
            exclusive_kernel32, exclusive_handle = directory_handles.pop()
            released = True
            api._windows_close_handle(exclusive_kernel32, exclusive_handle)
            rename_kernel32, rename_handle, _rename_information = api._windows_open_handle(
                parent_path,
                directory=True,
                rename_parent=True,
            )
            root_handle = rename_handle
        _windows_rename_file_handle(
            kernel32,
            source_handle,
            root_handle,
            destination_name,
            replace_if_exists=replace_existing,
        )
    finally:
        if rename_handle is not None:
            api._windows_close_handle(rename_kernel32, rename_handle)
        if released and directory_handles is not None:
            restored_kernel32, restored_handle, _restored = api._windows_open_handle(
                parent_path,
                directory=True,
                lock=True,
                add_file=True,
                repair=True,
            )
            directory_handles.append((restored_kernel32, restored_handle))


def _windows_commit_private_file_handle(
    *,
    api: Any,
    kernel32: Any,
    source_handle: Any,
    source_information: Any,
    parent_path: Path,
    parent_handle: Any,
    destination_name: str,
    descriptor: Any,
    dacl: Any,
    owner_sid: str,
    kind: str,
    replace_existing: bool = True,
    rename_state: list[bool] | None = None,
    directory_handles: list[tuple[Any, Any]] | None = None,
) -> None:
    """Validate the old target, then replace it through bound handles."""

    destination_name = _windows_child_name(destination_name)
    source_identity = _windows_file_identity(source_information)
    api._windows_verify_private_dacl(source_handle, owner_sid=owner_sid, directory=False)
    target_path = _windows_prepare_replace_destination(
        api=api,
        parent_path=parent_path,
        destination_name=destination_name,
        descriptor=descriptor,
        dacl=dacl,
        owner_sid=owner_sid,
        replace_existing=replace_existing,
    )
    _windows_rename_releasing_barrier(
        api=api,
        kernel32=kernel32,
        source_handle=source_handle,
        parent_path=parent_path,
        parent_handle=parent_handle,
        destination_name=destination_name,
        replace_existing=replace_existing,
        directory_handles=directory_handles,
    )
    if rename_state is not None:
        rename_state[0] = True
    api._windows_verify_private_dacl(source_handle, owner_sid=owner_sid, directory=False)
    try:
        committed_kernel32, committed_handle, committed_information = api._windows_open_handle(
            target_path,
            directory=False,
            share_delete=True,
        )
    except (FileNotFoundError, NativePolicySnapshotError) as error:
        raise NativePolicySnapshotError(f"native_policy_snapshot_{kind}_identity_failed") from error
    try:
        if source_identity is not None and _windows_file_identity(committed_information) != source_identity:
            raise NativePolicySnapshotError(f"native_policy_snapshot_{kind}_identity_failed")
        api._windows_verify_private_dacl(committed_handle, owner_sid=owner_sid, directory=False)
    finally:
        api._windows_close_handle(committed_kernel32, committed_handle)


def _windows_write_private_file_atomic(
    *,
    parent_path: Path,
    parent_handle: Any,
    temporary_name: str,
    destination_name: str,
    payload: bytes,
    maximum_bytes: int,
    kind: str,
    replace_existing: bool = True,
    directory_handles: list[tuple[Any, Any]] | None = None,
) -> None:
    """Create, write, and commit a private file while parent handles remain held."""

    import ctypes
    from ctypes import wintypes

    if not payload or len(payload) > maximum_bytes:
        raise NativePolicySnapshotError("native_policy_windows_write_too_large")
    temporary_name = _windows_child_name(temporary_name)
    destination_name = _windows_child_name(destination_name)
    api = _snapshot_api()
    with api._windows_private_descriptor(False) as (_advapi32, descriptor, dacl, owner_sid):
        temporary_path = parent_path / temporary_name
        kernel32, handle, information = api._windows_open_handle(
            temporary_path,
            directory=False,
            create_new=True,
            descriptor=descriptor,
            rename_source=True,
        )
        renamed = [False]
        try:
            api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
            write_file = kernel32.WriteFile
            write_file.argtypes = [
                wintypes.HANDLE,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.c_void_p,
            ]
            write_file.restype = wintypes.BOOL
            buffer = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
            written = 0
            while written < len(payload):
                request_size = min(64 * 1024, len(payload) - written)
                count = wintypes.DWORD()
                if not write_file(
                    handle,
                    ctypes.byref(buffer, written),
                    request_size,
                    ctypes.byref(count),
                    None,
                ):
                    raise NativePolicySnapshotError("native_policy_windows_write_failed")
                chunk_size = int(count.value)
                if chunk_size <= 0 or chunk_size > request_size:
                    raise NativePolicySnapshotError("native_policy_windows_write_failed")
                written += chunk_size
            flush = kernel32.FlushFileBuffers
            flush.argtypes = [wintypes.HANDLE]
            flush.restype = wintypes.BOOL
            if not flush(handle):
                raise NativePolicySnapshotError("native_policy_windows_sync_failed")
            _windows_commit_private_file_handle(
                api=api,
                kernel32=kernel32,
                source_handle=handle,
                source_information=information,
                parent_path=parent_path,
                parent_handle=parent_handle,
                destination_name=destination_name,
                descriptor=descriptor,
                dacl=dacl,
                owner_sid=owner_sid,
                kind=kind,
                replace_existing=replace_existing,
                rename_state=renamed,
                directory_handles=directory_handles,
            )
        except BaseException:
            # The source remains at the temporary name until rename succeeds,
            # so cleanup stays identity-bound to this handle for all failures,
            # including bounded writes and FlushFileBuffers.
            if not renamed[0]:
                with suppress(BaseException):
                    _windows_delete_file_handle(kernel32, handle)
            raise
        finally:
            api._windows_close_handle(kernel32, handle)


def _windows_delete_private_child(
    *,
    parent_path: Path,
    parent_handle: Any,
    name: str,
) -> None:
    """Delete one state child only through its verified parent and file handles."""

    name = _windows_child_name(name)
    _windows_handle_value(parent_handle)
    api = _snapshot_api()
    try:
        kernel32, handle, _information = api._windows_open_handle(
            parent_path / name,
            directory=False,
            rename_source=True,
            share_delete=True,
        )
    except FileNotFoundError:
        return
    try:
        owner_sid = api._windows_owner_sid()
        api._windows_verify_private_owner(handle, owner_sid=owner_sid)
        api._windows_verify_private_dacl(handle, owner_sid=owner_sid, directory=False)
        _windows_delete_file_handle(kernel32, handle)
    finally:
        api._windows_close_handle(kernel32, handle)


__all__ = [
    "_windows_commit_private_file_handle",
    "_windows_delete_file_handle",
    "_windows_delete_private_child",
    "_windows_file_identity",
    "_windows_handle_value",
    "_windows_rename_file_handle",
    "_windows_write_private_file_atomic",
]
