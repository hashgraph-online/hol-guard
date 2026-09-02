"""Windows handle and descriptor-contract tests for native snapshots."""

from __future__ import annotations

import ctypes
import types
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot as snapshot_module
import codex_plugin_scanner.guard.native_policy_snapshot_windows_io as windows_io
import codex_plugin_scanner.guard.native_policy_snapshot_windows_support as windows_support
from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
    _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT,
    _WINDOWS_FILE_TYPE_DISK,
)

__test__ = False


def test_windows_open_handle_uses_disk_nonreparse_read_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_arguments: list[tuple[object, ...]] = []
    closed: list[object] = []

    def create_file(*arguments: object) -> object:
        create_arguments.append(arguments)
        return ctypes.c_void_p(71)

    def get_information(_handle: object, pointer: object) -> int:
        information_type = snapshot_module._windows_file_information_type()
        information = ctypes.cast(pointer, ctypes.POINTER(information_type)).contents
        information.dwFileAttributes = snapshot_module._WINDOWS_FILE_ATTRIBUTE_NORMAL
        return 1

    def close_handle(handle: object) -> int:
        closed.append(handle)
        return 1

    kernel32 = types.SimpleNamespace(
        CreateFileW=create_file,
        CloseHandle=close_handle,
        GetFileInformationByHandle=get_information,
        GetFileType=lambda _handle: snapshot_module._WINDOWS_FILE_TYPE_DISK,
    )
    monkeypatch.setattr(snapshot_module, "_windows_dll", lambda _name: kernel32)

    opened = snapshot_module._windows_open_handle(Path("C:/Guard/snapshot.json"), directory=False)

    assert getattr(opened[1], "value", opened[1]) == 71
    assert create_arguments[0][1] == snapshot_module._WINDOWS_GENERIC_READ
    assert create_arguments[0][2] == snapshot_module._WINDOWS_FILE_SHARE_READ
    assert create_arguments[0][5] & snapshot_module._WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    assert closed == []
    snapshot_module._windows_close_handle(*opened[:2])
    assert [getattr(handle, "value", handle) for handle in closed] == [71]


def test_windows_create_new_validation_failure_deletes_before_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def create_file(*_arguments: object) -> object:
        return ctypes.c_void_p(73)

    def get_information(_handle: object, pointer: Any) -> int:
        information_type = snapshot_module._windows_file_information_type()
        information = ctypes.cast(pointer, ctypes.POINTER(information_type)).contents
        information.dwFileAttributes = _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        return 1

    kernel32 = types.SimpleNamespace(
        CreateFileW=create_file,
        CloseHandle=lambda _handle: events.append("close") or 1,
        GetFileInformationByHandle=get_information,
        GetFileType=lambda _handle: _WINDOWS_FILE_TYPE_DISK,
    )
    monkeypatch.setattr(snapshot_module, "_windows_dll", lambda _name: kernel32)
    monkeypatch.setattr(
        windows_io,
        "_windows_delete_file_handle",
        lambda _kernel, _handle: events.append("delete"),
    )

    with pytest.raises(snapshot_module.NativePolicySnapshotError, match="path_invalid"):
        windows_io._windows_open_handle(Path("C:/Guard/new.tmp"), directory=False, create_new=True)

    assert events == ["delete", "close"]


def test_windows_existing_directory_reapplies_owner_and_dacl_on_same_handle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    descriptor = ctypes.c_void_p(17)
    dacl = ctypes.c_void_p(19)
    handle = object()
    events: list[tuple[str, object]] = []
    security_attributes_type = snapshot_module._windows_security_attributes_type()

    @contextmanager
    def private_descriptor(_directory: bool):
        yield object(), descriptor, dacl, "S-1-5-21-1"

    def create_directory(_path: str, _attributes: object) -> int:
        events.append(("create", "existing"))
        return 0

    def open_handle(
        path: Path,
        *,
        directory: bool,
        create_new: bool = False,
        descriptor: object | None = None,
        repair: bool = False,
        lock: bool = False,
        rename_source: bool = False,
        add_file: bool = False,
    ) -> tuple[object, object, object]:
        assert not rename_source
        _ = add_file
        events.append(("open", (path, directory, create_new, descriptor, repair, lock)))
        return object(), handle, object()

    monkeypatch.setattr(snapshot_module, "_windows_private_descriptor", private_descriptor)
    monkeypatch.setattr(snapshot_module, "_windows_security_attributes_type", lambda: security_attributes_type)
    monkeypatch.setattr(
        snapshot_module,
        "_windows_dll",
        lambda _name: types.SimpleNamespace(CreateDirectoryW=create_directory),
    )
    monkeypatch.setattr(snapshot_module, "_windows_open_handle", open_handle)
    monkeypatch.setattr(
        snapshot_module,
        "_windows_verify_private_owner",
        lambda verified_handle, *, owner_sid: events.append(("owner", (verified_handle, owner_sid))),
    )
    monkeypatch.setattr(
        snapshot_module,
        "_windows_apply_private_dacl",
        lambda _kernel, applied_handle, applied_descriptor, applied_dacl, directory: events.append(
            ("apply", (applied_handle, applied_descriptor, applied_dacl, directory))
        ),
    )
    monkeypatch.setattr(
        snapshot_module,
        "_windows_verify_private_dacl",
        lambda verified_handle, *, owner_sid, directory: events.append(
            ("verify", (verified_handle, owner_sid, directory))
        ),
    )
    monkeypatch.setattr(
        snapshot_module,
        "_windows_close_handle",
        lambda _kernel, closed_handle: events.append(("close", closed_handle)),
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: snapshot_module._WINDOWS_ERROR_ALREADY_EXISTS, raising=False)

    snapshot_module._windows_ensure_private_directory(tmp_path / "native-runtime")

    target_open = (
        "open",
        (tmp_path / "native-runtime", True, False, None, True, True),
    )
    assert target_open in events
    target_index = events.index(target_open)
    assert events[target_index + 1] == ("owner", (handle, "S-1-5-21-1"))
    assert events[target_index + 2] == ("apply", (handle, descriptor, dacl, True))
    assert events[target_index + 3] == ("verify", (handle, "S-1-5-21-1", True))
    assert events[target_index + 4] == ("close", handle)


def test_windows_private_descriptor_deduplicates_system_owner_ace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []

    def convert(
        sddl: str,
        _revision: int,
        descriptor_pointer: object,
        _size_pointer: object,
    ) -> int:
        captured.append(sddl)
        ctypes.cast(descriptor_pointer, ctypes.POINTER(ctypes.c_void_p)).contents.value = 17
        return 1

    def get_dacl(
        _descriptor: object,
        present_pointer: object,
        dacl_pointer: object,
        _defaulted_pointer: object,
    ) -> int:
        ctypes.cast(present_pointer, ctypes.POINTER(ctypes.c_int)).contents.value = 1
        ctypes.cast(dacl_pointer, ctypes.POINTER(ctypes.c_void_p)).contents.value = 19
        return 1

    advapi32 = types.SimpleNamespace(
        ConvertStringSecurityDescriptorToSecurityDescriptorW=convert,
        GetSecurityDescriptorDacl=get_dacl,
    )
    kernel32 = types.SimpleNamespace(LocalFree=lambda _value: None)
    monkeypatch.setattr(windows_support, "_windows_owner_sid", lambda: snapshot_module._WINDOWS_SYSTEM_SID)
    monkeypatch.setattr(windows_support, "_windows_dll", lambda name: advapi32 if name == "advapi32" else kernel32)

    with windows_support._windows_private_descriptor(True):
        pass

    assert captured == [
        "O:S-1-5-18D:P(A;OICI;FA;;;S-1-5-18)",
    ]
