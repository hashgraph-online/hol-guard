"""Native Windows handle tests for immutable skill-file hashing."""

from __future__ import annotations

import ctypes
import types
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import windows_paths as windows_paths_module


class _FakeWindowsFunction:
    def __init__(self, implementation: object) -> None:
        self._implementation = implementation

    def __call__(self, *arguments: object) -> object:
        assert callable(self._implementation)
        return self._implementation(*arguments)


def _fake_kernel32(
    *,
    attributes: int,
    create_arguments: list[tuple[object, ...]],
    closed_handles: list[object],
    create_handles: list[int] | None = None,
) -> object:
    def create_file(*arguments: object) -> int:
        create_arguments.append(arguments)
        return create_handles.pop(0) if create_handles else 71

    def get_information(_handle: object, information_pointer: ctypes.c_void_p) -> int:
        information = ctypes.cast(
            information_pointer,
            ctypes.POINTER(windows_paths_module._WindowsByHandleFileInformation),
        ).contents
        information.dwFileAttributes = attributes
        return 1

    def close_handle(handle: object) -> int:
        closed_handles.append(handle)
        return 1

    return types.SimpleNamespace(
        CreateFileW=_FakeWindowsFunction(create_file),
        GetFileInformationByHandle=_FakeWindowsFunction(get_information),
        CloseHandle=_FakeWindowsFunction(close_handle),
    )


def _configure_windows_api(
    monkeypatch: pytest.MonkeyPatch,
    *,
    attributes: int,
    open_osfhandle: object,
    create_arguments: list[tuple[object, ...]],
    closed_handles: list[object],
    create_handles: list[int] | None = None,
) -> None:
    kernel32 = _fake_kernel32(
        attributes=attributes,
        create_arguments=create_arguments,
        closed_handles=closed_handles,
        create_handles=create_handles,
    )
    fake_msvcrt = types.SimpleNamespace(open_osfhandle=open_osfhandle)
    monkeypatch.setattr(windows_paths_module.os, "name", "nt")
    monkeypatch.setattr(
        windows_paths_module.ctypes,
        "WinDLL",
        lambda *_args, **_kwargs: kernel32,
        raising=False,
    )
    monkeypatch.setattr(windows_paths_module.importlib, "import_module", lambda _name: fake_msvcrt)


def test_windows_locked_descriptor_excludes_write_and_delete_sharing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("C:/Guard/SKILL.md")
    create_arguments: list[tuple[object, ...]] = []
    closed_handles: list[object] = []
    converted_handles: list[int] = []

    def open_osfhandle(handle: int, _flags: int) -> int:
        converted_handles.append(handle)
        return 83

    _configure_windows_api(
        monkeypatch,
        attributes=0x20,
        open_osfhandle=open_osfhandle,
        create_arguments=create_arguments,
        closed_handles=closed_handles,
    )

    descriptor = windows_paths_module.open_windows_locked_regular_descriptor(path)

    assert descriptor == 83
    assert converted_handles == [71]
    assert closed_handles == []
    desired_access = create_arguments[0][1]
    share_mode = create_arguments[0][2]
    flags = create_arguments[0][5]
    assert isinstance(desired_access, int)
    assert isinstance(share_mode, int)
    assert isinstance(flags, int)
    assert desired_access == windows_paths_module._WINDOWS_GENERIC_READ
    assert share_mode == windows_paths_module._WINDOWS_FILE_SHARE_READ
    assert not share_mode & 0x2
    assert not share_mode & 0x4
    assert flags & windows_paths_module._WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT


def test_windows_locked_descriptor_rejects_reparse_and_closes_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("C:/Guard/SKILL.md")
    create_arguments: list[tuple[object, ...]] = []
    closed_handles: list[object] = []

    def forbidden_conversion(_handle: int, _flags: int) -> int:
        raise AssertionError("a reparse point must not become a CRT descriptor")

    _configure_windows_api(
        monkeypatch,
        attributes=windows_paths_module._FILE_ATTRIBUTE_REPARSE_POINT,
        open_osfhandle=forbidden_conversion,
        create_arguments=create_arguments,
        closed_handles=closed_handles,
    )

    with pytest.raises(OSError, match="windows_locked_file_not_regular"):
        windows_paths_module.open_windows_locked_regular_descriptor(path)

    assert closed_handles == [71]


def test_windows_locked_descriptor_closes_handle_when_conversion_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("C:/Guard/SKILL.md")
    create_arguments: list[tuple[object, ...]] = []
    closed_handles: list[object] = []

    def failed_conversion(_handle: int, _flags: int) -> int:
        raise OSError("conversion failed")

    _configure_windows_api(
        monkeypatch,
        attributes=0x20,
        open_osfhandle=failed_conversion,
        create_arguments=create_arguments,
        closed_handles=closed_handles,
    )

    with pytest.raises(OSError, match="conversion failed"):
        windows_paths_module.open_windows_locked_regular_descriptor(path)

    assert closed_handles == [71]


def test_windows_locked_descriptor_retries_transient_sharing_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("C:/Guard/SKILL.md")
    create_arguments: list[tuple[object, ...]] = []
    closed_handles: list[object] = []
    retry_delays: list[float] = []
    invalid_handle = ctypes.c_void_p(-1).value
    assert isinstance(invalid_handle, int)
    _configure_windows_api(
        monkeypatch,
        attributes=0x20,
        open_osfhandle=lambda _handle, _flags: 83,
        create_arguments=create_arguments,
        closed_handles=closed_handles,
        create_handles=[invalid_handle, 71],
    )
    monkeypatch.setattr(windows_paths_module.ctypes, "get_last_error", lambda: 32, raising=False)
    monkeypatch.setattr(windows_paths_module.time, "sleep", retry_delays.append)

    assert windows_paths_module.open_windows_locked_regular_descriptor(path) == 83
    assert len(create_arguments) == 2
    assert retry_delays == [windows_paths_module._WINDOWS_LOCK_RETRY_SECONDS]
    assert closed_handles == []
