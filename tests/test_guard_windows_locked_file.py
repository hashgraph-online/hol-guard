"""Native Windows handle tests for immutable skill-file hashing."""

from __future__ import annotations

import ctypes
import types
from pathlib import Path
from typing import Protocol

import pytest

from codex_plugin_scanner.guard import windows_paths as windows_paths_module


class _FakeWindowsFunction:
    def __init__(self, implementation: object) -> None:
        self._implementation = implementation

    def __call__(self, *arguments: object) -> object:
        assert callable(self._implementation)
        return self._implementation(*arguments)


class _UnicodeOutputBuffer(Protocol):
    value: str


def _fake_kernel32(
    *,
    attributes: int,
    create_arguments: list[tuple[object, ...]],
    closed_handles: list[object],
    create_handles: list[int] | None = None,
    final_path: str | None = None,
    final_path_length: int | None = None,
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

    def get_final_path(_handle: object, buffer: _UnicodeOutputBuffer, _length: int, flags: int) -> int:
        assert flags == 0
        buffer.value = final_path or ""
        return final_path_length if final_path_length is not None else len(final_path or "")

    return types.SimpleNamespace(
        CreateFileW=_FakeWindowsFunction(create_file),
        GetFileInformationByHandle=_FakeWindowsFunction(get_information),
        GetFinalPathNameByHandleW=_FakeWindowsFunction(get_final_path),
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
    final_path: str | None = None,
    final_path_length: int | None = None,
) -> None:
    kernel32 = _fake_kernel32(
        attributes=attributes,
        create_arguments=create_arguments,
        closed_handles=closed_handles,
        create_handles=create_handles,
        final_path=final_path,
        final_path_length=final_path_length,
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


@pytest.mark.parametrize(
    ("expected", "actual"),
    [
        (r"C:\Guard\config.toml", r"\\?\C:\Guard\config.toml"),
        (r"\\server\share\Guard\config.toml", r"\\?\UNC\server\share\Guard\config.toml"),
    ],
)
def test_windows_locked_descriptor_binds_canonical_drive_and_unc_paths(
    monkeypatch: pytest.MonkeyPatch, expected: str, actual: str
) -> None:
    closed_handles: list[object] = []
    _configure_windows_api(
        monkeypatch,
        attributes=0x20,
        open_osfhandle=lambda _handle, _flags: 83,
        create_arguments=[],
        closed_handles=closed_handles,
        final_path=actual,
    )

    assert windows_paths_module.open_windows_locked_regular_descriptor(expected, expected_resolved_path=expected) == 83
    assert closed_handles == []


@pytest.mark.parametrize(
    "actual",
    [
        r"\\?\C:\attacker\config.toml",
        r"\\?\C:\Guard-other\config.toml",
        r"\\?\C:\Guard\CONFIG.toml",
    ],
)
def test_windows_locked_descriptor_rejects_wrong_physical_path_before_descriptor_conversion(
    monkeypatch: pytest.MonkeyPatch, actual: str
) -> None:
    closed_handles: list[object] = []

    def forbidden_conversion(_handle: int, _flags: int) -> int:
        raise AssertionError("a differently resolved file must not become a descriptor")

    _configure_windows_api(
        monkeypatch,
        attributes=0x20,
        open_osfhandle=forbidden_conversion,
        create_arguments=[],
        closed_handles=closed_handles,
        final_path=actual,
    )

    with pytest.raises(OSError, match="windows_locked_file_path_changed"):
        windows_paths_module.open_windows_locked_regular_descriptor(
            r"C:\Guard\config.toml", expected_resolved_path=r"C:\Guard\config.toml"
        )
    assert closed_handles == [71]


@pytest.mark.parametrize("length", [0, windows_paths_module._WINDOWS_PATH_BUFFER_SIZE])
def test_windows_locked_descriptor_rejects_failed_or_truncated_final_path(
    monkeypatch: pytest.MonkeyPatch, length: int
) -> None:
    closed_handles: list[object] = []
    _configure_windows_api(
        monkeypatch,
        attributes=0x20,
        open_osfhandle=lambda _handle, _flags: 83,
        create_arguments=[],
        closed_handles=closed_handles,
        final_path_length=length,
    )

    with pytest.raises(OSError, match="windows_locked_file_final_path_unavailable"):
        windows_paths_module.open_windows_locked_regular_descriptor(
            r"C:\Guard\config.toml", expected_resolved_path=r"C:\Guard\config.toml"
        )
    assert closed_handles == [71]
