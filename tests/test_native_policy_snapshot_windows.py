"""Windows ACL and handle-contract tests for native snapshots."""

from __future__ import annotations

import ctypes
import types
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot as snapshot_module

from .native_policy_snapshot_test_fixtures import _fake_windows_snapshot_kernel

__test__ = False


def test_windows_cache_reader_verifies_and_reads_one_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel32, information, closed = _fake_windows_snapshot_kernel(b"signed-cache")
    opened: list[object] = []
    verified: list[object] = []

    def open_handle(*_args: object, **_kwargs: object) -> tuple[object, object, object]:
        handle = object()
        opened.append(handle)
        return kernel32, handle, information

    monkeypatch.setattr(snapshot_module, "_windows_open_handle", open_handle)
    monkeypatch.setattr(snapshot_module, "_windows_owner_sid", lambda: "S-1-5-21-1")
    monkeypatch.setattr(
        snapshot_module,
        "_windows_verify_private_dacl",
        lambda handle, *, owner_sid, directory: verified.append((handle, owner_sid, directory)),
    )
    monkeypatch.setattr(
        snapshot_module,
        "_windows_close_handle",
        lambda _kernel, handle: closed.append(handle),
    )

    payload = snapshot_module._windows_read_snapshot_bytes(Path("C:/Guard/snapshot.json"))

    assert payload == b"signed-cache"
    assert len(opened) == 1
    assert verified == [(opened[0], "S-1-5-21-1", False)]
    assert closed == [opened[0]]


@pytest.mark.parametrize(
    ("failure", "reported_size", "read_result"),
    (
        ("acl", None, True),
        ("short", len(b"short") + 1, True),
        ("oversize", snapshot_module.POLICY_SNAPSHOT_MAX_BYTES + 1, True),
        ("read", None, False),
    ),
)
def test_windows_cache_reader_closes_handle_on_all_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    reported_size: int | None,
    read_result: bool,
) -> None:
    data = b"short" if failure == "short" else b"signed-cache"
    kernel32, information, closed = _fake_windows_snapshot_kernel(
        data,
        reported_size=reported_size,
        read_result=read_result,
    )
    handle = object()
    monkeypatch.setattr(
        snapshot_module,
        "_windows_open_handle",
        lambda *_args, **_kwargs: (kernel32, handle, information),
    )
    monkeypatch.setattr(snapshot_module, "_windows_owner_sid", lambda: "S-1-5-21-1")
    if failure == "acl":
        monkeypatch.setattr(
            snapshot_module,
            "_windows_verify_private_dacl",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                snapshot_module.NativePolicySnapshotError("native_policy_windows_acl_not_private")
            ),
        )
    else:
        monkeypatch.setattr(snapshot_module, "_windows_verify_private_dacl", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        snapshot_module,
        "_windows_close_handle",
        lambda _kernel, closed_handle: closed.append(closed_handle),
    )

    with pytest.raises(snapshot_module.NativePolicySnapshotError):
        snapshot_module._windows_read_snapshot_bytes(Path("C:/Guard/snapshot.json"))
    assert closed == [handle]


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


def test_windows_cache_read_rejects_ancestor_reparse_before_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(snapshot_module.os, "name", "nt")
    monkeypatch.setattr(snapshot_module, "_windows_path_has_reparse_component", lambda _path: True)
    monkeypatch.setattr(
        snapshot_module,
        "_windows_read_snapshot_bytes",
        lambda _path: (_ for _ in ()).throw(AssertionError("reparse path must not open")),
    )

    with pytest.raises(snapshot_module.NativePolicySnapshotError, match="cache_invalid"):
        snapshot_module._read_v3_snapshot_file(Path("C:/Guard/snapshot.json"))
