"""Windows ACL and handle-contract tests for native snapshots."""

from __future__ import annotations

import ctypes
import inspect
import types
from contextlib import contextmanager
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot as snapshot_module
import codex_plugin_scanner.guard.native_policy_snapshot_storage as storage_module
import codex_plugin_scanner.guard.native_policy_snapshot_windows_acl as windows_acl
import codex_plugin_scanner.guard.native_policy_snapshot_windows_atomic as windows_atomic
import codex_plugin_scanner.guard.native_policy_snapshot_windows_state as windows_state
import codex_plugin_scanner.guard.native_policy_snapshot_windows_support as windows_support

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
    set_security_arguments: list[tuple[object, ...]] = []
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

    def set_security_info(*arguments: object) -> int:
        set_security_arguments.append(arguments)
        return 0

    kernel32 = types.SimpleNamespace(
        CreateFileW=create_file,
        CloseHandle=close_handle,
        GetFileInformationByHandle=get_information,
        GetFileType=lambda _handle: snapshot_module._WINDOWS_FILE_TYPE_DISK,
    )
    advapi32 = types.SimpleNamespace(SetSecurityInfo=set_security_info)
    monkeypatch.setattr(
        snapshot_module,
        "_windows_dll",
        lambda name: advapi32 if name == "advapi32" else kernel32,
    )

    opened = snapshot_module._windows_open_handle(Path("C:/Guard/snapshot.json"), directory=False)

    assert getattr(opened[1], "value", opened[1]) == 71
    assert create_arguments[0][1] == snapshot_module._WINDOWS_GENERIC_READ
    assert create_arguments[0][2] == snapshot_module._WINDOWS_FILE_SHARE_READ
    assert create_arguments[0][5] & snapshot_module._WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    snapshot_module._windows_close_handle(*opened[:2])

    descriptor = ctypes.c_void_p(17)
    dacl = ctypes.c_void_p(19)
    hardened = snapshot_module._windows_open_handle(
        Path("C:/Guard/snapshot.json"),
        directory=False,
        share_write=True,
        descriptor=descriptor,
    )
    assert create_arguments[1][1] == snapshot_module._WINDOWS_GENERIC_READ | snapshot_module._WINDOWS_WRITE_DAC
    assert create_arguments[1][1] & snapshot_module._WINDOWS_WRITE_OWNER == 0
    assert create_arguments[1][2] == (
        snapshot_module._WINDOWS_FILE_SHARE_READ | snapshot_module._WINDOWS_FILE_SHARE_WRITE
    )
    snapshot_module._windows_apply_private_dacl(
        hardened[0],
        hardened[1],
        descriptor,
        dacl,
        False,
    )
    assert set_security_arguments[0][2] == snapshot_module._WINDOWS_SECURITY_INFORMATION
    assert set_security_arguments[0][3] is None
    assert getattr(set_security_arguments[0][5], "value", set_security_arguments[0][5]) == 19
    snapshot_module._windows_close_handle(*hardened[:2])

    assert [getattr(handle, "value", handle) for handle in closed] == [71, 71]


def test_windows_existing_directory_reapplies_private_dacl_on_same_handle(
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
    ) -> tuple[object, object, object]:
        assert not rename_source
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

    assert events[0] == ("create", "existing")
    target_open = ("open", (tmp_path / "native-runtime", True, False, None, True, True))
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
    assert windows_acl._windows_owner_is_trusted("S-1-5-21-1", "S-1-5-21-1")
    assert windows_acl._windows_owner_is_trusted(snapshot_module._WINDOWS_SYSTEM_SID, "S-1-5-21-1")
    assert windows_acl._windows_owner_is_trusted("S-1-5-32-544", "S-1-5-21-1")
    assert not windows_acl._windows_owner_is_trusted("S-1-5-21-2", "S-1-5-21-1")


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


def test_windows_directory_binding_fails_closed_on_reparse_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = snapshot_module.NativePolicySnapshotError("native_policy_windows_path_invalid")
    api = types.SimpleNamespace(
        _windows_open_handle=lambda *_args, **_kwargs: (_ for _ in ()).throw(expected),
    )
    monkeypatch.setattr(windows_state, "_windows_create_directory", lambda *_args: False)

    with pytest.raises(snapshot_module.NativePolicySnapshotError, match="path_invalid"):
        windows_state._windows_bind_directory_component(
            Path("C:/Guard/foreign-parent"),
            api=api,
            descriptor=object(),
            dacl=object(),
            owner_sid="S-1-5-21-1",
            private=False,
        )


def test_windows_commit_rejects_foreign_owner_before_acl_or_rename(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_handle = object()
    target_handle = object()
    events: list[str] = []

    def verify_dacl(handle: object, *, owner_sid: str, directory: bool) -> None:
        del owner_sid, directory
        events.append("verify-dacl-source" if handle is source_handle else "verify-dacl-target")

    def reject_foreign_owner(_handle: object, *, owner_sid: str) -> None:
        del owner_sid
        events.append("verify-owner")
        raise snapshot_module.NativePolicySnapshotError("foreign-owner")

    api = types.SimpleNamespace(
        _windows_verify_private_dacl=verify_dacl,
        _windows_open_handle=lambda *_args, **_kwargs: (object(), target_handle, types.SimpleNamespace()),
        _windows_verify_private_owner=reject_foreign_owner,
        _windows_apply_private_dacl=lambda *_args: events.append("apply-dacl"),
        _windows_close_handle=lambda *_args: events.append("close-target"),
    )
    monkeypatch.setattr(
        windows_atomic,
        "_windows_rename_file_handle",
        lambda *_args: events.append("rename"),
    )

    with pytest.raises(snapshot_module.NativePolicySnapshotError, match="foreign-owner"):
        windows_atomic._windows_commit_private_file_handle(
            api=api,
            kernel32=object(),
            source_handle=source_handle,
            source_information=types.SimpleNamespace(),
            parent_path=Path("C:/Guard"),
            parent_handle=object(),
            destination_name="target-state",
            descriptor=object(),
            dacl=object(),
            owner_sid="S-1-5-21-1",
            kind="cache",
        )

    assert events == ["verify-dacl-source", "verify-owner", "close-target"]


def test_windows_storage_writer_has_no_path_replace_in_native_branch() -> None:
    source = inspect.getsource(storage_module._write_v3_snapshot_file)
    native_branch = source.split('if os.name == "nt":', maxsplit=1)[1].split("return payload", maxsplit=1)[0]
    assert "os.replace" not in native_branch
    assert "_windows_write_private_file_atomic" in native_branch


def test_windows_atomic_writer_cleans_temp_on_precommit_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    deleted: list[tuple[object, object]] = []
    closed: list[tuple[object, object]] = []
    kernel32 = object()
    handle = object()

    @contextmanager
    def private_descriptor(_directory: bool):
        yield object(), object(), object(), "S-1-5-21-1"

    def reject_acl(*_args: object, **_kwargs: object) -> None:
        raise snapshot_module.NativePolicySnapshotError("acl-failure")

    monkeypatch.setattr(snapshot_module, "_windows_private_descriptor", private_descriptor)
    monkeypatch.setattr(
        snapshot_module,
        "_windows_open_handle",
        lambda *_args, **_kwargs: (kernel32, handle, types.SimpleNamespace()),
    )
    monkeypatch.setattr(snapshot_module, "_windows_verify_private_dacl", reject_acl)
    monkeypatch.setattr(
        windows_atomic,
        "_windows_delete_file_handle",
        lambda kernel, temporary: deleted.append((kernel, temporary)),
    )
    monkeypatch.setattr(
        snapshot_module,
        "_windows_close_handle",
        lambda kernel, temporary: closed.append((kernel, temporary)),
    )

    with pytest.raises(snapshot_module.NativePolicySnapshotError, match="acl-failure"):
        windows_atomic._windows_write_private_file_atomic(
            parent_path=tmp_path,
            parent_handle=object(),
            temporary_name=".snapshot.tmp",
            destination_name="snapshot.json",
            payload=b"payload",
            maximum_bytes=1024,
            kind="cache",
        )

    assert deleted == [(kernel32, handle)]
    assert closed == [(kernel32, handle)]
