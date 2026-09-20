from __future__ import annotations

import ctypes
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import windows_atomic_replace as subject
from codex_plugin_scanner.guard import windows_replaceable_file as reader
from codex_plugin_scanner.guard.daemon import manager


@pytest.fixture
def admission(monkeypatch, tmp_path):
    calls: list[tuple[Any, ...]] = []
    state = SimpleNamespace(succeeded=True, flags=0x400)
    information = SimpleNamespace(
        dwVolumeSerialNumber=7,
        nFileIndexHigh=8,
        nFileIndexLow=9,
        nFileSizeHigh=0,
        nFileSizeLow=31,
    )

    def volume(handle, name, size, serial, maximum, flags, filesystem, filesystem_size):
        calls.append(("volume", handle, name, size, serial, maximum, filesystem, filesystem_size))
        ctypes.cast(flags, ctypes.POINTER(subject.wintypes.DWORD)).contents.value = state.flags
        return int(state.succeeded)

    def metadata(api, handle, **arguments):
        calls.append(("metadata", handle, arguments))
        return information

    api = SimpleNamespace(GetVolumeInformationByHandleW=volume)
    monkeypatch.setattr(subject, "os", SimpleNamespace(name="nt", fspath=os.fspath))
    monkeypatch.setattr(
        subject, "sys", SimpleNamespace(getwindowsversion=lambda: SimpleNamespace(major=10, minor=0, build=14393))
    )
    monkeypatch.setattr(
        subject,
        "importlib",
        SimpleNamespace(import_module=lambda _name: SimpleNamespace(get_osfhandle=lambda descriptor: descriptor + 100)),
    )
    monkeypatch.setattr(subject, "_api", lambda: api)
    monkeypatch.setattr(subject, "_information", metadata)
    return tmp_path / "source", tmp_path / "destination", state, calls


@pytest.mark.parametrize("flags", [0x400, 0x100400], ids=["posix-only", "combined-volume-flags"])
def test_positive_admission_uses_the_original_descriptor_filesystem(admission, flags):
    source, destination, state, calls = admission
    state.flags = flags
    assert subject.prepare_replace(17, source, destination) == subject.SourceIdentity(7, 8, 9, 0, 31)
    assert calls == [
        ("volume", 117, None, 0, None, None, None, 0),
        ("metadata", 117, {"directory": False, "source": str(source), "destination": str(destination)}),
    ]


@pytest.mark.parametrize(
    "case",
    [
        "other-platform",
        "missing-version",
        "old-os",
        "version-error",
        "missing-api",
        "volume-unavailable",
        "flag-absent",
        "relative-path",
    ],
)
def test_unavailable_or_unsupported_admission_selects_no_ex_operation(admission, monkeypatch, case):
    source, destination, state, calls = admission

    def unavailable_version():
        raise OSError("synthetic version unavailable")

    def unavailable_api():
        raise AttributeError("synthetic API unavailable")

    if case == "other-platform":
        monkeypatch.setattr(subject, "os", SimpleNamespace(name="posix"))
    elif case == "missing-version":
        monkeypatch.setattr(subject, "sys", SimpleNamespace())
    elif case == "old-os":
        monkeypatch.setattr(subject.sys, "getwindowsversion", lambda: SimpleNamespace(major=10, minor=0, build=14392))
    elif case == "version-error":
        monkeypatch.setattr(subject.sys, "getwindowsversion", unavailable_version)
    elif case == "missing-api":
        monkeypatch.setattr(subject, "_api", unavailable_api)
    elif case == "volume-unavailable":
        state.succeeded = False
    elif case == "flag-absent":
        state.flags = 0x200
    else:
        source = Path("relative-source")
    assert subject.prepare_replace(17, source, destination) is None
    expected = [("volume", 117, None, 0, None, None, None, 0)] if case in ("volume-unavailable", "flag-absent") else []
    assert calls == expected


@pytest.mark.parametrize("selected", ["legacy", "ex"])
def test_preselected_operation_runs_once_after_the_original_close(monkeypatch, tmp_path, selected):
    source, target = tmp_path / "source", tmp_path / "destination"
    identity = subject.SourceIdentity(1, 2, 3, 0, 4)
    calls = []
    monkeypatch.setattr(subject, "prepare_replace", lambda *args: identity if selected == "ex" else None)
    monkeypatch.setattr(subject, "replace_once", lambda *args: calls.append(("ex", *args)))
    subject.replace_temporary_descriptor(
        71,
        source,
        target,
        close_descriptor=lambda fd: calls.append(("close", fd)),
        legacy_replace=lambda *args: calls.append(("legacy", *args)),
    )
    expected = ("ex", source, target, identity) if selected == "ex" else ("legacy", source, target)
    assert calls == [("close", 71), expected]


@pytest.mark.parametrize("selected", ["legacy", "ex"])
@pytest.mark.parametrize("kind", [OSError, KeyboardInterrupt], ids=["os-error", "base-exception"])
def test_selected_operation_failure_is_identical_and_never_retried(monkeypatch, tmp_path, selected, kind):
    source, target = tmp_path / "source", tmp_path / "destination"
    identity = subject.SourceIdentity(1, 2, 3, 0, 4)
    failure = kind("synthetic original mutation failure")
    calls = []

    def failed(*arguments):
        calls.append(("mutation", *arguments))
        raise failure

    def forbidden(*_arguments):
        raise AssertionError("second mutation was attempted")

    monkeypatch.setattr(subject, "prepare_replace", lambda *args: identity if selected == "ex" else None)
    monkeypatch.setattr(subject, "replace_once", failed if selected == "ex" else forbidden)
    with pytest.raises(kind) as caught:
        subject.replace_temporary_descriptor(
            71,
            source,
            target,
            close_descriptor=lambda fd: calls.append(("close", fd)),
            legacy_replace=failed if selected == "legacy" else forbidden,
        )
    assert caught.value is failure
    expected = ("mutation", source, target, identity) if selected == "ex" else ("mutation", source, target)
    assert calls == [("close", 71), expected]


@pytest.mark.parametrize("secondary_close_failure", [False, True])
def test_preparation_failure_closes_owned_descriptor_once_and_preserves_primary(
    monkeypatch, tmp_path, secondary_close_failure
):
    failure = OSError("synthetic bound metadata failure")
    calls = []

    def prepare(*_arguments):
        calls.append("prepare")
        raise failure

    def close(fd):
        calls.append(("close", fd))
        if secondary_close_failure:
            raise RuntimeError("synthetic close failure")

    monkeypatch.setattr(subject, "prepare_replace", prepare)
    monkeypatch.setattr(subject, "replace_once", lambda *_args: calls.append("unexpected-ex"))
    with pytest.raises(OSError) as caught:
        subject.replace_temporary_descriptor(
            71,
            tmp_path / "source",
            tmp_path / "destination",
            close_descriptor=close,
            legacy_replace=lambda *_args: calls.append("unexpected-legacy"),
        )
    assert caught.value is failure
    assert calls == ["prepare", ("close", 71)]


def test_failed_close_stops_the_preselected_mutation_without_retry(monkeypatch, tmp_path):
    failure = OSError("synthetic close failure")
    calls = []

    def close(fd):
        calls.append(("close", fd))
        raise failure

    monkeypatch.setattr(subject, "prepare_replace", lambda *_args: None)
    with pytest.raises(OSError) as caught:
        subject.replace_temporary_descriptor(
            71,
            tmp_path / "source",
            tmp_path / "destination",
            close_descriptor=close,
            legacy_replace=lambda *_args: calls.append("unexpected"),
        )
    assert caught.value is failure and calls == [("close", 71)]


class _AbsentNotesError(RuntimeError):
    def __getattribute__(self, name: str) -> Any:
        if name == "add_note":
            raise AttributeError(name)
        return super().__getattribute__(name)


class _FailedNotesError(RuntimeError):
    def add_note(self, _note: str) -> None:
        raise KeyboardInterrupt("synthetic note attachment failure")


@pytest.mark.parametrize("kind", [RuntimeError, _AbsentNotesError, _FailedNotesError])
def test_cleanup_note_is_optional_and_never_replaces_primary(kind):
    failure = kind("synthetic primary")
    reader._note_cleanup_failure(failure, "synthetic_cleanup_failure")
    assert str(failure) == "synthetic primary"


def test_reader_primary_os_error_survives_native_close_error(monkeypatch):
    failure = OSError("synthetic original metadata failure")
    secondary = OSError("synthetic native close failure")
    errors = iter((failure, secondary))
    closes = []
    api = SimpleNamespace(
        CreateFileW=lambda *_args: 71,
        GetFileInformationByHandle=lambda *_args: 0,
        CloseHandle=lambda handle: closes.append(handle) or 0,
    )
    monkeypatch.setattr(reader, "_descriptor_flags", lambda _flags: 0)
    monkeypatch.setattr(reader, "_file_api", lambda: api)
    monkeypatch.setattr(reader, "_windows_error", lambda: next(errors))
    with pytest.raises(OSError) as caught:
        reader._open_descriptor("synthetic-authority", 0)
    assert caught.value is failure and closes == [71]


@pytest.mark.parametrize("kind", [RuntimeError, _AbsentNotesError, _FailedNotesError])
def test_writer_primary_error_survives_each_native_close_error(monkeypatch, tmp_path, kind):
    failure = kind("synthetic original source check")
    calls = []
    identity = subject.SourceIdentity(1, 2, 3, 0, 4)
    api = SimpleNamespace(CloseHandle=lambda handle: calls.append(("close", handle)) or 0)

    def metadata(_api, _handle, *, directory, **_arguments):
        if directory:
            return SimpleNamespace(dwVolumeSerialNumber=1)
        raise failure

    monkeypatch.setattr(subject, "_names", lambda *_args: ("synthetic-source", "synthetic-target"))
    monkeypatch.setattr(subject, "sys", SimpleNamespace(audit=lambda *_args: calls.append(("audit",))))
    monkeypatch.setattr(subject, "_api", lambda: api)
    handles = iter((81, 82))
    monkeypatch.setattr(subject, "_open", lambda *_args: next(handles))
    monkeypatch.setattr(subject, "_information", metadata)
    monkeypatch.setattr(subject, "_error", lambda *_args: OSError("synthetic cleanup"))
    with pytest.raises(kind) as caught:
        subject.replace_once(tmp_path / "source", tmp_path / "target", identity)
    assert caught.value is failure and calls == [("audit",), ("close", 82), ("close", 81)]


def test_actual_writer_resolves_legacy_facade_after_close_rebind(monkeypatch, tmp_path):
    calls = []

    class WriterOs:
        name = "nt"

        def __getattr__(self, name):
            return getattr(os, name)

        def __init__(self):
            self.replace: Any = self.stale_replace

        def close(self, descriptor):
            calls.append("close")
            os.close(descriptor)
            self.replace = self.rebound_replace

        def stale_replace(self, _source: Path, _target: Path) -> None:
            raise AssertionError("captured stale replacement facade")

        def rebound_replace(self, source, target):
            calls.append("rebound-replace")
            os.replace(source, target)

    monkeypatch.setattr(manager, "os", cast(Any, WriterOs()))
    monkeypatch.setattr(subject, "prepare_replace", lambda *_args: None)
    target = tmp_path / "authority"
    manager._write_private_atomic_text(target, "synthetic-value")
    assert calls == ["close", "rebound-replace"]
    assert target.read_text(encoding="utf-8") == "synthetic-value"
    assert not list(tmp_path.glob(".authority.*"))
