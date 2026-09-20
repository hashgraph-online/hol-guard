from __future__ import annotations

import ctypes
import importlib.util
import json
import os
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.native_runtime.windows_atomic_replace_child import _NativeCalls
from codex_plugin_scanner.guard import windows_atomic_replace as probe
from codex_plugin_scanner.guard.daemon import manager

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "_original_windows_reader_control", _ROOT / "tests/test_windows_replaceable_reader_process.py"
)
assert _SPEC is not None and _SPEC.loader is not None
original = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(original)
_ORIGINAL_SAFE = original._safe_child_value
_CHILD = _ROOT / "ci/native_runtime/windows_atomic_replace_child.py"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Actual Windows product atomic replacement contract")


def _safe_native(value):
    keys = {
        "opens",
        "closes",
        "rename_calls",
        "rename_returned",
        "owned_handles_remaining",
        "first_failed_operation",
        "volume_queries",
        "volume_query_succeeded",
        "volume_flags",
    }
    if not isinstance(value, dict) or set(value) not in (keys, keys | {"writer_snapshot_taken"}):
        return False
    if any(
        type(value[name]) is not int or not 0 <= value[name] <= 8
        for name in keys - {"rename_returned", "first_failed_operation", "volume_query_succeeded", "volume_flags"}
    ):
        return False
    return (
        (value["volume_query_succeeded"] is None or type(value["volume_query_succeeded"]) is bool)
        and (
            value["volume_flags"] is None
            or (type(value["volume_flags"]) is int and 0 <= value["volume_flags"] <= 0xFFFFFFFF)
        )
        and type(value["rename_returned"]) is bool
        and value["first_failed_operation"] in (None, "parent_open", "source_open", "rename", "close")
        and ("writer_snapshot_taken" not in value or type(value["writer_snapshot_taken"]) is bool)
    )


def _safe_report(value, depth=0):
    if value == "rename_audit":
        return True
    if not isinstance(value, dict) or "probe" not in value:
        return _ORIGINAL_SAFE(value, depth)
    if not _safe_native(value["probe"]):
        return False
    report = {key: item for key, item in value.items() if key != "probe"}
    if report.get("operation") != "rename_audit":
        return _ORIGINAL_SAFE(report, depth)
    if set(report) != {"schema", "operation", "events", "refusal_same_object", "error"}:
        return False
    if report["schema"] != 1 or type(report["refusal_same_object"]) is not bool:
        return False
    if not _ORIGINAL_SAFE(report["error"], depth + 1):
        return False
    events = report["events"]
    if not isinstance(events, list) or len(events) > 4:
        return False
    return all(
        isinstance(event, dict)
        and set(event)
        == {
            "source_same",
            "destination_same",
            "source_dir_fd",
            "destination_dir_fd",
            "opens_before_event",
            "renames_before_event",
        }
        and type(event["source_same"]) is bool
        and type(event["destination_same"]) is bool
        and all(
            type(event[key]) is int and -1 <= event[key] <= 8
            for key in set(event) - {"source_same", "destination_same"}
        )
        for event in events
    )


@pytest.fixture
def probe_child(monkeypatch):
    monkeypatch.setattr(original, "_CHILD", _CHILD)
    monkeypatch.setattr(original, "_safe_child_value", _safe_report)


@pytest.mark.parametrize(
    "case", ["unheld", "missing", "crt_destination", "readonly_destination", "directory_destination"]
)
def test_actual_writer_matches_original_destination_outcomes(tmp_path, record_property, probe_child, case):
    results = []
    for candidate in (False, True):
        home = tmp_path / ("candidate" if candidate else "original")
        manager._ensure_private_directory(home)
        target = home / "daemon-auth-token"
        if case == "directory_destination":
            target.mkdir()
        elif case != "missing":
            manager._write_private_atomic_text(target, original._OLD)
        held = None
        if case == "crt_destination":
            held = os.open(target, os.O_RDONLY)
        if case == "readonly_destination":
            target.chmod(stat.S_IREAD)
        label = "candidate" if candidate else "original"
        try:
            extra = [] if candidate else ["--original-writer"]
            code, report = original._run_child(
                target, "--operation", "writer", *extra, record_property=record_property, label=label
            )
            assert isinstance(report, dict)
            record_property(f"{label}_writer_report", json.dumps(report, sort_keys=True))
            record_property(f"{label}_writer_exit_code", code)
            assert report["writer_calls"] == report["replace_calls"] == 1
            assert report["writer_locked"] and report["writer_fd_closed_before_replace"]
            assert report["temporary_siblings_removed"]
            assert report["original_exception_identity_preserved"]
            assert report["reference_writer"] is not candidate
            native = report["probe"]
            assert native["writer_snapshot_taken"] is candidate
            assert native["owned_handles_remaining"] == 0
            assert native["volume_queries"] == int(candidate)
            assert native["opens"] == native["closes"] == (2 if candidate else 0)
            assert native["rename_calls"] == int(candidate)
            if candidate:
                assert native["volume_query_succeeded"] is True and native["volume_flags"] & 0x400
            if case in ("unheld", "missing"):
                assert code == 0
                assert report["replace_returned"] and native["rename_returned"] is candidate
                assert report["error"] is None
                assert target.read_text(encoding="utf-8") == original._NEW
            else:
                assert code == 1
                assert report["replace_returned"] is native["rename_returned"] is False
                if case == "crt_destination":
                    # Each primitive exposes its actual OS error without translation.
                    assert report["error"] == {
                        "kind": "PermissionError",
                        "errno": 13,
                        "winerror": 32 if candidate else 5,
                    }
                else:
                    assert report["error"] == {"kind": "PermissionError", "errno": 13, "winerror": 5}
                if case == "directory_destination":
                    assert target.is_dir() and not list(target.iterdir())
                else:
                    assert target.read_text(encoding="utf-8") == original._OLD
            results.append(
                (code, {key: value for key, value in report.items() if key not in ("probe", "reference_writer")})
            )
        finally:
            if held is not None:
                os.close(held)
                record_property(f"{label}_destination_crt_reader_closed", True)
            if case == "readonly_destination":
                target.chmod(stat.S_IREAD | stat.S_IWRITE)
            record_property(f"{label}_temporary_siblings_removed", not list(home.glob(".daemon-auth-token.*")))
    record_property("original_candidate_exact_result_parity", results[0] == results[1])
    if case == "crt_destination":
        record_property("native_error_codes", json.dumps({"MoveFileExW": 5, "FileRenameInfoEx": 32}, sort_keys=True))
        comparable = []
        for code, result in results:
            error = {key: value for key, value in result["error"].items() if key != "winerror"}
            comparable.append((code, {**result, "error": error}))
        record_property("original_candidate_compatibility", comparable[0] == comparable[1])
        assert comparable[0] == comparable[1]
    else:
        assert results[0] == results[1]


@pytest.mark.parametrize("refuse", [False, True], ids=["observe", "refuse"])
def test_ex_rename_preserves_original_audit_boundary(tmp_path, record_property, probe_child, refuse):
    records = []
    for candidate in (False, True):
        home = tmp_path / ("candidate" if candidate else "original")
        home.mkdir()
        target = home / "authority"
        target.write_text(original._OLD, encoding="utf-8")
        source = home / ".rename-audit-source"
        source.write_text(original._NEW, encoding="utf-8")
        extra = ["--candidate"] if candidate else []
        if refuse:
            extra.append("--refuse")
        code, report = original._run_child(
            target,
            "--operation",
            "rename_audit",
            *extra,
            record_property=record_property,
            label="candidate" if candidate else "original",
        )
        record_property("candidate_report" if candidate else "original_report", json.dumps(report, sort_keys=True))
        assert code == 0 and isinstance(report, dict)
        records.append({key: value for key, value in report.items() if key != "probe"})
        assert report["probe"]["owned_handles_remaining"] == 0
        assert report["probe"]["rename_returned"] is (candidate and not refuse)
        assert report["probe"]["rename_calls"] == int(candidate and not refuse)
        assert report["probe"]["opens"] == report["probe"]["closes"] == (2 if candidate and not refuse else 0)
        assert source.exists() is refuse
        assert target.read_text(encoding="utf-8") == (original._OLD if refuse else original._NEW)
    assert records[0] == records[1]
    assert records[0]["events"] == [
        {
            "source_same": True,
            "destination_same": True,
            "source_dir_fd": -1,
            "destination_dir_fd": -1,
            "opens_before_event": 0,
            "renames_before_event": 0,
        }
    ]
    assert records[0]["refusal_same_object"] is refuse
    assert records[0]["error"] == ({"kind": "other", "errno": None, "winerror": None} if refuse else None)


@pytest.mark.parametrize("case", ["wrong_identity", "directory_source", "reparse_source"])
def test_ex_source_guards_reject_before_mutation(tmp_path, monkeypatch, record_property, case):
    target = tmp_path / "authority"
    target.write_text(original._OLD, encoding="utf-8")
    original_source = tmp_path / "original-source"
    original_source.write_text(original._NEW, encoding="utf-8")
    descriptor = os.open(original_source, os.O_RDONLY)
    try:
        expected = probe.snapshot_descriptor(descriptor)
    finally:
        os.close(descriptor)
    source = original_source
    if case == "wrong_identity":
        expected = replace(expected, index_low=expected.index_low ^ 1)
    elif case == "directory_source":
        source = tmp_path / "directory-source"
        source.mkdir()
    else:
        source = tmp_path / "reparse-source"
        source.symlink_to(original_source)
    native = _NativeCalls(probe._api())
    monkeypatch.setattr(probe, "_api", lambda: native)
    try:
        with pytest.raises(OSError):
            probe.replace_once(source, target, expected)
    finally:
        record_property("native_probe", json.dumps(native.report(), sort_keys=True))
    assert native.rename_calls == 0
    assert native.report()["owned_handles_remaining"] == 0
    assert target.read_text(encoding="utf-8") == original._OLD
    assert original_source.read_text(encoding="utf-8") == original._NEW


def test_native_report_keeps_committed_rename_separate_from_close_failure():
    native = _NativeCalls(
        SimpleNamespace(
            SetFileInformationByHandle=lambda *_arguments: 1,
            CloseHandle=lambda _handle: 0,
        )
    )
    native.handles.add(17)
    assert native.SetFileInformationByHandle(17, 22, None, 0) == 1
    assert native.CloseHandle(17) == 0
    report = native.report()
    assert report["rename_returned"] is True
    assert report["rename_calls"] == 1
    assert report["first_failed_operation"] == "close"
    assert report["owned_handles_remaining"] == 1


def test_ex_buffer_uses_absolute_name_null_root_and_sdk_layout():
    target = Path(r"C:\synthetic-parent\authority")
    buffer = probe._rename_buffer(target, 83)
    information = probe._RenameInfo.from_buffer(buffer)
    encoded = os.fspath(target).encode("utf-16-le", errors="surrogatepass")
    assert ctypes.sizeof(probe.wintypes.DWORD) == 4
    assert ctypes.sizeof(probe.wintypes.WCHAR) == 2
    assert ctypes.sizeof(probe.wintypes.HANDLE) == 8
    assert ctypes.sizeof(probe._RenameInfo) == 24
    assert probe._RenameInfo.Flags.offset == 0
    assert probe._RenameInfo.RootDirectory.offset == 8
    assert probe._RenameInfo.FileNameLength.offset == 16
    assert probe._RenameInfo.FileName.offset == 20
    assert information.Flags == 3 and information.RootDirectory is None
    assert information.FileNameLength == len(encoded)
    assert ctypes.sizeof(buffer) >= probe._RenameInfo.FileName.offset + len(encoded) + 2
    assert bytes(buffer)[20 : 20 + len(encoded)] == encoded
    assert bytes(buffer)[20 + len(encoded) : 22 + len(encoded)] == b"\0\0"


@pytest.mark.parametrize("refuse", [False, True], ids=["observe", "refuse"])
def test_actual_writer_keeps_original_single_audit_and_refusal(tmp_path, record_property, probe_child, refuse):
    records = []
    for candidate in (False, True):
        home = tmp_path / ("candidate" if candidate else "original")
        manager._ensure_private_directory(home)
        target = home / "daemon-auth-token"
        manager._write_private_atomic_text(target, original._OLD)
        extra = ["--candidate"] if candidate else []
        if refuse:
            extra.append("--refuse")
        label = "candidate" if candidate else "original"
        code, report = original._run_child(
            target, "--operation", "writer_audit", *extra, record_property=record_property, label=label
        )
        record_property(f"{label}_writer_report", json.dumps(report, sort_keys=True))
        assert isinstance(report, dict) and code == int(refuse)
        assert report["writer_calls"] == report["replace_calls"] == 1
        assert report["writer_locked"] and report["writer_fd_closed_before_replace"]
        assert report["original_exception_identity_preserved"]
        assert report["temporary_siblings_removed"]
        assert report["refusal_same_object"] is refuse
        assert report["audit_events"] == [
            {
                "source_same": True,
                "destination_same": True,
                "source_dir_fd": -1,
                "destination_dir_fd": -1,
                "opens_before_event": 0,
                "renames_before_event": 0,
            }
        ]
        native = report["probe"]
        assert native["volume_queries"] == int(candidate)
        assert native["opens"] == native["closes"] == (2 if candidate and not refuse else 0)
        assert native["rename_calls"] == int(candidate and not refuse)
        assert native["rename_returned"] is (candidate and not refuse)
        assert native["owned_handles_remaining"] == 0
        assert target.read_text(encoding="utf-8") == (original._OLD if refuse else original._NEW)
        records.append({key: value for key, value in report.items() if key not in ("probe", "reference_writer")})
    assert records[0] == records[1]
