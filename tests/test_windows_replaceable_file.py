from __future__ import annotations

import ctypes
import importlib.util
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import windows_replaceable_file as reader


class _WindowsOs:
    name = "nt"
    O_BINARY = 0x8000
    O_TEXT = 0x4000
    O_NOINHERIT = 0x80

    def __getattr__(self, name):
        return getattr(os, name)


class _Api:
    def __init__(self):
        self.handle = 41
        self.attributes = 0
        self.information_success = True
        self.file_type = 1
        self.close_success = True
        self.operations = []

    def CreateFileW(self, *arguments):  # noqa: N802 - actual Win32 API spelling
        self.operations.append(("open", arguments))
        return self.handle

    def GetFileInformationByHandle(self, handle, pointer):  # noqa: N802 - actual Win32 API spelling
        self.operations.append(("information", handle))
        information = ctypes.cast(
            pointer,
            ctypes.POINTER(reader._WindowsByHandleFileInformation),
        ).contents
        information.dwFileAttributes = self.attributes
        return self.information_success

    def GetFileType(self, handle):  # noqa: N802 - actual Win32 API spelling
        self.operations.append(("type", handle))
        return self.file_type

    def CloseHandle(self, handle):  # noqa: N802 - actual Win32 API spelling
        self.operations.append(("close", handle))
        return self.close_success


@pytest.fixture
def native_open(monkeypatch):
    api = _Api()
    events = []
    transfers = []
    error = PermissionError(13, "synthetic native failure")
    error.winerror = 32
    monkeypatch.setattr(reader, "os", _WindowsOs())
    monkeypatch.setattr(reader, "sys", SimpleNamespace(audit=lambda *args: events.append(args)))
    monkeypatch.setattr(reader, "_file_api", lambda: api)
    monkeypatch.setattr(reader, "_default_translation_mode", lambda: 0x4000)
    monkeypatch.setattr(reader, "_windows_error", lambda: error)
    monkeypatch.setattr(reader.ctypes, "set_last_error", lambda code: None, raising=False)

    def transfer(handle, flags):
        transfers.append((handle, flags))
        return 73

    monkeypatch.setattr(reader, "_transfer_descriptor", transfer)
    return api, events, transfers, error


def test_read_access_full_sharing_existing_noninheritable_open(native_open):
    api, events, transfers, _error = native_open
    target = Path("synthetic-authority")
    descriptor = reader.open_replaceable_read_descriptor(target, os.O_RDONLY)
    assert descriptor == 73
    assert events == [("open", str(target), None, os.O_RDONLY | 0x80)]
    assert api.operations == [
        ("open", (str(target), 0x80000000, 7, None, 3, 0x00200000, None)),
        ("information", 41),
        ("type", 41),
    ]
    assert transfers == [(41, 0x4080)]


def test_text_callback_leaves_single_event_to_fileio(native_open):
    api, events, transfers, _error = native_open
    assert reader._text_opener("synthetic-authority", 0x8080) == 73
    assert events == []
    assert transfers == [(41, 0x8080)]
    assert ("close", 41) not in api.operations


@pytest.mark.parametrize(
    "flags",
    [os.O_WRONLY, os.O_RDWR, os.O_CREAT, os.O_TRUNC, os.O_APPEND, 0x40, 0x4000],
    ids=["write", "read_write", "create", "truncate", "append", "delete_on_close", "text_mode"],
)
def test_unsafe_flags_fail_before_audit_or_open(native_open, flags):
    api, events, transfers, _error = native_open
    with pytest.raises(ValueError, match="must_be_read_only"):
        reader.open_replaceable_read_descriptor("synthetic-authority", flags)
    assert api.operations == events == transfers == []


@pytest.mark.parametrize("name", ["a\0b", "x" * 32768], ids=["nul", "windows_path_limit"])
def test_invalid_path_never_reaches_native_open(native_open, name):
    api, events, transfers, _error = native_open
    with pytest.raises(ValueError):
        reader.open_replaceable_read_descriptor(name, os.O_RDONLY)
    assert api.operations == events == transfers == []


def test_audit_refusal_propagates_same_object_without_open(native_open, monkeypatch):
    api, _events, transfers, _error = native_open
    refusal = RuntimeError("synthetic audit refusal")

    def refuse(*_arguments):
        raise refusal

    monkeypatch.setattr(reader, "sys", SimpleNamespace(audit=refuse))
    with pytest.raises(RuntimeError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is refusal
    assert api.operations == transfers == []


@pytest.mark.parametrize("handle", [None, ctypes.c_void_p(-1).value])
def test_original_open_error_is_not_wrapped_or_closed(native_open, handle):
    api, _events, transfers, error = native_open
    api.handle = handle
    with pytest.raises(PermissionError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is error
    assert error.winerror == 32
    assert len(api.operations) == 1
    assert transfers == []


def test_information_error_is_preserved_and_owned_handle_closed(native_open):
    api, _events, transfers, error = native_open
    api.information_success = False
    with pytest.raises(PermissionError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is error
    assert api.operations[-1] == ("close", 41)
    assert transfers == []


@pytest.mark.parametrize("attributes", [0x10, 0x400, 0x410], ids=["directory", "reparse", "both"])
def test_actual_handle_metadata_rejects_nonregular(native_open, attributes):
    api, _events, transfers, _error = native_open
    api.attributes = attributes
    with pytest.raises(OSError, match="not_regular"):
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert api.operations[-1] == ("close", 41)
    assert transfers == []


@pytest.mark.parametrize("file_type", [2, 3], ids=["character", "pipe"])
def test_nondisk_handle_is_not_transferred(native_open, file_type):
    api, _events, transfers, _error = native_open
    api.file_type = file_type
    with pytest.raises(OSError, match="not_disk"):
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert api.operations[-1] == ("close", 41)
    assert transfers == []


def test_file_type_error_retains_actual_error_and_clears_stale_code(native_open, monkeypatch):
    api, _events, transfers, error = native_open
    cleared = []
    monkeypatch.setattr(reader.ctypes, "set_last_error", cleared.append)
    api.file_type = 0
    with pytest.raises(PermissionError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert cleared == [0]
    assert caught.value is error
    assert api.operations[-1] == ("close", 41)
    assert transfers == []


def test_unknown_file_type_without_os_error_remains_rejected(native_open):
    api, _events, transfers, error = native_open
    api.file_type = 0
    error.winerror = 0
    with pytest.raises(OSError, match="not_disk"):
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert api.operations[-1] == ("close", 41)
    assert transfers == []


def test_descriptor_transfer_failure_keeps_original_error_and_closes(native_open, monkeypatch):
    api, _events, _transfers, _error = native_open
    failure = OSError("synthetic transfer failure")

    def transfer(_handle, _flags):
        raise failure

    monkeypatch.setattr(reader, "_transfer_descriptor", transfer)
    with pytest.raises(OSError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is failure
    assert api.operations.count(("close", 41)) == 1


def test_secondary_close_failure_does_not_replace_original_error(native_open):
    api, _events, transfers, error = native_open
    api.information_success = False
    api.close_success = False
    with pytest.raises(PermissionError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is error
    expected_notes = ["windows_replaceable_read_close_failed"] if callable(getattr(error, "add_note", None)) else None
    assert getattr(error, "__notes__", None) == expected_notes
    assert api.operations.count(("close", 41)) == 1
    assert transfers == []


def test_text_wrapper_preserves_utf8_newlines_and_closes(tmp_path, monkeypatch):
    target = tmp_path / "synthetic-authority"
    target.write_bytes("first\r\nsecond\né".encode())
    descriptors = []

    def opener(path, flags):
        descriptor = os.open(path, flags)
        descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(reader, "_text_opener", opener)
    assert reader.read_replaceable_text(target) == "first\nsecond\né"
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_text_decode_failure_still_closes_descriptor(tmp_path, monkeypatch):
    target = tmp_path / "synthetic-authority"
    target.write_bytes(b"\xff")
    descriptors = []

    def opener(path, flags):
        descriptor = os.open(path, flags)
        descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(reader, "_text_opener", opener)
    with pytest.raises(UnicodeDecodeError):
        reader.read_replaceable_text(target)
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


class _Crt:
    def __init__(self, mode=0x4000, result=0):
        self.mode = mode
        self.result = result
        self.calls = 0

    def _get_fmode(self, pointer):
        self.calls += 1
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_int)).contents.value = self.mode
        return self.result


def test_default_translation_reads_live_crt_mode(monkeypatch):
    crt = _Crt()
    monkeypatch.setattr(reader, "os", _WindowsOs())
    monkeypatch.setattr(reader, "_crt_api", lambda: crt)
    assert reader._descriptor_flags(os.O_RDONLY) == 0x4080
    crt.mode = 0x8000
    assert reader._descriptor_flags(os.O_RDONLY) == 0x8080
    assert crt.calls == 2


def test_explicit_fileio_binary_does_not_consult_default(monkeypatch):
    def unexpected():
        raise AssertionError("explicit binary mode queried the CRT default")

    monkeypatch.setattr(reader, "os", _WindowsOs())
    monkeypatch.setattr(reader, "_crt_api", unexpected)
    assert reader._descriptor_flags(0x8080) == 0x8080


@pytest.mark.parametrize("mode", [0], ids=["invalid"])
def test_unsupported_default_translation_fails_before_native_open(monkeypatch, mode):
    crt = _Crt(mode=mode)
    monkeypatch.setattr(reader, "os", _WindowsOs())
    monkeypatch.setattr(reader, "_crt_api", lambda: crt)

    def unexpected():
        raise AssertionError("unsupported translation reached native open")

    monkeypatch.setattr(reader, "_file_api", unexpected)
    with pytest.raises(OSError, match="translation_mode_unsupported"):
        reader._open_descriptor("synthetic-authority", os.O_RDONLY)
    assert crt.calls == 1


def test_crt_query_error_is_explicit_before_native_open(monkeypatch):
    crt = _Crt(result=22)
    monkeypatch.setattr(reader, "os", _WindowsOs())
    monkeypatch.setattr(reader, "_crt_api", lambda: crt)
    with pytest.raises(OSError) as caught:
        reader._descriptor_flags(os.O_RDONLY)
    assert caught.value.errno == 22
    assert crt.calls == 1


@pytest.mark.parametrize("initial", [0x4000, 0x8000], ids=["text_to_binary", "binary_to_text"])
def test_default_mode_is_observed_after_original_audit_callback(native_open, monkeypatch, initial):
    _api, events, transfers, _error = native_open
    mode = [initial]
    switched = 0x8000 if initial == 0x4000 else 0x4000

    def audit(*arguments):
        events.append(arguments)
        mode[0] = switched

    monkeypatch.setattr(reader, "sys", SimpleNamespace(audit=audit))
    monkeypatch.setattr(reader, "_default_translation_mode", lambda: mode[0])
    assert reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY) == 73
    assert transfers == [(41, switched | 0x80)]
    assert len(events) == 1


@pytest.fixture
def child_capture_driver(monkeypatch):
    path = Path(__file__).with_name("test_windows_replaceable_reader_process.py")
    spec = importlib.util.spec_from_file_location("reader_capture_control", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    properties = {}

    class Process:
        def __init__(self, stdout=b"", stderr=b"", code=0, failure=None):
            self.stdout_bytes, self.stderr_bytes = stdout, stderr
            self.code, self.failure = code, failure
            self.returncode = None
            self.calls = 0

        def communicate(self, timeout):
            assert timeout == 5.0
            self.calls += 1
            if self.calls == 1 and self.failure is not None:
                raise self.failure
            if self.returncode is None:
                self.returncode = self.code
            return self.stdout_bytes, self.stderr_bytes

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

    def call(process):
        monkeypatch.setattr(module.subprocess, "Popen", lambda *args, **kwargs: process)
        return module._run_child(
            Path("synthetic-authority"),
            "--operation",
            "audit",
            record_property=properties.__setitem__,
            label="test",
        )

    return Process, call, properties


def test_child_setup_error_keeps_original_safe_json_and_nonzero_code(child_capture_driver):
    process, call, properties = child_capture_driver
    report = {
        "schema": 1,
        "operation": "failure",
        "requested_operation": "audit",
        "error": {"kind": "OSError", "errno": 2, "winerror": 126},
        "origins": ["crt_binding"],
    }
    raw = (json.dumps(report, sort_keys=True) + "\n").encode()
    code, actual = call(process(stdout=raw, code=1))
    assert code == 1 and actual == report
    captured = json.loads(properties["child_capture_test"])
    assert captured["stdout_content"].encode() == raw
    assert captured["process_retired"] and captured["report_valid"]


def test_child_malformed_output_keeps_hash_without_exporting_content(child_capture_driver):
    process, call, properties = child_capture_driver
    raw = b"synthetic private-path sentinel"
    with pytest.raises(json.JSONDecodeError):
        call(process(stdout=raw))
    captured = json.loads(properties["child_capture_test"])
    assert captured["stdout_bytes"] == len(raw)
    assert len(captured["stdout_sha256"]) == 64
    assert captured["stdout_content"] is None
    assert not captured["report_valid"]
    assert "private-path" not in properties["child_capture_test"]


def test_child_stderr_rejects_after_safe_report_and_error_metadata_retention(child_capture_driver):
    process, call, properties = child_capture_driver
    raw = b'{"schema":1,"operation":"failure","error":{"kind":"other","errno":null,"winerror":null}}'
    with pytest.raises(RuntimeError, match="stderr_observed"):
        call(process(stdout=raw, stderr=b"synthetic path sentinel", code=1))
    captured = json.loads(properties["child_capture_test"])
    assert captured["return_code"] == 1 and captured["stdout_content"].encode() == raw
    assert captured["stderr_bytes"] > 0 and captured["stderr_content_retained"] is False
    assert "sentinel" not in properties["child_capture_test"]


def test_child_timeout_keeps_same_error_and_partial_metadata_after_kill(child_capture_driver):
    process, call, properties = child_capture_driver
    failure = subprocess.TimeoutExpired(["synthetic-child"], 5.0, output=b"partial")
    owned = process(failure=failure)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        call(owned)
    assert caught.value is failure
    captured = json.loads(properties["child_capture_test"])
    assert captured["timed_out"] and captured["kill_requested"] and captured["process_retired"]
    assert captured["timeout_partial"]["stdout_bytes"] == 7
    assert captured["return_code"] == -9 and captured["cleanup_error"] is None
    assert owned.calls == 2


def test_child_duplicate_key_cannot_export_rejected_earlier_value(child_capture_driver):
    process, call, properties = child_capture_driver
    raw = b'{"schema":1,"operation":"synthetic private-path sentinel","operation":"audit"}'
    with pytest.raises(ValueError, match="duplicate_key"):
        call(process(stdout=raw))
    captured = json.loads(properties["child_capture_test"])
    assert captured["stdout_content"] is None
    assert captured["stdout_bytes"] == len(raw)
    assert not captured["report_valid"]
    assert "sentinel" not in properties["child_capture_test"]
