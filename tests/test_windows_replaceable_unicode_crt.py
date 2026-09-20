from __future__ import annotations

import ctypes
import os
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import windows_replaceable_file as reader


class _WindowsOs:
    name = "nt"
    O_BINARY = 0x8000
    O_TEXT = 0x4000
    O_NOINHERIT = 0x80

    def __init__(self):
        self.closed: list[int] = []
        self.close_failure: BaseException | None = None

    def close(self, descriptor: int) -> None:
        self.closed.append(descriptor)
        if self.close_failure is not None:
            raise self.close_failure

    def __getattr__(self, name: str) -> Any:
        return getattr(os, name)


class _Crt:
    def __init__(self):
        self.mode = 0x10000
        self.descriptor = 73
        self.error_number = 0
        self.previous = 91
        self.calls: list[tuple[Any, ...]] = []
        self.open_failure: BaseException | None = None
        self.install_failure: BaseException | None = None
        self.restore_failure: BaseException | None = None
        callback = ctypes.CFUNCTYPE(
            None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t
        )
        self._guard_silent_invalid_parameter_handler = callback(lambda *_arguments: None)
        self.quiet = ctypes.cast(self._guard_silent_invalid_parameter_handler, ctypes.c_void_p).value

    def _get_fmode(self, pointer: Any) -> int:
        self.calls.append(("mode", self.mode))
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_int)).contents.value = self.mode
        return 0

    def _set_thread_local_invalid_parameter_handler(self, value: Any) -> int:
        raw = value.value if isinstance(value, ctypes.c_void_p) else value
        self.calls.append(("handler", raw))
        if raw == self.quiet:
            if self.install_failure is not None:
                raise self.install_failure
        else:
            ctypes.set_errno(123)
            if self.restore_failure is not None:
                raise self.restore_failure
        return self.previous

    def _wopen(self, name: str, flags: int, pmode: int) -> int:
        self.calls.append(("wopen", name, flags, pmode))
        if self.open_failure is not None:
            raise self.open_failure
        ctypes.set_errno(self.error_number)
        return self.descriptor


@pytest.fixture
def unicode_open(monkeypatch):
    crt, windows = _Crt(), _WindowsOs()
    events: list[tuple[Any, ...]] = []
    monkeypatch.setattr(reader, "os", windows)
    monkeypatch.setattr(reader, "sys", SimpleNamespace(audit=lambda *args: events.append(args)))
    monkeypatch.setattr(reader, "_crt_api", lambda: crt)

    def unexpected():
        raise AssertionError("Unicode preservation reached the native sharing opener")

    monkeypatch.setattr(reader, "_file_api", unexpected)
    return crt, windows, events


def test_unicode_default_keeps_unflagged_crt_open_and_caller_ownership(unicode_open):
    crt, windows, events = unicode_open
    assert reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY) == 73
    assert events == [("open", "synthetic-authority", None, 0x80)]
    assert crt.calls == [
        ("mode", 0x10000),
        ("handler", crt.quiet),
        ("wopen", "synthetic-authority", 0x80, 0o777),
        ("handler", 91),
    ]
    assert windows.closed == []


@pytest.mark.parametrize("error_number", [2, 13, 22, 24], ids=["missing", "access", "invalid", "descriptor_limit"])
def test_documented_crt_errno_is_captured_before_handler_restoration(unicode_open, error_number):
    crt, windows, events = unicode_open
    crt.descriptor, crt.error_number = -1, error_number
    with pytest.raises(OSError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    expected = OSError(error_number, os.strerror(error_number), "synthetic-authority")
    assert type(caught.value) is type(expected)
    assert caught.value.args == expected.args
    assert caught.value.filename == expected.filename
    assert getattr(caught.value, "winerror", None) is None
    assert crt.calls[-1] == ("handler", 91)
    assert windows.closed == []
    assert len(events) == 1


def test_original_open_exception_survives_handler_restore_failure(unicode_open):
    crt, windows, _events = unicode_open
    failure = RuntimeError("synthetic original CRT failure")
    crt.open_failure = failure
    crt.restore_failure = OSError("synthetic restore failure")
    with pytest.raises(RuntimeError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is failure
    expected_notes = (
        ["windows_replaceable_read_thread_handler_restore_failed"]
        if callable(getattr(failure, "add_note", None))
        else None
    )
    assert getattr(failure, "__notes__", None) == expected_notes
    assert crt.calls[-1] == ("handler", 91)
    assert windows.closed == []


def test_successful_descriptor_is_closed_once_if_handler_restore_fails(unicode_open):
    crt, windows, _events = unicode_open
    failure = OSError("synthetic restore failure")
    crt.restore_failure = failure
    with pytest.raises(OSError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is failure
    assert windows.closed == [73]
    assert crt.calls[-1] == ("handler", 91)


def test_secondary_descriptor_close_failure_does_not_replace_restore_error(unicode_open):
    crt, windows, _events = unicode_open
    failure = OSError("synthetic restore failure")
    crt.restore_failure = failure
    windows.close_failure = RuntimeError("synthetic close failure")
    with pytest.raises(OSError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is failure
    expected_notes = ["windows_replaceable_read_close_failed"] if callable(getattr(failure, "add_note", None)) else None
    assert getattr(failure, "__notes__", None) == expected_notes
    assert windows.closed == [73]


def test_handler_install_failure_cannot_open_or_close_a_descriptor(unicode_open):
    crt, windows, events = unicode_open
    failure = RuntimeError("synthetic handler install failure")
    crt.install_failure = failure
    with pytest.raises(RuntimeError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is failure
    assert crt.calls == [("mode", 0x10000), ("handler", crt.quiet)]
    assert windows.closed == []
    assert len(events) == 1


def test_unicode_audit_refusal_keeps_same_object_before_crt_access(unicode_open, monkeypatch):
    crt, windows, _events = unicode_open
    failure = RuntimeError("synthetic target audit refusal")

    def refuse(*_arguments):
        raise failure

    monkeypatch.setattr(reader, "sys", SimpleNamespace(audit=refuse))
    with pytest.raises(RuntimeError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is failure
    assert crt.calls == windows.closed == []


def test_audit_callback_entering_unicode_is_observed_before_open(unicode_open, monkeypatch):
    crt, windows, events = unicode_open
    crt.mode = 0x4000

    def audit(*arguments):
        events.append(arguments)
        crt.mode = 0x10000

    monkeypatch.setattr(reader, "sys", SimpleNamespace(audit=audit))
    assert reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY) == 73
    assert crt.calls[0] == ("mode", 0x10000)
    assert len(events) == 1 and windows.closed == []


def test_explicit_textio_binary_bypasses_unicode_crt_route(monkeypatch):
    calls: list[tuple[Any, ...]] = []

    def original_flags(flags):
        calls.append(("flags", flags))
        return 0x8080

    def unicode_route(*_arguments):
        raise AssertionError("TextIO entered the Unicode default route")

    class StopNativeError(Exception):
        pass

    def native_route():
        calls.append(("native",))
        raise StopNativeError

    monkeypatch.setattr(reader, "_descriptor_flags", original_flags)
    monkeypatch.setattr(reader, "_open_original_unicode_descriptor", unicode_route)
    monkeypatch.setattr(reader, "_file_api", native_route)
    with pytest.raises(StopNativeError):
        reader._open_descriptor("synthetic-authority", 0x8080)
    assert calls == [("flags", 0x8080), ("native",)]
