"""Exercise Windows termination outcomes without terminating real processes."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard import windows_paths
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module


@pytest.mark.parametrize(
    "expected_time,wait_results,terminate_result,expected_result,termination_calls",
    [
        (124, [], 1, False, 0),
        (123, [0], 1, True, 0),
        (123, [258, 0], 1, True, 1),
        (123, [258, 258], 1, False, 1),
        (123, [258], 0, False, 1),
        (123, [4294967295], 1, False, 0),
    ],
)
def test_windows_termination_reports_actual_outcome_and_closes_handle(
    monkeypatch: pytest.MonkeyPatch,
    expected_time: int,
    wait_results: list[int],
    terminate_result: int,
    expected_result: bool,
    termination_calls: int,
) -> None:
    def get_process_times(_handle, creation, *_times):
        creation._obj.dwLowDateTime = 123
        creation._obj.dwHighDateTime = 0
        return 1

    kernel = SimpleNamespace(
        OpenProcess=Mock(return_value=99),
        GetProcessTimes=Mock(side_effect=get_process_times),
        TerminateProcess=Mock(return_value=terminate_result),
        WaitForSingleObject=Mock(side_effect=wait_results),
        CloseHandle=Mock(return_value=1),
    )
    monkeypatch.setattr(windows_paths, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(windows_paths.ctypes, "WinDLL", Mock(return_value=kernel), raising=False)

    result = windows_paths.windows_terminate_process_if_creation_time(1234, expected_time)

    assert result is expected_result
    assert kernel.TerminateProcess.call_count == termination_calls
    assert kernel.WaitForSingleObject.call_count == len(wait_results)
    kernel.CloseHandle.assert_called_once_with(99)
    if termination_calls:
        kernel.TerminateProcess.assert_called_once_with(99, 1)


def test_windows_termination_clamps_bounded_wait_and_reports_unconfirmed_timeout(monkeypatch) -> None:
    wait_timeouts: list[int] = []
    clock = {"value": 100.0}

    def get_process_times(_handle, creation, *_times):
        creation._obj.dwLowDateTime = 123
        creation._obj.dwHighDateTime = 0
        return 1

    def wait(_handle, timeout_ms: int) -> int:
        wait_timeouts.append(timeout_ms)
        if len(wait_timeouts) == 2:
            clock["value"] = 100.25
        return windows_paths._WINDOWS_WAIT_TIMEOUT

    kernel = SimpleNamespace(
        OpenProcess=Mock(return_value=99),
        GetProcessTimes=Mock(side_effect=get_process_times),
        TerminateProcess=Mock(return_value=1),
        WaitForSingleObject=Mock(side_effect=wait),
        CloseHandle=Mock(return_value=1),
    )
    monkeypatch.setattr(windows_paths, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(windows_paths, "time", SimpleNamespace(monotonic=lambda: clock["value"]))
    monkeypatch.setattr(windows_paths.ctypes, "WinDLL", Mock(return_value=kernel), raising=False)

    result = windows_paths.windows_terminate_process_if_creation_time(1234, 123, timeout=0.25)

    assert result is False
    assert wait_timeouts == [0, 250]
    kernel.TerminateProcess.assert_called_once_with(99, 1)
    kernel.CloseHandle.assert_called_once_with(99)


def test_windows_process_owner_sid_reads_token_user_for_selected_pid(monkeypatch) -> None:
    sid_text = ctypes.create_unicode_buffer("S-1-5-21-42")
    sid_storage = ctypes.create_string_buffer(1)
    closed_handles: list[object] = []
    kernel = SimpleNamespace()
    advapi = SimpleNamespace()

    def open_process(_access, _inherit, pid: int):
        assert pid == 73_001
        return 101

    def open_process_token(_process, _access, token_pointer):
        ctypes.cast(token_pointer, ctypes.POINTER(wintypes.HANDLE)).contents.value = 202
        return 1

    def get_token_information(_token, _token_class, buffer, _size, returned_size):
        if buffer is None:
            ctypes.cast(returned_size, ctypes.POINTER(wintypes.DWORD)).contents.value = ctypes.sizeof(
                windows_paths._WindowsTokenUser
            )
            return 0
        token_user = ctypes.cast(
            buffer,
            ctypes.POINTER(windows_paths._WindowsTokenUser),
        ).contents
        token_user.User.Sid = ctypes.addressof(sid_storage)
        ctypes.cast(returned_size, ctypes.POINTER(wintypes.DWORD)).contents.value = ctypes.sizeof(
            windows_paths._WindowsTokenUser
        )
        return 1

    def convert_sid(_sid, output_pointer):
        ctypes.cast(output_pointer, ctypes.POINTER(wintypes.LPWSTR))[0] = ctypes.cast(
            sid_text,
            wintypes.LPWSTR,
        )
        return 1

    def close_handle(handle):
        closed_handles.append(getattr(handle, "value", handle))
        return 1

    kernel.OpenProcess = open_process
    kernel.CloseHandle = close_handle
    kernel.LocalFree = lambda _pointer: 0
    advapi.OpenProcessToken = open_process_token
    advapi.GetTokenInformation = get_token_information
    advapi.ConvertSidToStringSidW = convert_sid

    monkeypatch.setattr(windows_paths, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        windows_paths.ctypes,
        "WinDLL",
        lambda name, **_kwargs: kernel if name == "kernel32" else advapi,
        raising=False,
    )

    assert windows_paths.windows_process_owner_sid(73_001) == "sid:S-1-5-21-42"
    assert closed_handles == [202, 101]


def test_state_writer_uses_selected_pid_owner_for_adopted_daemon(monkeypatch, tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    adopted_pid = 73_002
    observed_pids: list[int] = []

    def owner_marker(pid: int) -> str:
        observed_pids.append(pid)
        return "sid:S-1-5-21-adopted"

    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "windows:123")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", owner_marker)

    daemon_manager_module.write_guard_daemon_state(
        guard_home,
        4781,
        "auth-token",
        pid=adopted_pid,
    )

    state = daemon_manager_module.load_authenticated_daemon_state(guard_home)
    assert observed_pids == [adopted_pid]
    assert state is not None
    assert state["pid"] == adopted_pid
    assert state["user"] == "sid:S-1-5-21-adopted"
