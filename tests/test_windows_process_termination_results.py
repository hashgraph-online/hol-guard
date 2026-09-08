"""Exercise Windows termination outcomes without terminating real processes."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard import windows_paths


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
