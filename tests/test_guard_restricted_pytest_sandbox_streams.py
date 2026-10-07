"""Standard-stream containment for the restricted pytest backend."""

import os
import sys

import pytest

from codex_plugin_scanner.guard.runtime.restricted_pytest_sandbox import _run_backend_process


def test_restricted_process_has_noninteractive_sanitized_standard_streams(
    capsys: pytest.CaptureFixture[str],
) -> None:
    return_code = _run_backend_process(
        [
            sys.executable,
            "-c",
            "import sys; print('stdin=' + repr(sys.stdin.read())); print('\\x1b[31mresult')",
        ],
        env=os.environ,
        timeout_seconds=5,
    )

    captured = capsys.readouterr()
    assert return_code == 0
    assert "stdin=''" in captured.out
    assert "\x1b" not in captured.out
    assert "result" in captured.out


def test_private_capability_stdout_is_bounded_and_not_replayed(capsys):
    output = bytearray()
    code = _run_backend_process(
        [sys.executable, "-c", "import sys; print('capability-result'); print('diagnostic', file=sys.stderr)"],
        env=os.environ,
        timeout_seconds=5,
        stdout_capture=output,
    )
    assert code == 0 and output == b"capability-result\n"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "diagnostic" in captured.err
