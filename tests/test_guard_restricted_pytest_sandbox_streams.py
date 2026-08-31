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
