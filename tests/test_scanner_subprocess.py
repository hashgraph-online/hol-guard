"""Containment contracts for optional third-party scanner processes."""

import sys
import time

from codex_plugin_scanner.integrations.scanner_subprocess import (
    MAX_SCANNER_OUTPUT_BYTES,
    run_bounded_scanner_process,
    scrubbed_scanner_env,
)


def test_scanner_environment_keeps_runtime_context_but_drops_ambient_secrets(monkeypatch) -> None:
    monkeypatch.setenv("PATH", "/trusted/bin")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")

    env = scrubbed_scanner_env()

    assert env["PATH"] == "/trusted/bin"
    assert "AWS_SECRET_ACCESS_KEY" not in env


def test_scanner_process_timeout_terminates_and_bounds_output() -> None:
    result = run_bounded_scanner_process(
        [
            sys.executable,
            "-c",
            "import sys,time; sys.stdout.write('x' * 2048); sys.stdout.flush(); time.sleep(5)",
        ],
        env=scrubbed_scanner_env(),
        timeout_seconds=0.1,
    )

    assert result.timed_out is True
    assert len(result.stdout.encode()) <= MAX_SCANNER_OUTPUT_BYTES


def test_scanner_process_discards_output_beyond_the_capture_budget() -> None:
    result = run_bounded_scanner_process(
        [sys.executable, "-c", f"import sys; sys.stdout.write('x' * {MAX_SCANNER_OUTPUT_BYTES + 1024})"],
        env=scrubbed_scanner_env(),
        timeout_seconds=5,
    )

    assert result.returncode == 0
    assert len(result.stdout.encode()) == MAX_SCANNER_OUTPUT_BYTES


def test_scanner_process_terminates_descendant_holding_captured_pipes() -> None:
    started = time.monotonic()
    result = run_bounded_scanner_process(
        [
            sys.executable,
            "-c",
            (
                "import subprocess,sys; "
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)']); "
                "print('leader done')"
            ),
        ],
        env=scrubbed_scanner_env(),
        timeout_seconds=1,
    )

    assert result.returncode == 0
    assert result.timed_out is False
    assert "leader done" in result.stdout
    assert time.monotonic() - started < 2
