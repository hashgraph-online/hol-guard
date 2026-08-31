"""Containment contracts for optional third-party scanner processes."""

import os
import sys
import time

import pytest

from codex_plugin_scanner.integrations import scanner_subprocess as scanner_subprocess_module
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
                "\ntry:\n"
                " child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'], "
                "start_new_session=True)\n"
                " print(f'child pid={child.pid}')\n"
                "except OSError:\n"
                " print('child spawn blocked')\n"
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
    if os.name == "posix" and "child pid=" in result.stdout:
        child_pid = int(
            next(line for line in result.stdout.splitlines() if line.startswith("child pid=")).split("=", 1)[1]
        )
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            pytest.fail("scanner descendant survived process-group cleanup")


def test_linux_scanner_lockdown_rejects_compat_architectures_and_x32() -> None:
    instructions = scanner_subprocess_module._linux_process_group_lockdown_instructions("x86_64")
    encoded = [(item.code, item.jt, item.jf, item.k) for item in instructions]

    assert encoded[:6] == [
        (0x20, 0, 0, 4),
        (0x15, 1, 0, 0xC000003E),
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),
        (0x45, 0, 1, 0x40000000),
        (0x06, 0, 0, 0x80000000),
    ]
    assert encoded[6:] == [
        (0x15, 0, 1, 109),
        (0x06, 0, 0, 0x00050001),
        (0x15, 0, 1, 112),
        (0x06, 0, 0, 0x00050001),
        (0x06, 0, 0, 0x7FFF0000),
    ]


def test_cpu_limit_stays_beyond_parent_wall_deadline(monkeypatch) -> None:
    if scanner_subprocess_module._resource is None:
        pytest.skip("POSIX resource limits are unavailable")
    observed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        scanner_subprocess_module,
        "_set_limit",
        lambda resource, value: observed.append((resource, value)),
    )

    scanner_subprocess_module._apply_resource_limits(1.0)

    assert (scanner_subprocess_module._resource.RLIMIT_CPU, 2) in observed
