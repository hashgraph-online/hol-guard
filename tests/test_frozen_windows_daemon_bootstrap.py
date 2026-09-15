"""Packaged Windows Core coverage for the authenticated daemon launch gate."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest


def _run_core(executable: Path, args: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(executable), *args],
        env=env,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )


def _json_result(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert result.returncode == 0, f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict), result.stdout
    return payload


def _assert_windows_process_stopped(pid: object) -> None:
    assert type(pid) is int and pid > 0, pid
    deadline = time.monotonic() + 5.0
    while True:
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        if f'"{pid}"' not in result.stdout:
            return
        if time.monotonic() >= deadline:
            pytest.fail(f"packaged daemon PID {pid} did not exit: {result.stdout!r}")
        time.sleep(0.1)


def _stop_and_assert_process_stopped(
    executable: Path,
    stop_args: list[str],
    *,
    env: dict[str, str],
    pid: object,
) -> dict[str, object]:
    stopped = _json_result(_run_core(executable, stop_args, env=env))
    assert stopped["running"] is False, stopped
    assert stopped["stopped"] is True, stopped
    assert stopped["pid"] == pid, stopped
    _assert_windows_process_stopped(pid)
    return stopped


@pytest.mark.skipif(os.name != "nt", reason="exercises the packaged Windows frozen runtime")
def test_packaged_windows_core_bootstrap_retry_and_repair(tmp_path: Path) -> None:
    executable_value = os.environ.get("HOL_GUARD_FROZEN_TEST_EXECUTABLE")
    if not executable_value:
        pytest.fail("HOL_GUARD_FROZEN_TEST_EXECUTABLE must point to the PyInstaller binary")
    executable = Path(executable_value).resolve(strict=True)
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    appdata = tmp_path / "appdata"
    local_appdata = tmp_path / "local-appdata"
    for directory in (home_dir, guard_home, appdata, local_appdata):
        directory.mkdir()

    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"}
    }
    env.update(
        {
            "HOME": str(home_dir),
            "USERPROFILE": str(home_dir),
            "APPDATA": str(appdata),
            "LOCALAPPDATA": str(local_appdata),
            "HOL_GUARD_HOME": str(guard_home),
            "HOL_GUARD_DESKTOP": "1",
        }
    )

    bootstrap_args = [
        "desktop",
        "bootstrap",
        "--guard-home",
        str(guard_home),
        "--home",
        str(home_dir),
        "--json",
    ]
    status_args = ["daemon", "status", "--guard-home", str(guard_home), "--json"]
    stop_args = ["daemon", "stop", "--guard-home", str(guard_home), "--json"]
    repair_args = ["daemon", "repair", "--guard-home", str(guard_home), "--json"]

    try:
        bootstrap = _json_result(_run_core(executable, bootstrap_args, env=env))
        assert bootstrap["schema"] == "guard-desktop-bootstrap.v1"
        first_status = _json_result(_run_core(executable, status_args, env=env))
        assert first_status["running"] is True, first_status
        first_pid = first_status["pid"]

        _stop_and_assert_process_stopped(
            executable,
            stop_args,
            env=env,
            pid=first_pid,
        )

        retry_bootstrap = _json_result(_run_core(executable, bootstrap_args, env=env))
        assert retry_bootstrap["schema"] == "guard-desktop-bootstrap.v1"
        retry_status = _json_result(_run_core(executable, status_args, env=env))
        assert retry_status["running"] is True
        retry_pid = retry_status["pid"]
        _stop_and_assert_process_stopped(
            executable,
            stop_args,
            env=env,
            pid=retry_pid,
        )

        repaired = _json_result(_run_core(executable, repair_args, env=env))
        assert repaired["runtime_status"] == "restarted"
        repaired_status = _json_result(_run_core(executable, status_args, env=env))
        assert repaired_status["running"] is True
    finally:
        cleanup = _run_core(executable, stop_args, env=env)
        assert cleanup.returncode == 0, f"stdout={cleanup.stdout!r}\nstderr={cleanup.stderr!r}"
        cleanup_payload = _json_result(cleanup)
        if isinstance(cleanup_payload.get("pid"), int):
            _assert_windows_process_stopped(cleanup_payload["pid"])
