"""Process-contention regressions for managed Codex daemon recovery."""

from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime as launch_runtime
from codex_plugin_scanner.guard import native_daemon_manage as daemon_manager
from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
    isolated_daemon_start_command,
    isolated_hook_environment,
    run_isolated_hook_process,
)


@pytest.mark.skipif(os.name == "nt", reason="POSIX recovery contention regression")
def test_concurrent_daemon_start_commands_do_not_wait_behind_active_recovery(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    guard_home.mkdir()
    home_dir.mkdir()
    package_root = Path(launch_runtime.__file__).resolve().parents[2]
    command = isolated_daemon_start_command(sys.executable, package_root, guard_home, home_dir)
    # A live recovery reservation, as a scheduled worker leaves it.
    (guard_home / "daemon-recovery-reservation.json").write_text(
        json.dumps({"created_at": time.time(), "token": "f" * 32}), encoding="utf-8"
    )

    def run_start_command():
        return run_isolated_hook_process(
            command,
            input_text="",
            cwd=home_dir,
            environment=isolated_hook_environment(),
            timeout_seconds=7.0,
            allow_windows_breakaway=True,
        )

    try:
        with (
            daemon_manager._guard_daemon_recovery_lock(  # pyright: ignore[reportPrivateUsage]
                guard_home
            ),
            ThreadPoolExecutor(max_workers=4) as executor,
        ):
            results = list(executor.map(lambda _index: run_start_command(), range(4)))
    finally:
        (guard_home / "daemon-recovery-reservation.json").unlink(missing_ok=True)

    diagnostics = [
        (result.returncode, result.timed_out, result.containment_failed, result.stdout) for result in results
    ]
    assert all(result.returncode == 0 for result in results), diagnostics
    assert all(not result.timed_out for result in results), diagnostics
