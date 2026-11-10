"""A slow but live daemon start is kept running instead of being terminated."""

from __future__ import annotations

import shlex
import sys
import time
from pathlib import Path

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon import recovery_worker, start_classification
from codex_plugin_scanner.guard.native_daemon_lifecycle import (
    _DAEMON_LIFECYCLE_DEADLINE,
    native_daemon_lifecycle,
)

# The packaged Windows runtime's own start timeline, as
# tests/test_frozen_windows_daemon_bootstrap.py printed it on a GitHub
# Windows runner: ``daemon_ready`` landed 30.4, 33.0 and 36.0 seconds after
# the daemon's first import, with ``init_http_server`` alone costing between
# 10.6 and 15.1 of them. A client that stops waiting earlier than that calls a
# healthy start a failure.
_PACKAGED_WINDOWS_READY_SECONDS = 36.0


class _FakeProcess:
    def __init__(self, pid: int = 424242) -> None:
        self.pid = pid
        self.returncode: int | None = None
        self.stdin = None
        self.terminated = False

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.terminated = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return self.returncode or 0


def _private_home(tmp_path: Path) -> Path:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    guard_home.chmod(0o700)
    return guard_home


def _deadline_bound_tree_check(pid: int, root_pid: int) -> bool:
    # Process-tree queries run under the lifecycle deadline, like the native inventory.
    deadline = _DAEMON_LIFECYCLE_DEADLINE.get()
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("Guard daemon operation deadline exceeded.")
    return pid == root_pid


def test_bootstrap_command_line_stays_shell_splittable() -> None:
    # Process inventory shlex-splits the daemon command line; an unbalanced
    # quote makes the inventory unknown and blocks every daemon start.
    bootstrap = daemon_manager_module._GUARD_DAEMON_BOOTSTRAP
    assert shlex.split(f"python -c {bootstrap} a b c m")[-4:] == ["a", "b", "c", "m"]


def test_recovery_worker_treats_a_still_starting_daemon_as_success(tmp_path: Path, monkeypatch) -> None:
    cleared: list[str] = []

    def still_starting(*_a, **_k):
        raise start_classification.GuardDaemonStillStartingError("Guard daemon is still starting")

    monkeypatch.setattr(recovery_worker, "recover_guard_daemon_after_hook_failure", still_starting)
    monkeypatch.setattr(
        recovery_worker,
        "clear_guard_daemon_recovery_reservation",
        lambda _gh, *, token: cleared.append(token) or True,
    )
    monkeypatch.setattr(
        sys, "argv", ["worker", str(tmp_path / "guard-home"), str(tmp_path), "overload", "reservation-token"]
    )

    assert recovery_worker.main() == 0
    assert cleared == ["reservation-token"]


def test_a_windows_start_record_stays_live_as_long_as_the_client_waits(native_hook_force: Path, tmp_path: Path) -> None:
    """The start-progress gate and the client read one budget, not two."""

    now_ns = 200 * 1_000_000_000
    recorded_at_ns = now_ns - int(_PACKAGED_WINDOWS_READY_SECONDS * 1_000_000_000)
    query = {
        "record": {"pid": 424242, "process_start_token": "token", "recorded_at_ns": recorded_at_ns},
        "now_ns": now_ns,
        "worker_ready_floor": 14.0,
    }
    facts = {
        "pid_running:424242": True,
        "start_token:424242": "token",
        "matches_command:424242": True,
    }
    windows = native_daemon_lifecycle(
        "start_progress_live",
        query,
        resolve_fact=lambda key: facts[key],
        platform="nt",
        guard_home=tmp_path,
    )
    assert windows == {"live": True}


def test_the_update_refresh_outlasts_the_start_it_waits_on(native_hook_force: Path, tmp_path: Path) -> None:
    """The subprocess that restarts the daemon after an update gets to finish."""

    from codex_plugin_scanner.guard.cli import update_commands
    from codex_plugin_scanner.guard.daemon.update_refresh_program import DAEMON_REFRESH_SCRIPT

    query = {"desktop": True, "worker_ready_floor": 14.0}
    windows = native_daemon_lifecycle("start_timeouts", query, platform="nt", guard_home=tmp_path)

    # One refresh attempt is the retirement loop, the start itself and the
    # stability window the program holds before it reports success. Read those
    # two bounds off the program rather than restating them here, so a change
    # to either one lands on this assertion.
    assert "retirement_deadline = time.monotonic() + 5.0" in DAEMON_REFRESH_SCRIPT
    assert "for _stability_check in range(3):" in DAEMON_REFRESH_SCRIPT
    assert "time.sleep(1.0)" in DAEMON_REFRESH_SCRIPT
    one_attempt = windows["post_update"] + 5.0 + 3.0

    assert one_attempt < update_commands._DAEMON_REFRESH_TIMEOUT_SECONDS
