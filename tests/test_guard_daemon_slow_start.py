"""A slow but live daemon start is kept running instead of being terminated."""

from __future__ import annotations

import ast
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon import recovery_worker, start_classification, start_heartbeat
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


def _write_heartbeat(guard_home: Path, *, pid: int, ns: int) -> None:
    path = start_heartbeat.start_heartbeat_path(guard_home)
    path.write_text(f"{pid} {ns}", encoding="utf-8")
    path.chmod(0o600)


def _deadline_bound_tree_check(pid: int, root_pid: int) -> bool:
    # Process-tree queries run under the lifecycle deadline, like the native inventory.
    deadline = _DAEMON_LIFECYCLE_DEADLINE.get()
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("Guard daemon operation deadline exceeded.")
    return pid == root_pid


def test_heartbeat_stops_counting_after_the_slow_start_window(tmp_path: Path) -> None:
    guard_home = _private_home(tmp_path)
    spawned_at_ns = time.time_ns() - int((start_heartbeat.SLOW_START_MAX_SECONDS + 5) * 1_000_000_000)
    _write_heartbeat(guard_home, pid=os.getpid(), ns=spawned_at_ns + 1_000_000_000)

    assert not start_classification.daemon_start_heartbeat_present(
        guard_home, root_pid=os.getpid(), spawned_at_ns=spawned_at_ns
    )
    assert not start_classification.daemon_still_starting_evidence_present(
        guard_home, root_pid=os.getpid(), spawned_at_ns=spawned_at_ns
    )


def test_bootstrap_emits_the_heartbeat_before_importing_guard(tmp_path: Path) -> None:
    guard_home = _private_home(tmp_path)
    env = {
        **{k: v for k, v in os.environ.items() if k in {"PATH", "SYSTEMROOT"}},
        start_heartbeat.START_HEARTBEAT_ENV: str(start_heartbeat.start_heartbeat_path(guard_home)),
    }
    before = time.time_ns()

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            daemon_manager_module._GUARD_DAEMON_BOOTSTRAP,
            sys.prefix,
            sys.exec_prefix,
            "[]",
            "platform",
        ],
        env=env,
        capture_output=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    heartbeat = start_heartbeat.load_start_heartbeat(guard_home)
    assert heartbeat is not None
    assert heartbeat[1] >= before


def test_launcher_env_never_carries_the_heartbeat_path(tmp_path: Path, monkeypatch) -> None:
    # Helper and wake-worker launches share this env builder; only the real
    # daemon spawn may add the heartbeat path, so they cannot overwrite it.
    guard_home = _private_home(tmp_path)
    monkeypatch.setattr(daemon_manager_module, "_guard_home_is_ephemeral", lambda _gh: False)
    monkeypatch.setenv(start_heartbeat.START_HEARTBEAT_ENV, str(tmp_path / "ambient"))

    env = daemon_manager_module._daemon_launcher_env(home_dir=tmp_path, guard_home=guard_home)

    assert start_heartbeat.START_HEARTBEAT_ENV not in env


def test_bootstrap_command_line_stays_shell_splittable() -> None:
    # Process inventory shlex-splits the daemon command line; an unbalanced
    # quote makes the inventory unknown and blocks every daemon start.
    code = start_heartbeat.START_HEARTBEAT_CODE
    assert "\\" not in code and "\n" not in code and '"' not in code
    bootstrap = daemon_manager_module._GUARD_DAEMON_BOOTSTRAP
    assert shlex.split(f"python -c {bootstrap} a b c m")[-4:] == ["a", "b", "c", "m"]


def test_entry_script_heartbeat_code_matches_the_shared_constant() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "mdm" / "hol-guard-entry.py"
    module = ast.parse(script.read_text(encoding="utf-8"))
    literal = next(
        ast.literal_eval(node.value)
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "_START_HEARTBEAT_CODE" for t in node.targets)
    )
    assert literal == start_heartbeat.START_HEARTBEAT_CODE


def test_heartbeat_is_written_atomically_without_leaving_temp_files(tmp_path: Path) -> None:
    guard_home = _private_home(tmp_path)
    path = start_heartbeat.start_heartbeat_path(guard_home)
    env = {**os.environ, start_heartbeat.START_HEARTBEAT_ENV: str(path)}
    subprocess.run([sys.executable, "-c", start_heartbeat.START_HEARTBEAT_CODE], env=env, check=True, timeout=60)

    assert sorted(p.name for p in guard_home.iterdir()) == [path.name]
    assert (path.stat().st_mode & 0o777) == 0o600 or os.name == "nt"
    assert start_heartbeat.load_start_heartbeat(guard_home) is not None


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
