"""A slow but live daemon start is kept running instead of being terminated."""

from __future__ import annotations

import ast
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon import recovery_worker, start_classification, start_heartbeat
from codex_plugin_scanner.guard.native_daemon_lifecycle import daemon_lifecycle_deadline


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


def _patch_spawn(monkeypatch: pytest.MonkeyPatch, process: _FakeProcess, *, after_spawn_wait) -> None:
    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_: None)
    monkeypatch.setattr(daemon_manager_module, "reap_orphaned_daemon_workers", lambda **_: None)
    monkeypatch.setattr(daemon_manager_module, "_running_guard_daemon_processes_for_guard_home", lambda _gh: [])
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _gh: None)
    monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _gh: None)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_in_progress", lambda _gh: False)
    monkeypatch.setattr(daemon_manager_module, "_adopt_existing_guard_daemon", lambda *_a, **_k: None)
    monkeypatch.setattr(daemon_manager_module, "_guard_home_is_ephemeral", lambda _gh: False)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda *_a, **_k: [5700])
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _: None)
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", lambda *_a, **_k: process)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "posix:token")
    # No lock, no journal entry: the child is still importing Python.
    monkeypatch.setattr(start_classification, "daemon_owner_lock_is_held", lambda _gh: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _gh: [])

    def fake_wait(_gh, **_kwargs):
        after_spawn_wait()

    monkeypatch.setattr(daemon_manager_module, "_wait_for_guard_daemon_url", fake_wait)


def test_slow_child_with_only_an_early_heartbeat_is_left_running(tmp_path: Path, monkeypatch) -> None:
    guard_home = _private_home(tmp_path)
    process = _FakeProcess()
    _patch_spawn(
        monkeypatch,
        process,
        after_spawn_wait=lambda: _write_heartbeat(guard_home, pid=process.pid, ns=time.time_ns()),
    )

    with pytest.raises(RuntimeError, match=r"^Guard daemon is still starting"):
        daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=30.0, home_dir=tmp_path)

    assert process.terminated is False
    assert daemon_manager_module.load_authenticated_guard_daemon_start_progress(guard_home) is not None


def test_silent_child_without_a_heartbeat_is_still_terminated(tmp_path: Path, monkeypatch) -> None:
    guard_home = _private_home(tmp_path)
    process = _FakeProcess()
    _patch_spawn(monkeypatch, process, after_spawn_wait=lambda: None)

    with pytest.raises(RuntimeError, match=r"^Guard approval center did not start"):
        daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=30.0, home_dir=tmp_path)

    assert process.terminated is True


def test_heartbeat_from_before_the_spawn_does_not_count(tmp_path: Path, monkeypatch) -> None:
    guard_home = _private_home(tmp_path)
    process = _FakeProcess()
    _patch_spawn(
        monkeypatch,
        process,
        after_spawn_wait=lambda: _write_heartbeat(guard_home, pid=process.pid, ns=1),
    )

    with pytest.raises(RuntimeError, match=r"^Guard approval center did not start"):
        daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=30.0, home_dir=tmp_path)

    assert process.terminated is True


def test_heartbeat_from_a_foreign_process_does_not_count(tmp_path: Path, monkeypatch) -> None:
    guard_home = _private_home(tmp_path)
    process = _FakeProcess()
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_parent_pid", lambda _pid: None)
    _patch_spawn(
        monkeypatch,
        process,
        after_spawn_wait=lambda: _write_heartbeat(guard_home, pid=999999, ns=time.time_ns()),
    )

    with pytest.raises(RuntimeError, match=r"^Guard approval center did not start"):
        daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=30.0, home_dir=tmp_path)

    assert process.terminated is True


def _deadline_bound_tree_check(pid: int, root_pid: int) -> bool:
    # Process-tree queries run under the lifecycle deadline, like the native inventory.
    deadline = daemon_lifecycle_deadline()
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("Guard daemon operation deadline exceeded.")
    return pid == root_pid


def test_wait_leaves_time_to_classify_a_slow_child(tmp_path: Path, monkeypatch) -> None:
    guard_home = _private_home(tmp_path)
    process = _FakeProcess()
    _patch_spawn(monkeypatch, process, after_spawn_wait=lambda: None)

    def spend_the_wait_budget(_gh, *, timeout: float, **_kwargs) -> None:
        stop = time.monotonic() + timeout
        while time.monotonic() < stop:
            pass
        _write_heartbeat(guard_home, pid=process.pid, ns=time.time_ns())

    monkeypatch.setattr(daemon_manager_module, "_wait_for_guard_daemon_url", spend_the_wait_budget)
    monkeypatch.setattr(start_classification, "_pid_in_process_tree", _deadline_bound_tree_check)

    with pytest.raises(RuntimeError, match=r"^Guard daemon is still starting"):
        daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=0.8, home_dir=tmp_path)

    assert process.terminated is False


def test_an_expired_poll_still_classifies_the_child(tmp_path: Path, monkeypatch) -> None:
    guard_home = _private_home(tmp_path)
    process = _FakeProcess()
    _patch_spawn(monkeypatch, process, after_spawn_wait=lambda: None)

    def expired_poll(_gh, **_kwargs) -> None:
        _write_heartbeat(guard_home, pid=process.pid, ns=time.time_ns())
        raise TimeoutError("Guard daemon operation deadline exceeded.")

    monkeypatch.setattr(daemon_manager_module, "_wait_for_guard_daemon_url", expired_poll)

    with pytest.raises(RuntimeError, match=r"^Guard daemon is still starting"):
        daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=30.0, home_dir=tmp_path)

    assert process.terminated is False


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


class TestProgressRecordOutlivesRecordedWindow:
    @staticmethod
    def _record(pid: int, *, age_seconds: float) -> dict[str, object]:
        spawned = time.time_ns() - int(age_seconds * 1_000_000_000)
        return {"pid": pid, "spawned_at_ns": spawned, "recorded_at_ns": spawned + 1_000_000_000}

    @staticmethod
    def _identity_only(monkeypatch) -> None:
        # Model the native check: live only when age is judged at record time.
        monkeypatch.setattr(
            daemon_manager_module,
            "_start_progress_record_is_live",
            lambda _gh, record, *, now_ns: now_ns == record["recorded_at_ns"],
        )

    def test_live_child_with_heartbeat_stays_live_past_the_recorded_window(self, tmp_path, monkeypatch) -> None:
        guard_home = _private_home(tmp_path)
        self._identity_only(monkeypatch)
        record = self._record(os.getpid(), age_seconds=70)
        _write_heartbeat(guard_home, pid=os.getpid(), ns=int(record["spawned_at_ns"]) + 500_000_000)

        assert daemon_manager_module._guard_daemon_start_progress_is_live(guard_home, record) is True

    def test_child_without_start_evidence_is_not_kept_alive(self, tmp_path, monkeypatch) -> None:
        guard_home = _private_home(tmp_path)
        self._identity_only(monkeypatch)
        monkeypatch.setattr(start_classification, "daemon_owner_lock_is_held", lambda _gh: False)

        record = self._record(os.getpid(), age_seconds=70)
        assert daemon_manager_module._guard_daemon_start_progress_is_live(guard_home, record) is False

    def test_child_past_the_hard_cap_is_not_kept_alive(self, tmp_path, monkeypatch) -> None:
        guard_home = _private_home(tmp_path)
        self._identity_only(monkeypatch)
        record = self._record(os.getpid(), age_seconds=start_heartbeat.SLOW_START_MAX_SECONDS + 10)
        _write_heartbeat(guard_home, pid=os.getpid(), ns=int(record["spawned_at_ns"]) + 500_000_000)

        assert daemon_manager_module._guard_daemon_start_progress_is_live(guard_home, record) is False

    def test_recycled_pid_is_not_kept_alive(self, tmp_path, monkeypatch) -> None:
        guard_home = _private_home(tmp_path)
        monkeypatch.setattr(daemon_manager_module, "_start_progress_record_is_live", lambda *_a, **_k: False)
        record = self._record(os.getpid(), age_seconds=70)
        _write_heartbeat(guard_home, pid=os.getpid(), ns=int(record["spawned_at_ns"]) + 500_000_000)

        assert daemon_manager_module._guard_daemon_start_progress_is_live(guard_home, record) is False


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
