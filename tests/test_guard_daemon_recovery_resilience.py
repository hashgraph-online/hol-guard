"""Adversarial daemon recovery coordination tests."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false

from __future__ import annotations

import subprocess
import sys
import threading
import time
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon.lifecycle_journal import load_daemon_lifecycle_events


@pytest.fixture(autouse=True)
def _stub_locator_publish(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        daemon_manager_module,
        "publish_approval_center_locator",
        lambda _home, _url: None,
    )


def _old_generation() -> dict[str, object]:
    return {"started_at": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()}


def _recent_generation() -> dict[str, object]:
    return {"started_at": datetime.now(timezone.utc).isoformat()}


@pytest.mark.parametrize("failure_kind", ["overload", "transport-failure"])
def test_recovery_preserves_live_daemon_for_non_control_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: daemon_manager_module.GuardDaemonHookFailureKind,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: _old_generation())
    monkeypatch.setattr(
        daemon_manager_module,
        "load_guard_daemon_url",
        lambda _home: "http://127.0.0.1:4781",
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "retire_all_guard_daemons_for_home",
        lambda _home: pytest.fail("load shedding and transient transport failures must not retire a live daemon"),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "ensure_guard_daemon",
        lambda _home, *, home_dir=None: pytest.fail("a live daemon must be reused"),
    )

    recovered = daemon_manager_module.recover_guard_daemon_after_hook_failure(
        guard_home,
        failure_kind=failure_kind,
    )

    assert recovered == "http://127.0.0.1:4781"


def test_recovery_starts_when_overloaded_state_has_no_live_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    retired: list[Path] = []
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: _old_generation())
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "retire_all_guard_daemons_for_home",
        lambda home: retired.append(home) or [],
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "ensure_guard_daemon",
        lambda _home, *, home_dir=None: "http://127.0.0.1:4782",
    )

    recovered = daemon_manager_module.recover_guard_daemon_after_hook_failure(
        guard_home,
        failure_kind="overload",
    )

    assert recovered == "http://127.0.0.1:4782"
    assert retired == []


def test_recovery_republishes_approval_center_after_starting_new_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    published: list[tuple[Path, str]] = []
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "ensure_guard_daemon",
        lambda _home, *, home_dir=None: "http://127.0.0.1:4782",
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "publish_approval_center_locator",
        lambda received_home, daemon_url: published.append((received_home, daemon_url)),
    )

    recovered = daemon_manager_module.recover_guard_daemon_after_hook_failure(
        guard_home,
        home_dir=home_dir,
        failure_kind="transport-failure",
    )

    assert recovered == "http://127.0.0.1:4782"
    assert published == [(guard_home, "http://127.0.0.1:4782")]


def test_recovery_keeps_live_daemon_when_locator_publication_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "ensure_guard_daemon",
        lambda _home, *, home_dir=None: "http://127.0.0.1:4782",
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "publish_approval_center_locator",
        lambda _home, _url: (_ for _ in ()).throw(OSError("write interrupted")),
    )

    recovered = daemon_manager_module.recover_guard_daemon_after_hook_failure(
        guard_home,
        failure_kind="transport-failure",
    )

    assert recovered == "http://127.0.0.1:4782"
    assert any(event["event"] == "locator_publish_failed" for event in load_daemon_lifecycle_events(guard_home))


def test_recovery_records_trigger_and_missing_authenticated_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    state = {
        **_old_generation(),
        "pid": 999_999,
        "state_id": "stopped-generation",
    }
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: False)
    monkeypatch.setattr(
        daemon_manager_module,
        "ensure_guard_daemon",
        lambda _home, *, home_dir=None: "http://127.0.0.1:4782",
    )

    recovered = daemon_manager_module.recover_guard_daemon_after_hook_failure(
        guard_home,
        failure_kind="transport-failure",
    )

    assert recovered == "http://127.0.0.1:4782"
    events = load_daemon_lifecycle_events(guard_home)
    assert [(event["event"], event.get("reason")) for event in events] == [
        ("recovery_requested", "transport-failure"),
        ("death_observed", "process_missing"),
    ]
    assert events[-1]["pid"] == 999_999
    assert events[-1].get("session_id") == "stopped-generation"


def test_recovery_preserves_authenticated_live_process_when_health_probe_misses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    state = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "source_root": daemon_manager_module._current_guard_daemon_source_root(),
        "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "pid": 4321,
        "port": 4781,
    }
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: expected_guard_home == guard_home,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "ensure_guard_daemon",
        lambda _home, *, home_dir=None: pytest.fail("a proven live generation must not be replaced"),
    )

    recovered = daemon_manager_module.recover_guard_daemon_after_hook_failure(
        guard_home,
        failure_kind="overload",
    )

    assert recovered == "http://127.0.0.1:4781"


def test_transport_recovery_preserves_authenticated_process_when_health_probe_misses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    state = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "source_root": daemon_manager_module._current_guard_daemon_source_root(),
        "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "pid": 4321,
        "port": 4781,
    }
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: expected_guard_home == guard_home,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "retire_all_guard_daemons_for_home",
        lambda _home: pytest.fail("a transport timeout must not retire a proven live daemon"),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "ensure_guard_daemon",
        lambda _home, *, home_dir=None: pytest.fail("a proven live generation must not be replaced"),
    )

    recovered = daemon_manager_module.recover_guard_daemon_after_hook_failure(
        guard_home,
        failure_kind="transport-failure",
    )

    assert recovered == "http://127.0.0.1:4781"


def test_transport_recovery_preserves_verified_old_process_when_health_probe_misses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    state = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "source_root": daemon_manager_module._current_guard_daemon_source_root(),
        "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
        **_old_generation(),
        "pid": 4321,
        "port": 4781,
    }
    retired: list[Path] = []
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: expected_guard_home == guard_home,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "retire_all_guard_daemons_for_home",
        lambda home: retired.append(home) or [],
    )
    monkeypatch.setattr(daemon_manager_module, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "ensure_guard_daemon",
        lambda _home, *, home_dir=None: "http://127.0.0.1:4782",
    )

    recovered = daemon_manager_module.recover_guard_daemon_after_hook_failure(
        guard_home,
        failure_kind="transport-failure",
    )

    assert recovered == "http://127.0.0.1:4781"
    assert retired == []


def test_recovery_does_not_reuse_recent_stale_runtime_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    stale_state: dict[str, object] = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "source_root": daemon_manager_module._current_guard_daemon_source_root(),
        "runtime_fingerprint": "stale-runtime-fingerprint",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    start_count = 0

    def ensure(_home: Path, *, home_dir: Path | None = None) -> str:
        nonlocal start_count
        del home_dir
        start_count += 1
        return "http://127.0.0.1:4782"

    assert not daemon_manager_module._guard_daemon_state_matches_current_runtime(stale_state)
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: stale_state)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "ensure_guard_daemon", ensure)
    monkeypatch.setattr(
        daemon_manager_module,
        "retire_all_guard_daemons_for_home",
        lambda _home: pytest.fail("ensure_guard_daemon owns stale runtime retirement"),
    )

    recovered = daemon_manager_module.recover_guard_daemon_after_hook_failure(
        guard_home,
        failure_kind="overload",
    )

    assert recovered == "http://127.0.0.1:4782"
    assert start_count == 1


def test_recovery_preserves_old_live_generation_for_concurrent_control_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    generation_lock = threading.Lock()
    generation_state = _old_generation()
    generation_url: str | None = "http://127.0.0.1:4781"
    retire_count = 0
    start_count = 0

    def load_state(_home: Path) -> dict[str, object]:
        with generation_lock:
            return generation_state

    def load_url(_home: Path) -> str | None:
        with generation_lock:
            return generation_url

    def retire(_home: Path) -> list[int]:
        nonlocal retire_count
        retire_count += 1
        return []

    def ensure(_home: Path, *, home_dir: Path | None = None) -> str:
        nonlocal generation_state, generation_url, start_count
        del home_dir
        start_count += 1
        with generation_lock:
            generation_state = _recent_generation()
            generation_url = "http://127.0.0.1:4782"
        return "http://127.0.0.1:4782"

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_lock", lambda _home: nullcontext())
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", load_state)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", load_url)
    monkeypatch.setattr(daemon_manager_module, "retire_all_guard_daemons_for_home", retire)
    monkeypatch.setattr(daemon_manager_module, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(daemon_manager_module, "ensure_guard_daemon", ensure)
    results: list[str] = []

    start_gate = threading.Barrier(32, timeout=10)
    barrier_errors: list[threading.BrokenBarrierError] = []

    def recover() -> None:
        try:
            start_gate.wait()
        except threading.BrokenBarrierError as error:
            barrier_errors.append(error)
            return
        results.append(daemon_manager_module.recover_guard_daemon_after_hook_failure(guard_home))

    workers = [threading.Thread(target=recover) for _ in range(32)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=2)

    assert all(not worker.is_alive() for worker in workers)
    assert barrier_errors == []
    assert retire_count == 0
    assert start_count == 0
    assert results == ["http://127.0.0.1:4781"] * 32


def test_recovery_lock_serializes_separate_processes(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    with daemon_manager_module._guard_daemon_recovery_lock(guard_home):
        script = (
            "from pathlib import Path;"
            "from codex_plugin_scanner.guard.daemon.manager import _guard_daemon_recovery_lock;"
            f"home=Path({str(guard_home)!r});"
            "lock=_guard_daemon_recovery_lock(home);"
            "lock.__enter__();"
            "print('acquired', flush=True);"
            "lock.__exit__(None,None,None)"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.2)
        assert process.poll() is None

    stdout, stderr = process.communicate(timeout=5)

    assert process.returncode == 0, stderr
    assert stdout.strip() == "acquired"


def test_managed_daemon_launch_disables_idle_shutdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_manager_module, "_guard_home_is_ephemeral", lambda _home: False)

    child_env = daemon_manager_module._daemon_launcher_env(
        home_dir=tmp_path,
        guard_home=tmp_path / "guard-home",
    )

    assert child_env["GUARD_DAEMON_IDLE_TIMEOUT_SECONDS"] == "0"


def test_ephemeral_daemon_launch_retains_server_idle_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_manager_module, "_guard_home_is_ephemeral", lambda _home: True)

    child_env = daemon_manager_module._daemon_launcher_env(
        home_dir=tmp_path,
        guard_home=tmp_path / "guard-home",
    )

    assert "GUARD_DAEMON_IDLE_TIMEOUT_SECONDS" not in child_env
