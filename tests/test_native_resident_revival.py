"""Fast failure, revival, and respawn of a native resident that is down."""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_resident_client as client_module
from codex_plugin_scanner.guard import native_resident_revival as revival
from codex_plugin_scanner.guard import native_resident_watchdog as watchdog
from codex_plugin_scanner.guard.cli import commands_lifecycle_gate as lifecycle_gate
from codex_plugin_scanner.guard.native_resident_client import _PersistentNativeClientPool

_BLOCKED = b'{"error":"native_resident_restart_circuit_open","retryable":false}'


@pytest.fixture(autouse=True)
def _clean_holds() -> None:
    revival._HOLDS.clear()


def _pool(tmp_path: Path) -> _PersistentNativeClientPool:
    return _PersistentNativeClientPool(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "native-runtime",
        environment={},
    )


def _fake_clients(monkeypatch: pytest.MonkeyPatch, responses: list[bytes]) -> list[object]:
    clients: list[object] = []

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            clients.append(self)

        def request(self, _payload: bytes, *, deadline_monotonic: float) -> bytes | None:
            del deadline_monotonic
            return responses.pop(0)

        def close(self, *, deadline_monotonic: float) -> bool:
            del deadline_monotonic
            return True

    monkeypatch.setattr(client_module, "_PersistentNativeClient", Client)
    return clients


def test_refused_respawn_fails_fast_without_spawning_a_client_per_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clients = _fake_clients(monkeypatch, [_BLOCKED])
    pool = _pool(tmp_path)
    deadline = time.monotonic() + 5

    assert pool.request(b"first", deadline_monotonic=deadline) == _BLOCKED
    assert client_module.native_resident_client_failure_code() == revival.RESTART_BLOCKED_CODE
    assert len(clients) == 1
    client_module.record_native_resident_client_failure_code(None)
    started = time.monotonic()
    for _ in range(20):
        assert pool.request(b"again", deadline_monotonic=deadline) == _BLOCKED
    assert client_module.native_resident_client_failure_code() == revival.RESTART_BLOCKED_CODE
    assert time.monotonic() - started < 0.5
    assert len(clients) == 1, "a held refusal must not spawn another stream"


def test_hold_expires_so_the_pool_probes_the_respawn_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clients = _fake_clients(monkeypatch, [_BLOCKED, b'{"schema":"ok"}'])
    pool = _pool(tmp_path)
    deadline = time.monotonic() + 5
    assert pool.request(b"first", deadline_monotonic=deadline) == _BLOCKED

    revival._HOLDS[pool._hold_key] = time.monotonic() - 1

    assert pool.request(b"probe", deadline_monotonic=deadline) == b'{"schema":"ok"}'
    assert len(clients) == 2
    assert not revival.restart_hold_active(pool._hold_key)


def test_a_refused_runtime_does_not_hold_another_runtime_for_the_same_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clients = _fake_clients(monkeypatch, [_BLOCKED, b'{"schema":"ok"}'])
    deadline = time.monotonic() + 5
    assert _pool(tmp_path).request(b"first", deadline_monotonic=deadline) == _BLOCKED

    updated = _PersistentNativeClientPool(
        executable=tmp_path / "runtime-updated",
        state_dir=tmp_path / "native-runtime",
        environment={},
    )

    assert updated.request(b"first", deadline_monotonic=deadline) == b'{"schema":"ok"}'
    assert len(clients) == 2


def test_other_startup_failures_do_not_arm_the_hold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    other = b'{"error":"native_resident_state_dir_create_failed","retryable":false}'
    clients = _fake_clients(monkeypatch, [other, b'{"schema":"ok"}'])
    pool = _pool(tmp_path)
    deadline = time.monotonic() + 5
    assert pool.request(b"first", deadline_monotonic=deadline) == other
    assert pool.request(b"second", deadline_monotonic=deadline) == b'{"schema":"ok"}'
    assert len(clients) == 2


def test_hold_helpers_arm_expire_and_clear(tmp_path: Path) -> None:
    key = (str(tmp_path / "runtime"), str(tmp_path / "native-runtime"))
    assert not revival.restart_hold_active(key)
    revival.arm_restart_hold(key, now=100.0)
    assert revival.restart_hold_active(key, now=100.0 + revival.RESTART_HOLD_SECONDS - 0.1)
    assert not revival.restart_hold_active(key, now=100.0 + revival.RESTART_HOLD_SECONDS + 0.1)
    revival.arm_restart_hold(key)
    revival.clear_restart_hold(key)
    assert not revival.restart_hold_active(key)


def test_restart_blocked_frame_matches_only_the_exact_refusal() -> None:
    assert revival.is_restart_blocked_frame(_BLOCKED)
    assert not revival.is_restart_blocked_frame(b'{"error":"native_resident_restart_circuit_open","retryable":true}')
    assert not revival.is_restart_blocked_frame(b'{"error":"native_resident_start_timeout","retryable":false}')


def test_unavailable_reason_names_repair_only_when_respawn_is_refused() -> None:
    default = "HOL Guard could not complete the native hook decision safely."
    assert "hol-guard repair" in revival.native_unavailable_reason("native_resident_restart_circuit_open", default)
    assert revival.native_unavailable_reason("native_client_timed_out", default) == default
    assert revival.native_unavailable_reason(None, default) == default


def test_reset_runs_the_native_command_and_clears_the_hold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, ...]] = []

    def run(command: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        seen.append(command)
        return SimpleNamespace(returncode=0, timed_out=False, containment_failed=False)

    monkeypatch.setattr(revival, "run_isolated_hook_process", run)
    key = (str(tmp_path / "runtime"), str(tmp_path / "native-runtime"))
    revival.arm_restart_hold(key)

    assert revival.reset_native_resident_restart_pacing(
        executable=tmp_path / "runtime", guard_home=tmp_path, environment={}
    )

    assert seen == [
        (str(tmp_path / "runtime"), "resident-reset-restart-budget", "--state-dir", str(tmp_path / "native-runtime"))
    ]
    assert not revival.restart_hold_active(key)


def test_reset_reports_failure_when_the_command_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        revival,
        "run_isolated_hook_process",
        lambda *_a, **_k: SimpleNamespace(returncode=2, timed_out=False, containment_failed=False),
    )
    assert not revival.reset_native_resident_restart_pacing(
        executable=tmp_path / "runtime", guard_home=tmp_path, environment={}
    )

    def explode(*_a: object, **_k: object) -> None:
        raise OSError("no launcher")

    monkeypatch.setattr(revival, "run_isolated_hook_process", explode)
    assert not revival.reset_native_resident_restart_pacing(
        executable=tmp_path / "runtime", guard_home=tmp_path, environment={}
    )


def _repair_args() -> argparse.Namespace:
    return argparse.Namespace(guard_command="repair")


def test_repair_revives_the_runtime_before_the_approval_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    monkeypatch.setattr(lifecycle_gate, "revive_native_resident", lambda home: order.append("revive") or True)

    def gate(home: Path) -> SimpleNamespace:
        del home
        order.append("gate")
        return SimpleNamespace(enabled=False, totp_enabled=False, cooldown_seconds=0)

    monkeypatch.setattr(lifecycle_gate, "public_config", gate)
    monkeypatch.setattr(lifecycle_gate, "consume_desktop_lifecycle_env", lambda **_k: None)
    monkeypatch.setattr(lifecycle_gate, "lifecycle_authority_home", lambda home, requirement: home)

    lifecycle_gate.enforce_lifecycle_gate(_repair_args(), guard_home=tmp_path, error_stream=io.StringIO())

    assert order == ["revive", "gate"]


def test_other_commands_do_not_revive_the_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    revived: list[Path] = []
    monkeypatch.setattr(lifecycle_gate, "revive_native_resident", lambda home: revived.append(home) or True)
    monkeypatch.setattr(
        lifecycle_gate,
        "public_config",
        lambda home: SimpleNamespace(enabled=False, totp_enabled=False, cooldown_seconds=0),
    )
    monkeypatch.setattr(lifecycle_gate, "consume_desktop_lifecycle_env", lambda **_k: None)
    monkeypatch.setattr(lifecycle_gate, "lifecycle_authority_home", lambda home, requirement: home)
    args = argparse.Namespace(guard_command="uninstall", self_uninstall=False, all=False, harness="codex")

    lifecycle_gate.enforce_lifecycle_gate(args, guard_home=tmp_path, error_stream=io.StringIO())

    assert revived == []


def _dead_pid() -> int:
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    process.wait()
    return process.pid


def _publish(state_dir: Path, pid: int, marker: str | None = None) -> None:
    generation = state_dir / "resident-v3-abc" / "generation-1.json"
    generation.parent.mkdir(parents=True)
    state: dict[str, object] = {"process_id": pid}
    if marker is not None:
        state["process_start_marker"] = marker
    generation.write_text(json.dumps(state), encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="pid probing is POSIX only")
def test_watchdog_detects_published_state_with_a_dead_process(tmp_path: Path) -> None:
    state_dir = tmp_path / "native-runtime"
    assert not watchdog.resident_provably_dead(state_dir)
    _publish(state_dir, _dead_pid())
    assert watchdog.resident_provably_dead(state_dir)


@pytest.mark.skipif(os.name == "nt", reason="pid probing is POSIX only")
def test_watchdog_treats_a_reused_linux_pid_as_dead(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(watchdog, "process_start_token", lambda _pid: "linux:200")
    reused = tmp_path / "reused"
    _publish(reused, os.getpid(), "linux:100")
    assert watchdog.resident_provably_dead(reused)
    same = tmp_path / "same"
    _publish(same, os.getpid(), "linux:200")
    assert not watchdog.resident_provably_dead(same)
    darwin = tmp_path / "darwin"
    _publish(darwin, os.getpid(), "darwin:1:2")
    assert not watchdog.resident_provably_dead(darwin)
    monkeypatch.setattr(watchdog, "process_start_token", lambda _pid: None)
    assert not watchdog.resident_provably_dead(reused), "an unreadable marker stays conservative"


@pytest.mark.skipif(os.name == "nt", reason="pid probing is POSIX only")
def test_watchdog_leaves_live_and_unreadable_residents_alone(tmp_path: Path) -> None:
    live = tmp_path / "live"
    _publish(live, os.getpid())
    assert not watchdog.resident_provably_dead(live)
    broken = tmp_path / "broken"
    (broken / "resident-v3-abc").mkdir(parents=True)
    (broken / "resident-v3-abc" / "generation-1.json").write_text("{nope", encoding="utf-8")
    assert not watchdog.resident_provably_dead(broken)


@pytest.mark.skipif(os.name == "nt", reason="pid probing is POSIX only")
def test_watchdog_respawns_only_a_tracked_dead_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state_dir = tmp_path / "native-runtime"
    _publish(state_dir, _dead_pid())
    calls: list[Path] = []
    monkeypatch.setattr("codex_plugin_scanner.guard.approval_gate.public_config", lambda home: calls.append(home))

    monkeypatch.setattr(watchdog, "tracked_native_resident_state_dirs", lambda _home: ())
    assert not watchdog.respawn_dead_resident(tmp_path)
    assert calls == []

    monkeypatch.setattr(watchdog, "tracked_native_resident_state_dirs", lambda _home: (state_dir,))
    assert watchdog.respawn_dead_resident(tmp_path)
    assert calls == [tmp_path]


@pytest.mark.skipif(os.name == "nt", reason="pid probing is POSIX only")
def test_watchdog_treats_a_refused_respawn_as_not_respawned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.approval_gate_types import ApprovalGateError

    state_dir = tmp_path / "native-runtime"
    _publish(state_dir, _dead_pid())

    def refused(home: Path) -> None:
        del home
        raise ApprovalGateError("native_approval_gate_unavailable", "native approval authority did not answer")

    monkeypatch.setattr("codex_plugin_scanner.guard.approval_gate.public_config", refused)
    monkeypatch.setattr(watchdog, "tracked_native_resident_state_dirs", lambda _home: (state_dir,))
    assert not watchdog.respawn_dead_resident(tmp_path)


def test_route_unavailable_body_names_a_refused_respawn() -> None:
    client_module.record_native_resident_client_failure_code(revival.RESTART_BLOCKED_CODE)
    assert revival.native_route_unavailable_body() == {
        "error": "native_route_policy_unavailable",
        "reason_code": revival.RESTART_BLOCKED_CODE,
    }
    client_module.record_native_resident_client_failure_code("native_client_pool_exhausted")
    assert revival.native_route_unavailable_body() == {"error": "native_route_policy_unavailable"}
    client_module.record_native_resident_client_failure_code(None)


def test_watchdog_thread_respawns_repeatedly_and_survives_errors(tmp_path: Path) -> None:
    stop = threading.Event()
    errors: list[str] = []
    ticks = threading.Semaphore(0)
    attempts = 0

    def respawn(home: Path) -> bool:
        nonlocal attempts
        del home
        attempts += 1
        ticks.release()
        if attempts == 1:
            raise RuntimeError("boom")
        return True

    thread = watchdog.start_native_resident_watchdog(
        tmp_path, stop=stop, on_error=errors.append, interval=0.01, respawn=respawn
    )
    assert ticks.acquire(timeout=5)
    assert ticks.acquire(timeout=5)
    stop.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert errors == ["native_resident_watchdog_failed"]
    assert attempts >= 2


def _unavailable_denial(tmp_path: Path, failure_code: str | None, event_name: str = "PreToolUse") -> str:
    from codex_plugin_scanner.guard.daemon.hook_worker_native import _record_unavailable_native
    from codex_plugin_scanner.guard.native_resident_client import record_native_resident_client_failure_code

    host = SimpleNamespace(metrics=SimpleNamespace(record_route=lambda _route: None), activity_writer=None)
    record_native_resident_client_failure_code(failure_code)
    try:
        response = _record_unavailable_native(
            cast(Any, host),
            {"hook_event_name": event_name, "tool_name": "Bash", "tool_input": {"command": "ls"}, "prompt": "hi"},
            harness="codex",
            event_name=event_name,
            reason_code="native_pre_tool_unavailable",
            guard_home=tmp_path,
        )
    finally:
        record_native_resident_client_failure_code(None)
    return json.dumps(response)


def test_pre_tool_denial_names_repair_when_the_runtime_will_not_restart(tmp_path: Path) -> None:
    assert "hol-guard repair" in _unavailable_denial(tmp_path, "native_resident_restart_circuit_open")
    assert "hol-guard repair" not in _unavailable_denial(tmp_path, "native_client_timed_out")


def test_prompt_denial_names_repair_when_the_runtime_will_not_restart(tmp_path: Path) -> None:
    refused = _unavailable_denial(tmp_path, "native_resident_restart_circuit_open", "UserPromptSubmit")
    assert "hol-guard repair" in refused
    timed_out = _unavailable_denial(tmp_path, "native_client_timed_out", "UserPromptSubmit")
    assert "hol-guard repair" not in timed_out
    assert "could not complete native prompt review safely" in timed_out
