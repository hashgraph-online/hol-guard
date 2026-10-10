from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import time
import uuid
from contextlib import contextmanager, nullcontext
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import live_process_identity
from codex_plugin_scanner.guard.cli import commands_daemon_recovery as recovery_cli
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon import user_recovery as recovery_module
from codex_plugin_scanner.guard.daemon.user_recovery import (
    AuthorizationDecision,
    ProcessIdentity,
    ProtectionResult,
    ReadyResult,
    RecoveryHooks,
    ServiceInspection,
    StartResult,
    StopResult,
    UserRecoveryCoordinator,
)


def _current_owner_marker() -> str:
    marker = live_process_identity.process_owner_marker(os.getpid())
    assert marker is not None
    return marker


def _identity(guard_home: Path, *, pid: int = 41, generation: str = "generation-1") -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        generation=generation,
        runtime="runtime-1",
        guard_home=guard_home,
        user=_current_owner_marker(),
        start_marker=f"start-{generation}",
    )


def _pending_snapshot(phase: str) -> dict[str, object]:
    return {
        "schema": "hol-guard-recovery.v1",
        "capabilities": ["diagnostics", "inspect", "restart", "status"],
        "operationId": "12121212-1212-4212-8212-121212121212",
        "sequence": 2,
        "startedAt": "2026-09-20T12:00:00+00:00",
        "updatedAt": "2026-09-20T12:00:01+00:00",
        "phase": phase,
        "activeElapsedMs": 1000,
        "workerActive": True,
        "retryAllowed": False,
        "outcome": "pending",
        "reasonCode": "healthy",
        "service": "ready",
        "protection": "unknown",
        "requiresHumanAction": False,
        "checks": [],
    }


def _coordinator(
    tmp_path: Path,
    service: ServiceInspection,
    *,
    posture: str = "on",
    protection_posture=None,
    authorize: AuthorizationDecision | None = None,
    authorize_hook=None,
    stop_process=None,
    process_dead=None,
    start_process=None,
    verify_ready=None,
    protection_health=None,
    inspect_service=None,
    recovery_lock=None,
    start_lock=None,
    update_busy=None,
    calls: list[str] | None = None,
    clock=None,
    active_budget_seconds: float = 60.0,
    lock_timeout_seconds: float = 0.0,
    load_snapshot=None,
    load_receipt=None,
    persist_snapshot=None,
    use_default_stop_process: bool = False,
) -> UserRecoveryCoordinator:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    observed = calls if calls is not None else []

    def inspect(_home: Path, _state: object, timeout: float | None = None) -> ServiceInspection:
        observed.append("inspect")
        if inspect_service is not None:
            return recovery_module._call_hook(inspect_service, timeout)
        return service

    hooks = RecoveryHooks(
        clock=clock or (lambda: 100.0),
        wall_clock=lambda: __import__("datetime").datetime(2026, 9, 20, tzinfo=__import__("datetime").timezone.utc),
        load_state=lambda _home: {"state": "fixture"},
        inspect_service=inspect,
        protection_posture=protection_posture or (lambda _home: posture),
        authorize=authorize_hook or (lambda _home: authorize if authorize is not None else True),
        update_busy=update_busy or (lambda _home: False),
        recovery_lock=recovery_lock or (lambda *_args: nullcontext()),
        start_lock=start_lock or (lambda *_args: nullcontext()),
        stop_process=(
            None
            if use_default_stop_process
            else (stop_process or (lambda _identity, _remaining: StopResult(True)))
        ),
        process_dead=process_dead or (lambda _identity: True),
        start_process=start_process or (lambda _home, _remaining: StartResult(True)),
        verify_ready=verify_ready or (lambda _home, identity, _remaining: ReadyResult(True, identity)),
        protection_health=protection_health
        or (lambda _home, _identity, _remaining: ProtectionResult("verified", "healthy")),
        load_snapshot=load_snapshot,
        load_receipt=load_receipt,
        persist_snapshot=persist_snapshot,
    )
    return UserRecoveryCoordinator(
        guard_home,
        hooks=hooks,
        active_budget_seconds=active_budget_seconds,
        lock_timeout_seconds=lock_timeout_seconds,
    )


def test_inspection_is_read_only_and_classifies_missing_service(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        calls=calls,
    )

    snapshot = coordinator.inspect()

    assert snapshot["operationId"] is None
    assert snapshot["phase"] == "checking"
    assert snapshot["reasonCode"] == "service_missing"
    assert snapshot["service"] == "unavailable"
    assert calls == ["inspect"]


@pytest.mark.parametrize(
    ("inventory", "expected_reason"),
    (
        ([], "service_missing"),
        ([{"pid": 41}], "identity_unverified"),
        ([{"pid": 41}, {"pid": 42}], "multiple_instances"),
    ),
)
def test_public_inspection_uses_default_manager_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inventory: list[object],
    expected_reason: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()

    class FakeManager:
        @staticmethod
        def load_authenticated_daemon_state(home: Path) -> None:
            assert home == guard_home
            return None

        @staticmethod
        def _running_guard_daemon_processes_for_guard_home(home: Path) -> list[object]:
            assert home == guard_home
            return inventory

    monkeypatch.setattr(recovery_module, "_manager", lambda: FakeManager())
    coordinator = UserRecoveryCoordinator(
        guard_home,
        hooks=RecoveryHooks(
            protection_posture=lambda _home: "on",
            update_busy=lambda _home: False,
        ),
    )
    before = tuple(guard_home.iterdir())

    snapshot = coordinator.inspect()

    assert snapshot["phase"] == "checking"
    assert snapshot["service"] == "unavailable"
    assert snapshot["reasonCode"] == expected_reason
    assert snapshot["retryAllowed"] is True
    assert tuple(guard_home.iterdir()) == before


def test_public_inspection_fails_closed_when_default_inventory_probe_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()

    class FakeManager:
        @staticmethod
        def load_authenticated_daemon_state(_home: Path) -> None:
            return None

        @staticmethod
        def _running_guard_daemon_processes_for_guard_home(_home: Path) -> list[object]:
            raise OSError("inventory unavailable")

    monkeypatch.setattr(recovery_module, "_manager", lambda: FakeManager())
    coordinator = UserRecoveryCoordinator(
        guard_home,
        hooks=RecoveryHooks(
            protection_posture=lambda _home: "on",
            update_busy=lambda _home: False,
        ),
    )

    snapshot = coordinator.inspect()

    assert snapshot["service"] == "unavailable"
    assert snapshot["reasonCode"] == "service_missing"
    assert snapshot["requiresHumanAction"] is False


@pytest.mark.parametrize(
    ("case", "expected_service", "expected_reason"),
    (
        ("invalid_state", "unavailable", "identity_unverified"),
        ("home_mismatch", "unavailable", "identity_unverified"),
        ("runtime_mismatch", "unavailable", "runtime_mismatch"),
        ("pid_missing", "unavailable", "service_missing"),
        ("endpoint_conflict", "unavailable", "endpoint_conflict"),
        ("endpoint_unknown", "unavailable", "identity_unverified"),
        ("probe_error", "unavailable", "service_unresponsive"),
        ("healthy", "ready", "healthy"),
    ),
)
def test_public_inspection_default_inspector_fails_closed_by_identity_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected_service: str,
    expected_reason: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    identity = _identity(guard_home)
    state: dict[str, object] = {
        "pid": identity.pid,
        "generation": identity.generation,
        "runtime": identity.runtime,
        "guard_home": str(guard_home),
        "user": identity.user,
        "start_marker": identity.start_marker,
    }
    if case == "invalid_state":
        state["pid"] = "not-a-pid"
    elif case == "home_mismatch":
        state["guard_home"] = str(tmp_path / "other-home")

    class FakeManager:
        @staticmethod
        def load_authenticated_daemon_state(home: Path) -> dict[str, object]:
            assert home == guard_home
            return state

        @staticmethod
        def _guard_daemon_state_matches_current_runtime(_state: dict[str, object]) -> bool:
            return case != "runtime_mismatch"

        @staticmethod
        def _guard_daemon_pid_is_running(_pid: int) -> bool:
            return case != "pid_missing"

        @staticmethod
        def _guard_daemon_pid_command_identity(
            _pid: int, *, expected_guard_home: Path
        ) -> bool | None:
            assert expected_guard_home == guard_home
            if case == "endpoint_conflict":
                return False
            if case == "endpoint_unknown":
                return None
            return True

    monkeypatch.setattr(recovery_module, "_manager", lambda: FakeManager())
    monkeypatch.setattr(recovery_module, "_identity_os_evidence_matches", lambda _identity: True)
    if case == "probe_error":
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.daemon.live_identity.probe_live_guard_daemon_identity",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("probe unavailable")),
        )
    else:
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.daemon.live_identity.probe_live_guard_daemon_identity",
            lambda _home, **_kwargs: ({**state, "daemon_url": "http://127.0.0.1:5474"}, "healthy"),
        )
    coordinator = UserRecoveryCoordinator(
        guard_home,
        hooks=RecoveryHooks(
            protection_posture=lambda _home: "on",
            update_busy=lambda _home: False,
        ),
    )

    snapshot = coordinator.inspect()

    assert snapshot["service"] == expected_service
    assert snapshot["reasonCode"] == expected_reason
    assert snapshot["phase"] == "checking"


def test_active_operation_without_latest_snapshot_returns_contract_snapshot(tmp_path: Path) -> None:
    active_request_id = uuid.UUID("12121212-1212-4212-8212-121212121212")
    concurrent_request_id = "34343434-3434-4434-8434-343434343434"
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
    )
    operation = recovery_module._Operation(
        operation_id=active_request_id,
        request_id=active_request_id,
        started_monotonic=100.0,
        deadline_monotonic=160.0,
        started_at="2026-09-20T12:00:00+00:00",
        execution_active=True,
    )
    home_key = str(coordinator.guard_home)
    operation_key = recovery_module._operation_key(home_key, active_request_id)
    with recovery_module._OPERATIONS_LOCK:
        recovery_module._ACTIVE_BY_HOME[home_key] = operation
        recovery_module._ACTIVE_BY_ID[operation_key] = operation
    emitted: list[dict[str, object]] = []
    try:
        result = coordinator.restart(concurrent_request_id, emit=emitted.append)
    finally:
        with recovery_module._OPERATIONS_LOCK:
            recovery_module._ACTIVE_BY_HOME.pop(home_key, None)
            recovery_module._ACTIVE_BY_ID.pop(operation_key, None)

    assert result["operationId"] == str(active_request_id)
    assert result["phase"] == "waiting_for_owner"
    assert result["reasonCode"] == "operation_busy"
    assert result["workerActive"] is True
    assert result["retryAllowed"] is False
    assert emitted == [result]


def test_healthy_service_reconnects_without_stop_or_start(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", identity, True, True, True),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )
    events: list[dict[str, object]] = []

    result = coordinator.restart("11111111-1111-4111-8111-111111111111", emit=events.append)

    assert result["phase"] == "complete"
    assert result["outcome"] == "reconnected"
    assert result["service"] == "ready"
    assert result["protection"] == "verified"
    assert "stop" not in calls
    assert "start" not in calls
    assert [event["phase"] for event in events] == ["checking", "checking", "reconnecting", "verifying", "complete"]


def test_public_inspection_accepts_validated_mapping_and_check_shapes(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    identity_mapping = {
        "pid": identity.pid,
        "generation": identity.generation,
        "runtime": identity.runtime,
        "guard_home": str(identity.guard_home),
        "user": identity.user,
        "start_marker": identity.start_marker,
    }
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unknown", "unknown"),
        inspect_service=lambda: {
            "service": "ready",
            "reasonCode": "healthy",
            "identity": identity_mapping,
            "process_running": True,
            "authenticated": True,
            "dashboard_ready": True,
                "protection": "verified",
                "checks": [
                    {"id": "process_identity", "result": "pass", "reasonCode": "healthy"},
                    {"id": "process_identity", "result": "fail", "reasonCode": "identity_unverified"},
                {"id": "not_a_check", "result": "pass", "reasonCode": "healthy"},
                "malformed",
            ],
        },
    )

    snapshot = coordinator.inspect()

    assert snapshot["service"] == "ready"
    assert snapshot["reasonCode"] == "healthy"
    assert snapshot["protection"] == "verified"
    checks = snapshot["checks"]
    identity_checks = [check for check in checks if check["id"] == "process_identity"]
    assert len(identity_checks) == 1
    assert identity_checks[0]["result"] == "pass"
    assert all(check["id"] != "not_a_check" for check in checks)
    assert {check["id"] for check in checks} >= {"process_identity", "authenticated_service", "dashboard_ready"}


def test_public_restart_accepts_mapping_authorization_start_readiness_and_protection(
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home, pid=83, generation="mapping-generation")
    identity_mapping = {
        "pid": identity.pid,
        "generation": identity.generation,
        "runtime": identity.runtime,
        "guard_home": str(identity.guard_home),
        "user": identity.user,
        "start_marker": identity.start_marker,
    }
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        authorize_hook=lambda _home: {
            "allowed": True,
            "requiresHumanAction": False,
            "reasonCode": "healthy",
        },
        start_process=lambda *_args: {
            "started": True,
            "identity": identity_mapping,
            "reasonCode": "healthy",
        },
        verify_ready=lambda *_args: {
            "ready": True,
            "identity": identity_mapping,
            "reasonCode": "healthy",
        },
        protection_health=lambda *_args: {"state": "verified", "reasonCode": "healthy"},
        calls=calls,
    )

    result = coordinator.restart("83838383-8383-4383-8383-838383838383")

    assert result["phase"] == "complete"
    assert result["outcome"] == "started"
    assert result["service"] == "ready"
    assert result["protection"] == "verified"


@pytest.mark.parametrize("stop_result", [True, {"exit_confirmed": True}])
def test_public_restart_accepts_confirmed_stop_compatibility_shapes_before_replacement(
    tmp_path: Path, stop_result: object
) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home, pid=84, generation="mapping-stop-generation")
    inspections = iter(
        [
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_missing", identity),
        ]
    )
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        inspect_service=lambda: next(inspections),
        stop_process=lambda *_args: calls.append("stop") or stop_result,
        process_dead=lambda *_args: pytest.fail("confirmed stop mapping required no fallback death check"),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
        calls=calls,
    )

    result = coordinator.restart("84848484-8484-4484-8484-848484848484")

    assert result["phase"] == "complete"
    assert result["outcome"] == "restarted"
    assert [call for call in calls if call in {"stop", "start"}] == ["stop", "start"]


@pytest.mark.parametrize(
    ("start_result", "expected_phase", "expected_reason", "expected_worker", "expected_retry"),
    (
        ("daemon-url", "needs_action", "identity_unverified", True, False),
        (object(), "failed", "startup_failed", False, True),
    ),
)
def test_public_restart_never_treats_untrusted_start_shapes_as_success(
    tmp_path: Path,
    start_result: object,
    expected_phase: str,
    expected_reason: str,
    expected_worker: bool,
    expected_retry: bool,
) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home, pid=86, generation="untrusted-start-shape")
    request_id = "86868686-8686-4686-8686-868686868687"
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        start_process=lambda *_args: start_result,
        verify_ready=lambda *_args: ReadyResult(True, identity),
    )

    try:
        result = coordinator.restart(request_id)
    finally:
        operation_id = uuid.UUID(request_id)
        home_key = str(coordinator.guard_home)
        with recovery_module._OPERATIONS_LOCK:
            recovery_module._ACTIVE_BY_HOME.pop(home_key, None)
            recovery_module._ACTIVE_BY_ID.pop(recovery_module._operation_key(home_key, operation_id), None)

    assert result["phase"] == expected_phase
    assert result["reasonCode"] == expected_reason
    assert result["workerActive"] is expected_worker
    assert result["retryAllowed"] is expected_retry
    assert result["requiresHumanAction"] is True


def test_public_restart_fails_closed_on_untrusted_readiness_shape(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home, pid=87, generation="untrusted-ready-shape")
    request_id = "87878787-8787-4787-8787-878787878788"
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        start_process=lambda *_args: StartResult(True, identity),
        verify_ready=lambda *_args: object(),
    )

    try:
        result = coordinator.restart(request_id)
    finally:
        operation_id = uuid.UUID(request_id)
        home_key = str(coordinator.guard_home)
        with recovery_module._OPERATIONS_LOCK:
            recovery_module._ACTIVE_BY_HOME.pop(home_key, None)
            recovery_module._ACTIVE_BY_ID.pop(recovery_module._operation_key(home_key, operation_id), None)

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "startup_failed"
    assert result["workerActive"] is True
    assert result["retryAllowed"] is False
    assert result["requiresHumanAction"] is True


def test_public_restart_does_not_start_after_unconfirmed_compatibility_stop_shape(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home, pid=88, generation="untrusted-stop-shape")
    inspections = iter(
        [
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
        ]
    )
    request_id = "88888888-8888-4888-8888-888888888889"
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        inspect_service=lambda: next(inspections),
        stop_process=lambda *_args: object(),
        process_dead=lambda *_args: False,
        start_process=lambda *_args: pytest.fail("unconfirmed stop must not start a replacement"),
    )

    try:
        result = coordinator.restart(request_id)
    finally:
        operation_id = uuid.UUID(request_id)
        home_key = str(coordinator.guard_home)
        with recovery_module._OPERATIONS_LOCK:
            recovery_module._ACTIVE_BY_HOME.pop(home_key, None)
            recovery_module._ACTIVE_BY_ID.pop(recovery_module._operation_key(home_key, operation_id), None)

    assert result["phase"] == "timed_out_waiting"
    assert result["reasonCode"] == "worker_exit_unconfirmed"
    assert result["workerActive"] is True
    assert result["retryAllowed"] is False
    assert result["requiresHumanAction"] is True


@pytest.mark.parametrize(
    ("protection_result", "expected_phase", "expected_state"),
    (
        ("verified", "complete", "verified"),
        (object(), "needs_action", "unknown"),
    ),
)
def test_public_restart_maps_string_and_invalid_protection_shapes(
    tmp_path: Path,
    protection_result: object,
    expected_phase: str,
    expected_state: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home, pid=89, generation="protection-shape")
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        start_process=lambda *_args: StartResult(True, identity),
        verify_ready=lambda *_args: ReadyResult(True, identity),
        protection_health=lambda *_args: protection_result,
    )

    result = coordinator.restart("89898989-8989-4898-8898-898989898989")

    assert result["phase"] == expected_phase
    assert result["protection"] == expected_state
    assert result["outcome"] == ("started" if expected_phase == "complete" else "not_recovered")


def test_invalid_authorization_hook_shape_fails_closed_before_mutation(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        authorize_hook=lambda _home: "allowed",
        start_process=lambda *_args: calls.append("start") or StartResult(True),
        calls=calls,
    )

    result = coordinator.restart("85858585-8585-4585-8585-858585858585")

    assert result["phase"] == "awaiting_approval"
    assert result["reasonCode"] == "approval_required"
    assert result["requiresHumanAction"] is True
    assert "start" not in calls


@pytest.mark.parametrize(
    ("protection_result", "expected_state", "expected_phase"),
    [(True, "verified", "complete"), (False, "needs_attention", "needs_action")],
)
def test_public_restart_maps_fresh_boolean_protection_results(
    tmp_path: Path,
    protection_result: bool,
    expected_state: str,
    expected_phase: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home, pid=85, generation=f"boolean-protection-{protection_result}")
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        start_process=lambda *_args: StartResult(True, identity),
        verify_ready=lambda *_args: ReadyResult(True, identity),
        protection_health=lambda *_args: protection_result,
    )

    result = coordinator.restart("85858585-8585-4585-8585-858585858586")

    assert result["phase"] == expected_phase
    assert result["protection"] == expected_state
    assert result["outcome"] == ("started" if protection_result else "not_recovered")


def test_boolean_start_hook_without_identity_never_reports_recovery_success(tmp_path: Path) -> None:
    request_id = "86868686-8686-4686-8686-868686868686"
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        start_process=lambda *_args: True,
        verify_ready=lambda *_args: ReadyResult(True, _identity(tmp_path / "guard-home")),
    )

    try:
        result = coordinator.restart(request_id)
        assert result["phase"] == "needs_action"
        assert result["reasonCode"] == "identity_unverified"
        assert result["workerActive"] is True
        assert result["retryAllowed"] is False
    finally:
        operation_id = uuid.UUID(request_id)
        home_key = str(coordinator.guard_home)
        with recovery_module._OPERATIONS_LOCK:
            recovery_module._ACTIVE_BY_HOME.pop(home_key, None)
            recovery_module._ACTIVE_BY_ID.pop(recovery_module._operation_key(home_key, operation_id), None)


def test_boolean_readiness_without_generation_never_reports_recovery_success(tmp_path: Path) -> None:
    request_id = "87878787-8787-4787-8787-878787878787"
    identity = _identity(tmp_path / "guard-home", generation="boolean-readiness")
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        start_process=lambda *_args: StartResult(True, identity),
        verify_ready=lambda *_args: True,
    )

    try:
        result = coordinator.restart(request_id)
        assert result["phase"] == "needs_action"
        assert result["reasonCode"] == "identity_unverified"
        assert result["workerActive"] is True
        assert result["retryAllowed"] is False
    finally:
        operation_id = uuid.UUID(request_id)
        home_key = str(coordinator.guard_home)
        with recovery_module._OPERATIONS_LOCK:
            recovery_module._ACTIVE_BY_HOME.pop(home_key, None)
            recovery_module._ACTIVE_BY_ID.pop(recovery_module._operation_key(home_key, operation_id), None)


def test_completed_request_uuid_replay_returns_cached_result_without_starting_again(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home, pid=81, generation="replay-generation")
    starts: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        start_process=lambda *_args: starts.append("start") or StartResult(True, identity),
        verify_ready=lambda *_args: ReadyResult(True, identity),
        protection_health=lambda *_args: ProtectionResult("verified", "healthy"),
    )
    request_id = "81818181-8181-4181-8181-818181818181"

    first = coordinator.restart(request_id)
    replay = coordinator.restart(request_id)

    assert first["phase"] == "complete"
    assert replay == first
    assert starts == ["start"]


def test_status_returns_completed_operation_and_rejects_unknown_request(tmp_path: Path) -> None:
    request_id = "82828282-8282-4282-8282-828282828282"
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
    )

    result = coordinator.restart(request_id)

    assert coordinator.status(request_id) == result
    with pytest.raises(KeyError):
        coordinator.status("83838383-8383-4383-8383-838383838383")


def test_status_reads_validated_durable_receipt_when_operation_is_not_in_memory(tmp_path: Path) -> None:
    request_id = "84848484-8484-4484-8484-848484848484"
    receipt = _pending_snapshot("verifying")
    receipt["operationId"] = request_id

    def load_receipt(_home: Path, operation_id: uuid.UUID) -> dict[str, object] | None:
        return receipt if str(operation_id) == request_id else None

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        load_receipt=load_receipt,
    )

    status = coordinator.status(request_id)

    assert status == receipt
    assert status["phase"] == "verifying"
    assert status["workerActive"] is True


def test_diagnostics_reads_validated_durable_receipt_when_operation_is_not_in_memory(tmp_path: Path) -> None:
    request_id = "93939393-9393-4393-8393-939393939393"
    receipt = _pending_snapshot("verifying")
    receipt["operationId"] = request_id

    def load_receipt(_home: Path, operation_id: uuid.UUID) -> dict[str, object] | None:
        return receipt if str(operation_id) == request_id else None

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        load_receipt=load_receipt,
    )

    report = coordinator.diagnostics(request_id)

    assert report["operationId"] == request_id
    assert report["eventCount"] == 1
    assert report["retainedEventCount"] == 1
    assert report["truncated"] is False
    assert report["latest"] == receipt
    assert report["events"] == [receipt]
    with pytest.raises(KeyError):
        coordinator.diagnostics("94949494-9494-4494-8494-949494949494")


@pytest.mark.parametrize("receipt_kind", ("non_mapping", "invalid_snapshot", "mismatched_operation"))
def test_restart_rejects_untrusted_durable_receipt_before_mutation(
    tmp_path: Path, receipt_kind: str
) -> None:
    request_id = "95959595-9595-4595-8595-959595959595"
    if receipt_kind == "non_mapping":
        raw_receipt: object = "corrupt-receipt"
    elif receipt_kind == "invalid_snapshot":
        raw_receipt = {"snapshot": {}}
    else:
        mismatched = _pending_snapshot("verifying")
        mismatched["operationId"] = "96969696-9696-4696-8696-969696969696"
        raw_receipt = mismatched

    calls: list[str] = []
    persisted: list[dict[str, object]] = []

    def load_receipt(_home: Path, _operation_id: uuid.UUID) -> object:
        return raw_receipt

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        calls=calls,
        load_receipt=load_receipt,
        persist_snapshot=lambda _home, snapshot: persisted.append(snapshot),
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
        verify_ready=lambda *_args: calls.append("ready") or ReadyResult(True),
        protection_health=lambda *_args: calls.append("protection") or ProtectionResult("verified", "healthy"),
    )

    result = coordinator.restart(request_id)

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "unknown"
    assert result["workerActive"] is True
    assert result["retryAllowed"] is False
    assert result["requiresHumanAction"] is True
    assert calls == ["inspect"]
    assert persisted == []


def test_dashboard_session_failure_preserves_healthy_daemon(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", identity, True, True, True),
        calls=calls,
        verify_ready=lambda *_args: ReadyResult(False, identity, "session_invalid"),
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("15151515-1515-4515-8515-151515151515")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "session_invalid"
    assert result["service"] == "ready"
    assert result["workerActive"] is False
    assert calls.count("stop") == 0
    assert calls.count("start") == 0


def test_reconnect_rejects_readiness_identity_replacement(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    expected = _identity(guard_home, pid=41, generation="generation-1")
    replacement = _identity(guard_home, pid=42, generation="generation-2")
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", expected, True, True, True),
        calls=calls,
        verify_ready=lambda *_args: ReadyResult(True, replacement),
        protection_health=lambda *_args: calls.append("protection") or ProtectionResult("verified", "healthy"),
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, replacement),
    )

    result = coordinator.restart("16161616-1616-4616-8616-161616161616")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert result["workerActive"] is False
    assert result["retryAllowed"] is True
    assert "protection" not in calls
    assert "stop" not in calls
    assert "start" not in calls
    assert str(guard_home) not in recovery_module._ACTIVE_BY_HOME


def test_start_rejects_readiness_identity_replacement(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    started = _identity(guard_home, pid=41, generation="generation-1")
    replacement = _identity(guard_home, pid=42, generation="generation-2")
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        calls=calls,
        start_process=lambda *_args: calls.append("start") or StartResult(True, started),
        verify_ready=lambda *_args: ReadyResult(True, replacement),
        protection_health=lambda *_args: calls.append("protection") or ProtectionResult("verified", "healthy"),
    )

    result = coordinator.restart("17171717-1717-4717-8717-171717171717")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert result["workerActive"] is True
    assert calls.count("start") == 1
    assert "protection" not in calls
    active = recovery_module._ACTIVE_BY_HOME.get(str(guard_home))
    assert active is not None
    assert active.unresolved_identity == started


@pytest.mark.parametrize("protection_state", ("unknown", "needs_attention"))
def test_reconnected_daemon_does_not_complete_without_verified_protection(
    tmp_path: Path,
    protection_state: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    emitted: list[dict[str, object]] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", identity, True, True, True, protection="verified"),
        protection_health=lambda *_args: ProtectionResult(protection_state, "unknown"),
    )

    result = coordinator.restart("18181818-1818-4818-8818-181818181818", emit=emitted.append)
    reconnecting = next(snapshot for snapshot in emitted if snapshot["phase"] == "reconnecting")
    verifying = next(snapshot for snapshot in emitted if snapshot["phase"] == "verifying")
    reconnecting_checks = {check["id"]: check for check in reconnecting["checks"]}
    verifying_checks = {check["id"]: check for check in verifying["checks"]}

    assert result["phase"] == "needs_action"
    assert result["outcome"] == "not_recovered"
    assert result["service"] == "ready"
    assert result["protection"] == protection_state
    assert result["requiresHumanAction"] is True
    assert result["workerActive"] is False
    assert str(guard_home) not in recovery_module._ACTIVE_BY_HOME
    assert reconnecting["protection"] == "unknown"
    assert reconnecting_checks["protection_health"]["result"] == "unknown"
    assert verifying["protection"] == "unknown"
    assert verifying_checks["protection_health"]["result"] == "unknown"


@pytest.mark.parametrize("protection_state", ("unknown", "needs_attention"))
def test_started_daemon_does_not_complete_without_verified_protection(
    tmp_path: Path,
    protection_state: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        start_process=lambda *_args: StartResult(True, identity),
        protection_health=lambda *_args: ProtectionResult(protection_state, "unknown"),
    )

    result = coordinator.restart("1a1a1a1a-1a1a-41a1-81a1-1a1a1a1a1a1a")

    assert result["phase"] == "needs_action"
    assert result["outcome"] == "not_recovered"
    assert result["service"] == "ready"
    assert result["protection"] == protection_state
    assert result["requiresHumanAction"] is True
    assert result["workerActive"] is False
    assert str(guard_home) not in recovery_module._ACTIVE_BY_HOME


def test_started_daemon_readiness_failure_does_not_reuse_protection_health_evidence(tmp_path: Path) -> None:
    identity = _identity(tmp_path / "guard-home")
    emitted: list[dict[str, object]] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing", protection="verified"),
        start_process=lambda *_args: StartResult(True, identity),
        verify_ready=lambda *_args: ReadyResult(False, identity, "startup_failed"),
        protection_health=lambda *_args: pytest.fail("failed readiness must not report protection health"),
    )

    result = coordinator.restart("78787878-7878-4878-8878-787878787878", emit=emitted.append)
    checks = {check["id"]: check for check in result["checks"]}
    reconnecting = next(snapshot for snapshot in emitted if snapshot["phase"] == "reconnecting")
    reconnecting_checks = {check["id"]: check for check in reconnecting["checks"]}

    assert result["phase"] == "failed"
    assert result["workerActive"] is True
    assert result["protection"] == "unknown"
    assert checks["protection_health"]["result"] == "unknown"
    assert reconnecting["protection"] == "unknown"
    assert reconnecting_checks["protection_health"]["result"] == "unknown"


def test_reconnect_readiness_deadline_keeps_worker_owned_until_reconciled(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home, generation="reconnect-generation")
    clock = {"value": 100.0}
    readiness_calls = 0
    calls: list[str] = []

    def verify_ready(_home: Path, observed: ProcessIdentity | None, _remaining: float) -> ReadyResult:
        nonlocal readiness_calls
        readiness_calls += 1
        assert observed == identity
        if readiness_calls == 1:
            clock["value"] = 101.0
            return ReadyResult(False, identity, "startup_failed")
        return ReadyResult(True, identity, "healthy")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", identity, True, True, True),
        calls=calls,
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        verify_ready=verify_ready,
        protection_health=lambda *_args: calls.append("protection") or ProtectionResult("verified", "healthy"),
    )

    first = coordinator.restart("1b1b1b1b-1b1b-41b1-81b1-1b1b1b1b1b1b")

    assert first["phase"] == "failed"
    assert first["reasonCode"] == "deadline_exceeded"
    assert first["service"] == "ready"
    assert first["workerActive"] is True
    assert first["retryAllowed"] is False
    assert "protection" not in calls

    reconciled = coordinator.restart("1c1c1c1c-1c1c-41c1-81c1-1c1c1c1c1c1c")

    assert reconciled["phase"] == "complete"
    assert reconciled["outcome"] == "reconnected"
    assert reconciled["workerActive"] is False
    assert reconciled["retryAllowed"] is True
    assert calls.count("protection") == 1
    assert "stop" not in calls
    assert "start" not in calls


def test_reconnect_protection_probe_exception_fails_closed_without_mutation(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home, generation="protection-generation")
    observed: dict[str, object] = {}
    calls: list[str] = []

    def verify_ready(_home: Path, observed_identity: ProcessIdentity | None, _remaining: float) -> ReadyResult:
        observed["ready"] = observed_identity
        return ReadyResult(True, identity, "healthy")

    def protection_health(_home: Path, observed_identity: ProcessIdentity | None, _remaining: float):
        observed["protection"] = observed_identity
        calls.append("protection")
        raise RuntimeError("protection probe unavailable")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", identity, True, True, True),
        calls=calls,
        verify_ready=verify_ready,
        protection_health=protection_health,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("1d1d1d1d-1d1d-41d1-81d1-1d1d1d1d1d1d")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "unknown"
    assert result["service"] == "ready"
    assert result["protection"] == "unknown"
    assert result["workerActive"] is False
    assert result["retryAllowed"] is True
    assert result["requiresHumanAction"] is True
    assert observed == {"ready": identity, "protection": identity}
    assert calls[-1] == "protection"
    assert "stop" not in calls
    assert "start" not in calls


def test_reconnect_session_failure_does_not_reuse_protection_health_evidence(tmp_path: Path) -> None:
    identity = _identity(tmp_path / "guard-home")
    emitted: list[dict[str, object]] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection(
            "ready",
            "healthy",
            identity,
            True,
            authenticated=True,
            dashboard_ready=True,
            protection="verified",
        ),
        verify_ready=lambda *_args: ReadyResult(False, identity, "session_invalid"),
        protection_health=lambda *_args: pytest.fail("session failure must not report protection health"),
    )

    result = coordinator.restart("56565656-5656-4565-8565-565656565656", emit=emitted.append)
    checks = {check["id"]: check for check in result["checks"]}
    reconnecting = next(snapshot for snapshot in emitted if snapshot["phase"] == "reconnecting")
    reconnecting_checks = {check["id"]: check for check in reconnecting["checks"]}

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "session_invalid"
    assert result["protection"] == "unknown"
    assert checks["protection_health"]["result"] == "unknown"
    assert reconnecting["protection"] == "unknown"
    assert reconnecting_checks["protection_health"]["result"] == "unknown"


def test_reconnect_timeout_does_not_reuse_protection_health_evidence(tmp_path: Path) -> None:
    identity = _identity(tmp_path / "guard-home")
    clock = {"now": 100.0}

    def verify_ready(*_args: object) -> ReadyResult:
        clock["now"] = 102.0
        return ReadyResult(False, identity, "deadline_exceeded")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection(
            "ready",
            "healthy",
            identity,
            True,
            authenticated=True,
            dashboard_ready=True,
            protection="verified",
        ),
        clock=lambda: clock["now"],
        active_budget_seconds=1.0,
        verify_ready=verify_ready,
    )

    result = coordinator.restart("67676767-6767-4676-8676-676767676767")
    checks = {check["id"]: check for check in result["checks"]}

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "deadline_exceeded"
    assert result["workerActive"] is True
    assert result["protection"] == "unknown"
    assert checks["protection_health"]["result"] == "unknown"


def test_unresponsive_service_without_identity_refuses_replacement(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", None, True),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("1e1e1e1e-1e1e-41e1-81e1-1e1e1e1e1e1e")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert result["workerActive"] is False
    assert result["retryAllowed"] is True
    assert result["requiresHumanAction"] is True
    assert calls == ["inspect", "inspect"]


def test_unresponsive_stop_exception_restarts_only_after_dead_proof(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    target = _identity(guard_home, generation="replacement-generation")
    inspections = iter(
        [
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_missing", target),
        ]
    )
    observed: dict[str, object] = {}

    def stop_process(observed_identity: ProcessIdentity, _remaining: float) -> None:
        observed["stop"] = observed_identity
        raise RuntimeError("stop failed")

    def process_dead(observed_identity: ProcessIdentity) -> bool:
        observed["dead"] = observed_identity
        return True

    def verify_ready(_home: Path, observed_identity: ProcessIdentity | None, _remaining: float) -> ReadyResult:
        observed["ready"] = observed_identity
        return ReadyResult(True, target, "healthy")

    def protection_health(_home: Path, observed_identity: ProcessIdentity | None, _remaining: float):
        observed["protection"] = observed_identity
        return ProtectionResult("verified", "healthy")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", target, True),
        inspect_service=lambda: next(inspections),
        stop_process=stop_process,
        process_dead=process_dead,
        start_process=lambda *_args: StartResult(True, target),
        verify_ready=verify_ready,
        protection_health=protection_health,
    )

    result = coordinator.restart("1f1f1f1f-1f1f-41f1-81f1-1f1f1f1f1f1f")

    assert result["phase"] == "complete"
    assert result["outcome"] == "restarted"
    assert result["workerActive"] is False
    assert result["retryAllowed"] is True
    assert observed == {
        "stop": target,
        "dead": target,
        "ready": target,
        "protection": target,
    }


@pytest.mark.parametrize(
    ("start_mode", "request_id"),
    (
        ("exception", "22222222-2222-4222-8222-222222222222"),
        ("rejected", "23232323-2323-4232-8232-232323232323"),
    ),
)
def test_missing_service_start_failure_is_public_without_readiness_probe(
    tmp_path: Path,
    start_mode: str,
    request_id: str,
) -> None:
    calls: list[str] = []

    def start_process(*_args: object):
        calls.append("start")
        if start_mode == "exception":
            raise RuntimeError("daemon start failed")
        return StartResult(False, None, "startup_failed")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        calls=calls,
        start_process=start_process,
        verify_ready=lambda *_args: pytest.fail("failed start must not probe readiness"),
        protection_health=lambda *_args: pytest.fail("failed start must not probe protection"),
    )

    result = coordinator.restart(request_id)

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "startup_failed"
    assert result["workerActive"] is (start_mode == "exception")
    assert result["retryAllowed"] is (start_mode == "rejected")
    assert result["requiresHumanAction"] is True
    assert calls[-1] == "start"
    assert calls.count("inspect") == 3


def test_start_exception_does_not_reuse_protection_health_evidence(
    tmp_path: Path,
) -> None:
    inspections = iter(
        [
            ServiceInspection("unavailable", "service_missing", protection="unknown"),
            ServiceInspection("unavailable", "service_missing", protection="verified"),
            ServiceInspection("unavailable", "service_missing", protection="unknown"),
        ]
    )

    def start_process(*_args: object) -> None:
        raise RuntimeError("start outcome is uncertain")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        inspect_service=lambda: next(inspections),
        start_process=start_process,
    )

    result = coordinator.restart("45454545-4545-4454-8454-454545454545")
    checks = {check["id"]: check for check in result["checks"]}

    assert result["phase"] == "failed"
    assert result["workerActive"] is True
    assert result["protection"] == "unknown"
    assert checks["protection_health"]["result"] == "unknown"


@pytest.mark.parametrize(
    ("start_mode", "request_id"),
    (
        ("exception", "33333333-3333-4333-8333-333333333333"),
        ("rejected", "34343434-3434-4434-8434-343434343434"),
    ),
)
def test_replacement_start_failure_is_public_without_readiness_probe(
    tmp_path: Path,
    start_mode: str,
    request_id: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    target = _identity(guard_home, generation="start-after-stop-generation")
    inspections = iter(
        [
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_missing", target),
        ]
    )
    calls: list[str] = []

    def start_process(*_args: object):
        calls.append("start")
        if start_mode == "exception":
            raise RuntimeError("replacement start failed")
        return StartResult(False, None, "startup_failed")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", target, True),
        inspect_service=lambda: next(inspections),
        calls=calls,
        stop_process=lambda _identity, _remaining: calls.append("stop") or StopResult(True),
        start_process=start_process,
        verify_ready=lambda *_args: pytest.fail("failed replacement must not probe readiness"),
        protection_health=lambda *_args: pytest.fail("failed replacement must not probe protection"),
    )

    result = coordinator.restart(request_id)

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "startup_failed"
    assert result["workerActive"] is (start_mode == "exception")
    assert result["retryAllowed"] is (start_mode == "rejected")
    assert result["requiresHumanAction"] is True
    assert [call for call in calls if call in {"stop", "start"}] == ["stop", "start"]


def test_same_generation_session_reconnect_uses_remaining_budget(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    observed_remaining: list[float] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", identity, True, True, True),
        active_budget_seconds=0.5,
        verify_ready=lambda _home, _identity, remaining: observed_remaining.append(remaining)
        or ReadyResult(True, identity),
    )

    result = coordinator.restart("19191919-1919-4919-8919-191919191919")

    assert result["phase"] == "complete"
    assert result["service"] == "ready"
    assert observed_remaining and 0.0 < observed_remaining[0] <= 0.5


def test_post_budget_inspection_and_readiness_use_remaining_deadline(tmp_path: Path) -> None:
    identity = _identity(tmp_path / "guard-home")
    clock = {"value": 100.0}
    inspection_timeouts: list[float | None] = []
    readiness_timeouts: list[float] = []

    def inspect(timeout: float | None = None) -> ServiceInspection:
        inspection_timeouts.append(timeout)
        if timeout is not None:
            clock["value"] += 0.25
        return ServiceInspection("ready", "healthy", identity, True, True, True)

    def verify_ready(_home: Path, _identity: ProcessIdentity | None, remaining: float) -> ReadyResult:
        readiness_timeouts.append(remaining)
        return ReadyResult(True, identity)

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", identity, True, True, True),
        inspect_service=inspect,
        verify_ready=verify_ready,
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
    )

    result = coordinator.restart("19191919-1919-4919-8919-191919191919")

    assert result["phase"] == "complete"
    assert inspection_timeouts[0] is None
    assert len(inspection_timeouts) >= 2
    assert any(timeout is not None for timeout in inspection_timeouts[1:])
    assert all(timeout is None or 0.0 < timeout <= 1.0 for timeout in inspection_timeouts)
    assert readiness_timeouts and 0.0 < readiness_timeouts[0] <= 1.0


def test_mapping_inspection_preserves_explicit_dashboard_session_failure(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)

    inspection = recovery_module._coerce_service(
        {
            "service": "ready",
            "reason_code": "session_invalid",
            "identity": {
                "pid": identity.pid,
                "generation": identity.generation,
                "runtime": identity.runtime,
                "guard_home": str(identity.guard_home),
                "user": identity.user,
                "start_marker": identity.start_marker,
            },
            "process_running": True,
            "authenticated": True,
            "dashboard_ready": False,
        },
        guard_home,
        None,
    )

    assert inspection.service == "ready"
    assert inspection.reason_code == "session_invalid"
    assert inspection.authenticated is True
    assert inspection.dashboard_ready is False


def test_default_inspector_session_failure_preserves_healthy_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    identity = _identity(guard_home)
    state = {
        "pid": identity.pid,
        "generation": identity.generation,
        "runtime": identity.runtime,
        "guard_home": str(guard_home),
        "user": identity.user,
        "start_marker": identity.start_marker,
    }
    probe_calls: list[ProcessIdentity] = []
    mutations: list[str] = []

    class FakeManager:
        @staticmethod
        def _guard_daemon_state_matches_current_runtime(_state: dict[str, object]) -> bool:
            return True

        @staticmethod
        def _guard_daemon_pid_is_running(_pid: int) -> bool:
            return True

        @staticmethod
        def _guard_daemon_pid_command_identity(_pid: int, *, expected_guard_home: Path) -> bool:
            assert expected_guard_home == guard_home
            return True

    def probe(_home: Path, *, session_timeout: float) -> tuple[dict[str, object], str]:
        assert 0.0 < session_timeout <= 1.0
        probe_calls.append(identity)
        return {**state, "daemon_url": "http://127.0.0.1:5474"}, "session_invalid"

    monkeypatch.setattr(recovery_module, "_manager", lambda: FakeManager())
    monkeypatch.setattr(recovery_module, "_identity_os_evidence_matches", lambda _identity: True)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.live_identity.probe_live_guard_daemon_identity",
        probe,
    )
    coordinator = UserRecoveryCoordinator(
        guard_home,
        hooks=RecoveryHooks(
            clock=lambda: 100.0,
            wall_clock=lambda: __import__("datetime").datetime(
                2026, 9, 20, tzinfo=__import__("datetime").timezone.utc
            ),
            load_state=lambda _home: state,
            protection_posture=lambda _home: "on",
            authorize=lambda _home: True,
            update_busy=lambda _home: False,
            recovery_lock=lambda *_args: nullcontext(),
            start_lock=lambda *_args: nullcontext(),
            stop_process=lambda *_args: mutations.append("stop") or StopResult(True),
            start_process=lambda *_args: mutations.append("start") or StartResult(True, identity),
            protection_health=lambda *_args: ProtectionResult("verified", "healthy"),
        ),
    )

    result = coordinator.restart("20202020-2020-4020-8020-202020202020")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "session_invalid"
    assert result["service"] == "ready"
    assert len(probe_calls) == 3
    assert all(item == identity for item in probe_calls)
    assert mutations == []


@pytest.mark.parametrize("mismatch", ("start", "owner"))
def test_default_inspector_rejects_reused_pid_without_os_identity_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    identity = _identity(guard_home)
    state = {
        "pid": identity.pid,
        "generation": identity.generation,
        "runtime": identity.runtime,
        "guard_home": str(guard_home),
        "user": identity.user,
        "start_marker": identity.start_marker,
    }

    class FakeManager:
        @staticmethod
        def _guard_daemon_state_matches_current_runtime(_state: dict[str, object]) -> bool:
            return True

        @staticmethod
        def _guard_daemon_pid_is_running(_pid: int) -> bool:
            return True

        @staticmethod
        def _guard_daemon_pid_command_identity(_pid: int, *, expected_guard_home: Path) -> bool:
            assert expected_guard_home == guard_home
            return True

    monkeypatch.setattr(recovery_module, "_manager", lambda: FakeManager())
    monkeypatch.setattr(
        live_process_identity,
        "process_start_token",
        lambda _pid: "start-reused" if mismatch == "start" else identity.start_marker,
    )
    monkeypatch.setattr(
        live_process_identity,
        "process_owner_marker",
        lambda _pid: "uid:other" if mismatch == "owner" else identity.user,
    )

    inspection = recovery_module._default_inspect_service(guard_home, state)

    assert inspection.service == "unavailable"
    assert inspection.reason_code == "identity_unverified"
    assert inspection.identity == identity


def test_default_inspector_rechecks_os_generation_after_session_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    identity = _identity(guard_home)
    state = {
        "pid": identity.pid,
        "generation": identity.generation,
        "runtime": identity.runtime,
        "guard_home": str(guard_home),
        "user": identity.user,
        "start_marker": identity.start_marker,
    }

    class FakeManager:
        @staticmethod
        def _guard_daemon_state_matches_current_runtime(_state: dict[str, object]) -> bool:
            return True

        @staticmethod
        def _guard_daemon_pid_is_running(_pid: int) -> bool:
            return True

        @staticmethod
        def _guard_daemon_pid_command_identity(_pid: int, *, expected_guard_home: Path) -> bool:
            assert expected_guard_home == guard_home
            return True

    start_markers = iter((identity.start_marker, "start-reused"))
    monkeypatch.setattr(recovery_module, "_manager", lambda: FakeManager())
    monkeypatch.setattr(
        live_process_identity,
        "process_start_token",
        lambda _pid: next(start_markers),
    )
    monkeypatch.setattr(live_process_identity, "process_owner_marker", lambda _pid: identity.user)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.live_identity.probe_live_guard_daemon_identity",
        lambda _home, **_kwargs: ({**state, "daemon_url": "http://127.0.0.1:5474"}, "healthy"),
    )

    inspection = recovery_module._default_inspect_service(guard_home, state)

    assert inspection.service == "unavailable"
    assert inspection.reason_code == "identity_unverified"
    assert inspection.identity == identity


def test_owned_unresponsive_service_is_stopped_then_started(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    inspections = iter(
        [
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_missing", identity),
        ]
    )
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        inspect_service=lambda: next(inspections),
        calls=calls,
        stop_process=lambda _identity, _remaining: calls.append("stop") or StopResult(True),
        start_process=lambda _home, _remaining: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("22222222-2222-4222-8222-222222222222")

    assert result["phase"] == "complete"
    assert result["outcome"] == "restarted"
    assert calls.count("stop") == 1
    assert calls.count("start") == 1


def test_identity_conflict_never_mutates_the_process(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "endpoint_conflict", _identity(tmp_path / "guard-home"), True),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("33333333-3333-4333-8333-333333333333")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "endpoint_conflict"
    assert calls == ["inspect", "inspect"]


def test_missing_process_start_token_refuses_stop_at_mutation_boundary(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = ProcessIdentity(41, "generation-1", "runtime-1", guard_home, _current_owner_marker(), None)
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("45454545-4545-4454-8454-454545454545")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert "stop" not in calls
    assert "start" not in calls


def test_wrong_process_owner_refuses_stop_at_mutation_boundary(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = ProcessIdentity(42, "generation-owner", "runtime-1", guard_home, "different-user", "start-owner")
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("46464646-4646-4464-8464-464646464646")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert "stop" not in calls
    assert "start" not in calls


def test_missing_authenticated_os_token_does_not_adopt_reused_pid_generation(
    tmp_path: Path, monkeypatch
) -> None:
    guard_home = tmp_path / "guard-home"
    identity = ProcessIdentity(43, "generation-state", "runtime-1", guard_home, _current_owner_marker(), None)
    retire_calls: list[dict[str, object]] = []

    monkeypatch.setattr(live_process_identity, "process_start_token", lambda _pid: "windows:live-generation")

    def retire(pid: int, **kwargs: object) -> bool:
        retire_calls.append({"pid": pid, **kwargs})
        return True

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        use_default_stop_process=True,
    )

    result = coordinator._stop_process(identity, 1.0)

    assert result is False
    assert retire_calls == []


def test_target_process_owner_marker_must_match_authenticated_state(
    tmp_path: Path, monkeypatch
) -> None:
    identity = _identity(tmp_path / "guard-home", pid=43)
    retire_calls: list[dict[str, object]] = []

    monkeypatch.setattr(live_process_identity, "process_start_token", lambda _pid: identity.start_marker)
    monkeypatch.setattr(live_process_identity, "process_owner_marker", lambda _pid: "uid:foreign")
    monkeypatch.setattr(
        daemon_manager_module,
        "_retire_guard_daemon_pid",
        lambda pid, **kwargs: retire_calls.append({"pid": pid, **kwargs}) or True,
    )

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        use_default_stop_process=True,
    )

    assert coordinator._stop_process(identity, 1.0) is False
    assert retire_calls == []


def test_wrong_runtime_and_home_refuse_stop_before_signal(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    target = ProcessIdentity(44, "generation-1", "runtime-1", guard_home, _current_owner_marker(), "start-1")
    changed = ProcessIdentity(
        44,
        "generation-1",
        "runtime-2",
        tmp_path / "other-home",
        _current_owner_marker(),
        "start-1",
    )
    inspections = iter(
        [
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", changed, True),
            ServiceInspection("unavailable", "service_unresponsive", changed, True),
            ServiceInspection("unavailable", "service_unresponsive", changed, True),
        ]
    )
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", target, True),
        calls=calls,
        inspect_service=lambda: next(inspections),
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, changed),
    )

    result = coordinator.restart("48484848-4848-4484-8484-484848484848")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert "stop" not in calls
    assert "start" not in calls


def test_generation_change_before_escalation_is_rejected_by_stop_boundary(
    tmp_path: Path, monkeypatch
) -> None:
    guard_home = tmp_path / "guard-home"
    identity = ProcessIdentity(45, "generation-1", "runtime-1", guard_home, _current_owner_marker(), "start-1")
    observed: dict[str, object] = {}

    def retire(
        pid: int,
        *,
        expected_guard_home: Path,
        expected_start_marker: str | None = None,
        **_kwargs: object,
    ) -> bool:
        observed.update(
            pid=pid,
            guard_home=expected_guard_home,
            start_marker=expected_start_marker,
        )
        return False

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)
    monkeypatch.setattr(live_process_identity, "process_start_token", lambda _pid: identity.start_marker)
    monkeypatch.setattr(live_process_identity, "process_owner_marker", lambda _pid: identity.user)
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        use_default_stop_process=True,
    )

    result = coordinator._stop_process(identity, 1.0)

    assert result is False
    assert observed == {
        "pid": identity.pid,
        "guard_home": guard_home,
        "start_marker": identity.start_marker,
    }


def test_generation_change_after_confirmed_stop_refuses_replacement_start(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    target = _identity(guard_home)
    changed = ProcessIdentity(
        target.pid,
        "generation-2",
        target.runtime,
        guard_home,
        target.user,
        "start-generation-2",
    )
    inspections = iter(
        [
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", changed, True),
        ]
    )
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", target, True),
        inspect_service=lambda: next(inspections),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, target),
    )

    result = coordinator.restart("47474747-4747-4474-8474-474747474747")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert [call for call in calls if call in {"stop", "start"}] == ["stop"]


def test_ambiguous_endpoint_after_confirmed_stop_refuses_replacement_start(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    target = _identity(guard_home)
    inspections = iter(
        [
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "service_unresponsive", target, True),
            ServiceInspection("unavailable", "endpoint_conflict", target, True),
        ]
    )
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", target, True),
        inspect_service=lambda: next(inspections),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, target),
    )

    result = coordinator.restart("48484848-4848-4484-8484-484848484848")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "endpoint_conflict"
    assert [call for call in calls if call in {"stop", "start"}] == ["stop"]


def test_protection_off_after_start_lock_prevents_start(tmp_path: Path) -> None:
    state = {"posture": "on"}
    calls: list[str] = []

    @contextmanager
    def start_lock(*_args: object):
        state["posture"] = "off"
        yield

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        protection_posture=lambda _home: state["posture"],
        start_lock=start_lock,
        calls=calls,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("49494949-4949-4494-8494-494949494949")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "protection_off"
    assert "start" not in calls


def test_protection_off_after_stop_lock_prevents_stop(tmp_path: Path) -> None:
    state = {"posture": "on"}
    identity = _identity(tmp_path / "guard-home")
    calls: list[str] = []

    @contextmanager
    def start_lock(*_args: object):
        state["posture"] = "off"
        yield

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        protection_posture=lambda _home: state["posture"],
        start_lock=start_lock,
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("4a4a4a4a-4a4a-44a4-84a4-4a4a4a4a4a4a")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "protection_off"
    assert "stop" not in calls
    assert "start" not in calls


def test_approval_invalidated_after_recovery_lock_prevents_start(tmp_path: Path) -> None:
    state = {"approved": True}
    calls: list[str] = []
    validation_calls: list[str] = []
    proof_prompt_calls: list[str] = []

    def authorize(_home: Path) -> AuthorizationDecision:
        validation_calls.append("validate")
        if len(validation_calls) == 1:
            proof_prompt_calls.append("prompt")
            return AuthorizationDecision(True)
        return AuthorizationDecision(False, True, "approval_required")

    @contextmanager
    def recovery_lock(*_args: object):
        state["approved"] = False
        yield

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        authorize_hook=authorize,
        recovery_lock=recovery_lock,
        calls=calls,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("4b4b4b4b-4b4b-44b4-84b4-4b4b4b4b4b4b")

    assert result["phase"] == "awaiting_approval"
    assert result["reasonCode"] == "approval_required"
    assert "start" not in calls
    assert validation_calls == ["validate", "validate"]
    assert proof_prompt_calls == ["prompt"]


def test_update_busy_at_initial_inspection_blocks_authorization_and_mutation(tmp_path: Path) -> None:
    calls: list[str] = []
    authorization_calls: list[str] = []

    def authorize(_home: Path) -> AuthorizationDecision:
        authorization_calls.append("authorize")
        return AuthorizationDecision(True)

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        update_busy=lambda _home: True,
        authorize_hook=authorize,
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("4d4d4d4d-4d4d-44d4-84d4-4d4d4d4d4d4d")

    assert result["phase"] == "waiting_for_owner"
    assert result["reasonCode"] == "update_busy"
    assert result["workerActive"] is False
    assert result["retryAllowed"] is False
    assert authorization_calls == []
    assert calls == ["inspect"]


def test_non_human_authorization_denial_returns_needs_action_without_mutation(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        authorize=AuthorizationDecision(False, False, "runtime_mismatch"),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("4e4e4e4e-4e4e-44e4-84e4-4e4e4e4e4e4e")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "runtime_mismatch"
    assert result["workerActive"] is False
    assert result["retryAllowed"] is False
    assert result["requiresHumanAction"] is True
    assert calls == ["inspect"]


def test_update_ownership_changed_after_start_lock_prevents_start(tmp_path: Path) -> None:
    state = {"busy": False}
    calls: list[str] = []

    @contextmanager
    def start_lock(*_args: object):
        state["busy"] = True
        yield

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        start_lock=start_lock,
        update_busy=lambda _home: state["busy"],
        calls=calls,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("4c4c4c4c-4c4c-44c4-84c4-4c4c4c4c4c4c")

    assert result["phase"] == "waiting_for_owner"
    assert result["reasonCode"] == "update_busy"
    assert "start" not in calls


def test_explicitly_disabled_protection_prevents_launch(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        posture="off",
        calls=calls,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("44444444-4444-4444-8444-444444444444")

    assert coordinator.inspect()["retryAllowed"] is False
    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "protection_off"
    assert result["protection"] == "off"
    assert "start" not in calls


def test_unknown_protection_posture_prevents_mutation(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        posture="unknown",
        calls=calls,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("77777777-7777-4777-8777-777777777777")

    assert coordinator.inspect()["retryAllowed"] is False
    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "unknown"
    assert "start" not in calls


def test_uncertain_exit_keeps_retry_disabled_and_does_not_start_replacement(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", _identity(tmp_path / "guard-home"), True),
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(False, "worker_exit_unconfirmed"),
        process_dead=lambda _identity: False,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("55555555-5555-4555-8555-555555555555")

    assert result["phase"] == "timed_out_waiting"
    assert result["reasonCode"] == "worker_exit_unconfirmed"
    assert result["workerActive"] is True
    assert result["retryAllowed"] is False
    assert "start" not in calls


@pytest.mark.parametrize("mutation", ("stop", "start", "start_after_stop"))
def test_unexpected_mutation_exception_retains_recovery_ownership(
    tmp_path: Path,
    mutation: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home, generation=f"unexpected-{mutation}")
    side_effect_seen = {"stop": False, "start": False}
    calls: list[str] = []
    initial = (
        ServiceInspection("unavailable", "service_unresponsive", identity, True)
        if mutation in {"stop", "start_after_stop"}
        else ServiceInspection("unavailable", "service_missing")
    )

    def inspect() -> ServiceInspection:
        if mutation == "start" and side_effect_seen["start"]:
            return ServiceInspection("ready", "healthy", identity, True)
        if mutation == "start_after_stop" and side_effect_seen["stop"]:
            if side_effect_seen["start"]:
                return ServiceInspection("ready", "healthy", identity, True)
            return ServiceInspection("unavailable", "service_missing")
        return initial

    def fail_after_mutation(name: str) -> None:
        calls.append(name)
        side_effect_seen[name] = True
        raise AssertionError(f"{name} worker failed after the mutation boundary")

    def stop_after_mutation(*_args: object) -> StopResult:
        calls.append("stop")
        side_effect_seen["stop"] = True
        return StopResult(True)

    coordinator = _coordinator(
        tmp_path,
        initial,
        inspect_service=inspect,
        stop_process=(
            (lambda *_args: fail_after_mutation("stop"))
            if mutation == "stop"
            else stop_after_mutation if mutation == "start_after_stop" else None
        ),
        process_dead=lambda _identity: False,
        start_process=(
            (lambda *_args: fail_after_mutation("start"))
            if mutation in {"start", "start_after_stop"}
            else None
        ),
    )

    first = coordinator.restart("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    second = coordinator.restart("dddddddd-dddd-4ddd-8ddd-dddddddddddd")

    assert first["workerActive"] is True
    assert first["retryAllowed"] is False
    assert second["operationId"] == first["operationId"]
    assert second["workerActive"] is True
    expected_calls = ["stop"] if mutation == "stop" else ["start"]
    if mutation == "start_after_stop":
        expected_calls = ["stop", "start"]
    assert calls == expected_calls


def test_unresolved_timeout_reconciles_before_a_second_stop(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    dead = {"value": False}
    calls: list[str] = []
    inspection_count = 0

    def inspect() -> ServiceInspection:
        nonlocal inspection_count
        inspection_count += 1
        reason_code = "service_missing" if dead["value"] and inspection_count >= 9 else "service_unresponsive"
        return ServiceInspection("unavailable", reason_code, identity, reason_code != "service_missing")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        inspect_service=inspect,
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(False, "worker_exit_unconfirmed"),
        process_dead=lambda _identity: dead["value"],
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    first = coordinator.restart("55555555-5555-4555-8555-555555555555")
    second = coordinator.restart("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")

    assert first["phase"] == "timed_out_waiting"
    assert second["phase"] == "timed_out_waiting"
    assert second["operationId"] == first["operationId"]
    assert [call for call in calls if call in {"stop", "start"}] == ["stop"]

    dead["value"] = True
    reconciled = coordinator.restart("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")

    assert reconciled["phase"] == "complete"
    assert reconciled["workerActive"] is False
    assert [call for call in calls if call in {"stop", "start"}] == ["stop", "stop", "start"]


def test_deadline_expiry_before_stop_does_not_mutate(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    calls: list[str] = []

    @contextmanager
    def recovery_lock(*_args: object):
        clock["value"] = 101.0
        yield

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", _identity(tmp_path / "guard-home"), True),
        calls=calls,
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        lock_timeout_seconds=2.0,
        recovery_lock=lambda *_args: recovery_lock(),
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("cccccccc-cccc-4ccc-8ccc-cccccccccccc")

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "deadline_exceeded"
    assert result["workerActive"] is False
    assert not any(call in {"stop", "start"} for call in calls)


def test_deadline_expiry_after_start_lock_does_not_start_missing_service(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    calls: list[str] = []

    @contextmanager
    def start_lock(*_args: object):
        clock["value"] = 101.0
        yield

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        calls=calls,
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        start_lock=start_lock,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("cececece-cece-4ece-8ece-cececececece")

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "deadline_exceeded"
    assert result["workerActive"] is False
    assert "start" not in calls


def test_deadline_expiry_after_readiness_does_not_probe_protection(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    calls: list[str] = []
    identity = _identity(tmp_path / "guard-home")

    def verify_ready(_home: Path, _identity: ProcessIdentity | None, _remaining: float) -> ReadyResult:
        calls.append("ready")
        clock["value"] = 101.0
        return ReadyResult(True, identity)

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("ready", "healthy", identity, True, True, True),
        calls=calls,
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        verify_ready=verify_ready,
        protection_health=lambda *_args: calls.append("protection") or ProtectionResult("verified", "healthy"),
    )

    result = coordinator.restart("cfcfcfcf-cfcf-4fcf-8fcf-cfcfcfcfcfcf")

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "deadline_exceeded"
    assert result["workerActive"] is True
    assert calls.count("ready") == 1
    assert "protection" not in calls


def test_deadline_expiry_after_confirmed_stop_does_not_start_replacement(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    calls: list[str] = []

    def stop(_identity: ProcessIdentity, remaining: float) -> StopResult:
        assert remaining > 0.0
        calls.append("stop")
        clock["value"] = 101.0
        return StopResult(True)

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", _identity(tmp_path / "guard-home"), True),
        calls=calls,
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        lock_timeout_seconds=2.0,
        stop_process=stop,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("dddddddd-dddd-4ddd-8ddd-dddddddddddd")

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "deadline_exceeded"
    assert result["workerActive"] is False
    assert [call for call in calls if call in {"stop", "start"}] == ["stop"]


def test_helper_timeouts_are_never_greater_than_remaining_budget(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    observed: dict[str, float] = {}
    identity = _identity(tmp_path / "guard-home")

    @contextmanager
    def recovery_lock(_home: Path, timeout: float):
        observed["recovery_lock"] = timeout
        yield

    @contextmanager
    def start_lock(_home: Path, timeout: float):
        observed["start_lock"] = timeout
        yield

    def stop(_identity: ProcessIdentity, remaining: float) -> StopResult:
        observed["stop"] = remaining
        return StopResult(True)

    def start(_home: Path, remaining: float) -> StartResult:
        observed["start"] = remaining
        return StartResult(True, identity)

    def ready(_home: Path, _identity: ProcessIdentity | None, remaining: float) -> ReadyResult:
        observed["ready"] = remaining
        return ReadyResult(True, identity)

    inspections = iter(
        [
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_missing", identity),
        ]
    )
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        inspect_service=lambda: next(inspections),
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        lock_timeout_seconds=10.0,
        recovery_lock=recovery_lock,
        start_lock=start_lock,
        stop_process=stop,
        start_process=start,
        verify_ready=ready,
    )

    result = coordinator.restart("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")

    assert result["phase"] == "complete"
    assert observed
    assert all(0.0 <= timeout <= 1.0 for timeout in observed.values())


def test_approval_wait_does_not_consume_recovery_budget(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    observed: dict[str, float] = {}
    started_identity = _identity(tmp_path / "guard-home")

    def authorize(_home: Path) -> bool:
        clock["value"] = 1000.0
        return True

    @contextmanager
    def recovery_lock(_home: Path, timeout: float):
        observed["recovery_lock"] = timeout
        yield

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        lock_timeout_seconds=10.0,
        authorize_hook=authorize,
        recovery_lock=recovery_lock,
        start_process=lambda *_args: StartResult(True, started_identity),
    )

    result = coordinator.restart("abababab-abab-4aba-8aba-abababababab")

    assert result["phase"] == "complete"
    assert observed["recovery_lock"] == 1.0


def test_unavailable_pending_snapshot_fails_closed_before_mutation(tmp_path: Path) -> None:
    calls: list[str] = []

    def unavailable(_home: Path):
        raise RuntimeError("recovery_state_invalid")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", _identity(tmp_path / "guard-home"), True),
        load_snapshot=unavailable,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("cdcdcdcd-cdcd-4cdc-8cdc-cdcdcdcdcdcd")

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "unknown"
    assert result["workerActive"] is True
    assert not any(call in {"stop", "start"} for call in calls)


def test_stale_read_only_receipt_reconnects_fresh_ready_service(tmp_path: Path) -> None:
    for phase in ("checking", "reconnecting"):
        phase_home = tmp_path / phase
        phase_home.mkdir()
        identity = _identity(phase_home / "guard-home")
        calls: list[str] = []
        coordinator = _coordinator(
            phase_home,
            ServiceInspection("ready", "healthy", identity, True, True, True),
            calls=calls,
            process_dead=lambda _identity: False,
            load_snapshot=lambda _home, phase=phase: _pending_snapshot(phase),
            stop_process=lambda *_args, calls=calls: calls.append("stop") or StopResult(True),
            start_process=lambda *_args, calls=calls, identity=identity: calls.append("start")
            or StartResult(True, identity),
        )

        request_id = (
            "15151515-1515-4515-8515-151515151515"
            if phase == "checking"
            else "16161616-1616-4616-8616-161616161616"
        )
        result = coordinator.restart(request_id)

        assert result["phase"] == "complete"
        assert result["outcome"] == "reconnected"
        assert not any(call in {"stop", "start"} for call in calls)


def test_stale_checking_receipt_allows_fresh_missing_service_start(tmp_path: Path) -> None:
    calls: list[str] = []
    identity = _identity(tmp_path / "guard-home")
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing", None, True),
        calls=calls,
        load_snapshot=lambda _home: _pending_snapshot("checking"),
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("17171717-1717-4717-8717-171717171717")

    assert result["phase"] == "complete"
    assert result["outcome"] == "started"
    assert calls.count("start") == 1
    assert "stop" not in calls


def test_stale_verifying_receipt_blocks_missing_identity(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing", None, True),
        calls=calls,
        load_snapshot=lambda _home: _pending_snapshot("verifying"),
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("18181818-1818-4818-8818-181818181818")

    assert result["phase"] == "waiting_for_owner"
    assert result["workerActive"] is True
    assert not any(call in {"stop", "start"} for call in calls)


def test_pending_snapshot_expires_only_after_fresh_missing_inventory(tmp_path: Path) -> None:
    calls: list[str] = []
    persisted: list[dict[str, object]] = []
    identity = _identity(tmp_path / "guard-home")

    def load_snapshot(_home: Path) -> dict[str, object]:
        return persisted[-1] if persisted else _pending_snapshot("verifying")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing", None, False),
        calls=calls,
        load_snapshot=load_snapshot,
        persist_snapshot=lambda _home, snapshot: persisted.append(dict(snapshot)),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("1b1b1b1b-1b1b-41b1-81b1-1b1b1b1b1b1b")

    assert result["phase"] == "complete"
    assert result["outcome"] == "started"
    assert calls.count("start") == 1
    assert persisted
    assert any(snapshot["phase"] == "needs_action" and snapshot["workerActive"] is False for snapshot in persisted)


def test_pending_snapshot_retains_owner_when_dead_proof_is_still_ambiguous(tmp_path: Path) -> None:
    identity = _identity(tmp_path / "guard-home")
    calls: list[str] = []
    inspections = iter(
        [
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
            ServiceInspection("unavailable", "service_unresponsive", identity, True),
        ]
    )
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        inspect_service=lambda: next(inspections),
        calls=calls,
        load_snapshot=lambda _home: _pending_snapshot("verifying"),
        process_dead=lambda _identity: True,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True, identity),
    )

    result = coordinator.restart("1f1f1f1f-1f1f-41f1-81f1-1f1f1f1f1f1f")

    assert result["phase"] == "waiting_for_owner"
    assert result["workerActive"] is True
    assert result["retryAllowed"] is False
    assert not any(call in {"stop", "start"} for call in calls)


def test_pending_snapshot_expiration_failure_keeps_owner_unresolved(tmp_path: Path) -> None:
    calls: list[str] = []

    def persist_failure(_home: Path, _snapshot: dict[str, object]) -> None:
        raise OSError("recovery_receipt_read_only")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing", None, False),
        calls=calls,
        load_snapshot=lambda _home: _pending_snapshot("verifying"),
        persist_snapshot=persist_failure,
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("1f1f1f1f-1f1f-41f1-81f1-1f1f1f1f1f1f")

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "unknown"
    assert result["workerActive"] is True
    assert result["retryAllowed"] is False
    assert result["requiresHumanAction"] is True
    assert "start" not in calls


def test_unrelated_recovery_lock_failure_is_safe_and_does_not_persist(tmp_path: Path) -> None:
    persisted: list[dict[str, object]] = []

    def broken_lock(*_args):
        raise RuntimeError("lock_backend_unavailable")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        recovery_lock=broken_lock,
        persist_snapshot=lambda _home, snapshot: persisted.append(snapshot),
    )

    result = coordinator.restart("efefefef-efef-4efe-8efe-efefefefefef")

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "unknown"
    assert persisted == []


def test_recovery_lock_timeout_waits_for_owner_without_persisting(tmp_path: Path) -> None:
    calls: list[str] = []
    persisted: list[dict[str, object]] = []

    def timed_out_lock(*_args: object):
        raise TimeoutError("recovery_lock_timeout")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        calls=calls,
        recovery_lock=timed_out_lock,
        persist_snapshot=lambda _home, snapshot: persisted.append(dict(snapshot)),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("f0f0f0f0-f0f0-40f0-80f0-f0f0f0f0f0f0")

    assert result["phase"] == "waiting_for_owner"
    assert result["reasonCode"] == "operation_busy"
    assert result["workerActive"] is False
    assert result["retryAllowed"] is False
    assert persisted == []
    assert "start" not in calls
    assert coordinator.status(result["operationId"]) == result


def test_started_worker_remains_active_when_readiness_times_out(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    identity = _identity(tmp_path / "guard-home")

    def verify_ready(_home, _identity, _remaining):
        clock["value"] = 101.0
        return ReadyResult(False, identity, "startup_failed")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        start_process=lambda _home, _remaining: StartResult(True, identity),
        verify_ready=verify_ready,
    )

    result = coordinator.restart("dededede-dede-4ded-8ded-dededededede")

    assert result["phase"] == "failed"
    assert result["reasonCode"] == "deadline_exceeded"
    assert result["workerActive"] is True
    assert result["retryAllowed"] is False


def test_unresolved_worker_survives_final_persistence_failure(tmp_path: Path) -> None:
    identity = _identity(tmp_path / "guard-home")
    persisted: list[str] = []

    def persist(_home: Path, snapshot: dict[str, object]) -> None:
        persisted.append(str(snapshot["phase"]))
        if snapshot["phase"] == "timed_out_waiting":
            raise OSError("simulated final snapshot write failure")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        stop_process=lambda *_args: StopResult(False, "worker_exit_unconfirmed"),
        process_dead=lambda _identity: False,
        persist_snapshot=persist,
    )

    result = coordinator.restart("1c1c1c1c-1c1c-41c1-81c1-1c1c1c1c1c1c")

    assert result["phase"] == "failed"
    assert result["workerActive"] is True
    assert result["retryAllowed"] is False
    assert result["requiresHumanAction"] is True
    assert persisted == ["checking", "stopping", "timed_out_waiting"]
    active = recovery_module._ACTIVE_BY_HOME.get(str(coordinator.guard_home))
    assert active is not None
    assert active.unresolved_owner is True


def test_default_stop_passes_remaining_to_bounded_retirement(tmp_path: Path, monkeypatch) -> None:
    identity = _identity(tmp_path / "guard-home")
    captured: dict[str, object] = {}

    def retire(pid: int, **kwargs: object) -> bool:
        captured["pid"] = pid
        captured.update(kwargs)
        return True

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)
    monkeypatch.setattr(live_process_identity, "process_start_token", lambda _pid: identity.start_marker)
    monkeypatch.setattr(live_process_identity, "process_owner_marker", lambda _pid: identity.user)
    # The fixture normally injects a stop hook; exercise the coordinator's
    # production default directly so the manager timeout contract is covered.
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", identity, True),
        use_default_stop_process=True,
    )
    result = coordinator._stop_process(identity, 0.25)

    assert result is True
    assert captured == {
        "pid": identity.pid,
        "expected_guard_home": coordinator.guard_home,
        "expected_creation_time": None,
        "expected_start_marker": identity.start_marker,
        "timeout": 0.25,
    }


def test_default_start_returns_authenticated_generation_identity(tmp_path: Path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    identity = _identity(guard_home, pid=47, generation="generation-start")
    state = {
        "pid": identity.pid,
        "generation": identity.generation,
        "runtime": identity.runtime,
        "guard_home": str(identity.guard_home),
        "user": identity.user,
        "start_marker": identity.start_marker,
    }

    class FakeManager:
        @staticmethod
        def ensure_guard_daemon(*_args: object, **_kwargs: object) -> str:
            return "http://127.0.0.1:5417"

        @staticmethod
        def load_authenticated_daemon_state(_home: Path) -> dict[str, object]:
            return state

    monkeypatch.setattr(recovery_module, "_manager", lambda: FakeManager())
    coordinator = UserRecoveryCoordinator(
        guard_home,
        home_dir=tmp_path / "home",
        hooks=RecoveryHooks(load_state=lambda _home: None),
    )

    started = coordinator._start_process(1.0)

    assert isinstance(started, StartResult)
    assert started.started is True
    assert started.identity == identity


def test_default_start_identity_flows_through_readiness_and_protection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    identity = _identity(guard_home, pid=48, generation="generation-default-start-flow")
    state = {
        "pid": identity.pid,
        "generation": identity.generation,
        "runtime": identity.runtime,
        "guard_home": str(identity.guard_home),
        "user": identity.user,
        "start_marker": identity.start_marker,
    }
    starts = 0
    readiness_identities: list[ProcessIdentity | None] = []
    protection_identities: list[ProcessIdentity | None] = []

    class FakeManager:
        @staticmethod
        def ensure_guard_daemon(*_args: object, **_kwargs: object) -> str:
            nonlocal starts
            starts += 1
            return "http://127.0.0.1:5417"

        @staticmethod
        def load_authenticated_daemon_state(_home: Path) -> dict[str, object]:
            return state

    monkeypatch.setattr(recovery_module, "_manager", lambda: FakeManager())

    def inspect_service(_home: Path, _state: object) -> ServiceInspection:
        if starts == 0:
            return ServiceInspection("unavailable", "service_missing")
        return ServiceInspection("ready", "healthy", identity, True, True, True)

    def verify_ready(
        _home: Path,
        observed: ProcessIdentity | None,
        _remaining: float,
    ) -> ReadyResult:
        readiness_identities.append(observed)
        return ReadyResult(observed == identity, observed, "healthy" if observed == identity else "identity_unverified")

    def protection_health(
        _home: Path,
        observed: ProcessIdentity | None,
        _remaining: float,
    ) -> ProtectionResult:
        protection_identities.append(observed)
        return ProtectionResult("verified", "healthy")

    coordinator = UserRecoveryCoordinator(
        guard_home,
        hooks=RecoveryHooks(
            load_state=lambda _home: None,
            inspect_service=inspect_service,
            protection_posture=lambda _home: "on",
            update_busy=lambda _home: False,
            authorize=lambda _home: True,
            recovery_lock=lambda *_args: nullcontext(),
            start_lock=lambda *_args: nullcontext(),
            verify_ready=verify_ready,
            protection_health=protection_health,
        ),
    )

    result = coordinator.restart("2a2a2a2a-2a2a-42a2-82a2-2a2a2a2a2a2a")

    assert result["phase"] == "complete"
    assert result["outcome"] == "started"
    assert result["service"] == "ready"
    assert result["protection"] == "verified"
    assert starts == 1
    assert readiness_identities == [identity]
    assert protection_identities == [identity]


def test_unverified_default_start_retains_owner_and_blocks_duplicate_start(tmp_path: Path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    starts = 0
    live = False

    class FakeManager:
        @staticmethod
        def ensure_guard_daemon(*_args: object, **_kwargs: object) -> str:
            nonlocal starts
            starts += 1
            return "http://127.0.0.1:5417"

        @staticmethod
        def load_authenticated_daemon_state(_home: Path) -> None:
            return None

    monkeypatch.setattr(recovery_module, "_manager", lambda: FakeManager())

    def inspect(_home: Path, _state: object) -> ServiceInspection:
        return (
            ServiceInspection("unavailable", "service_unresponsive", None, True)
            if live
            else ServiceInspection("unavailable", "service_missing")
        )

    def verify_ready(_home: Path, _identity: ProcessIdentity | None, _remaining: float) -> ReadyResult:
        nonlocal live
        live = True
        return ReadyResult(False, None, "identity_unverified")

    hooks = RecoveryHooks(
        clock=lambda: 100.0,
        wall_clock=lambda: __import__("datetime").datetime(
            2026, 9, 20, tzinfo=__import__("datetime").timezone.utc
        ),
        load_state=lambda _home: None,
        inspect_service=inspect,
        protection_posture=lambda _home: "on",
        update_busy=lambda _home: False,
        authorize=lambda _home: True,
        recovery_lock=lambda *_args: nullcontext(),
        start_lock=lambda *_args: nullcontext(),
        verify_ready=verify_ready,
    )
    coordinator = UserRecoveryCoordinator(guard_home, hooks=hooks)

    first = coordinator.restart("1d1d1d1d-1d1d-41d1-81d1-1d1d1d1d1d1d")
    second = coordinator.restart("1e1e1e1e-1e1e-41e1-81e1-1e1e1e1e1e1e")

    assert first["phase"] == "failed"
    assert first["reasonCode"] == "identity_unverified"
    assert first["workerActive"] is True
    assert first["retryAllowed"] is False
    assert second["operationId"] == first["operationId"]
    assert second["workerActive"] is True
    assert second["retryAllowed"] is False
    assert starts == 1


def test_same_home_barrier_requests_register_one_mutation(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    identity = _identity(guard_home)
    registration_barrier = threading.Barrier(2)
    state_lock = threading.Lock()
    clock_calls = 0
    starts = 0
    results: list[dict[str, object]] = []
    errors: list[BaseException] = []

    def clock() -> float:
        nonlocal clock_calls
        with state_lock:
            clock_calls += 1
            call_number = clock_calls
        if call_number <= 2:
            registration_barrier.wait(timeout=5.0)
        return 100.0 + call_number

    def start(_home: Path, _remaining: float) -> StartResult:
        nonlocal starts
        with state_lock:
            starts += 1
        return StartResult(True, identity)

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        clock=clock,
        start_process=start,
    )

    def run(request_id: str) -> None:
        try:
            results.append(coordinator.restart(request_id))
        except BaseException as exc:  # pragma: no cover - assertion below reports the error
            errors.append(exc)

    threads = [
        threading.Thread(target=run, args=(request_id,))
        for request_id in (
            "51515151-5151-4515-8515-515151515151",
            "52525252-5252-4525-8525-525252525252",
        )
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10.0)

    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    assert len(results) == 2
    assert starts == 1


def test_started_worker_timeout_blocks_second_request_until_proven_dead(tmp_path: Path) -> None:
    clock = {"value": 100.0}
    identity = _identity(tmp_path / "guard-home")
    dead = {"value": False}
    calls: list[str] = []
    starts = {"count": 0}

    def start(_home: Path, _remaining: float) -> StartResult:
        calls.append("start")
        starts["count"] += 1
        return StartResult(True, identity)

    def verify_ready(_home: Path, current: ProcessIdentity | None, _remaining: float) -> ReadyResult:
        if starts["count"] == 1:
            clock["value"] = 101.0
            return ReadyResult(False, current or identity, "deadline_exceeded")
        return ReadyResult(True, current or identity)

    def process_dead(current: ProcessIdentity) -> bool:
        assert current == identity
        return dead["value"]

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        calls=calls,
        clock=lambda: clock["value"],
        active_budget_seconds=1.0,
        start_process=start,
        verify_ready=verify_ready,
        process_dead=process_dead,
    )

    first = coordinator.restart("19191919-1919-4919-8919-191919191919")
    second = coordinator.restart("20202020-2020-4020-8020-202020202020")

    assert first["phase"] == "failed"
    assert first["reasonCode"] == "deadline_exceeded"
    assert first["workerActive"] is True
    assert second["operationId"] == first["operationId"]
    assert [call for call in calls if call == "start"] == ["start"]

    dead["value"] = True
    reconciled = coordinator.restart("21212121-2121-4121-8121-212121212121")

    assert reconciled["phase"] == "complete"
    assert reconciled["outcome"] == "started"
    assert [call for call in calls if call == "start"] == ["start", "start"]


def test_cross_process_unresolved_stop_receipt_blocks_second_stop_until_proven_dead(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    owner_ready = tmp_path / "owner-ready"
    release_owner = tmp_path / "release-owner"
    worker_dead = tmp_path / "worker-dead"
    dead_check_log = tmp_path / "dead-check.log"
    persisted_log = tmp_path / "persisted.log"
    script = textwrap.dedent(
        """
        from __future__ import annotations

        import argparse
        import io
        import os
        import sys
        import time
        from pathlib import Path

        from codex_plugin_scanner.guard import live_process_identity
        from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
        from codex_plugin_scanner.guard.daemon import manager
        from codex_plugin_scanner.guard.daemon.user_recovery import (
            ProcessIdentity,
            ProtectionResult,
            ReadyResult,
            RecoveryHooks,
            ServiceInspection,
            StartResult,
            StopResult,
            UserRecoveryCoordinator as CoreCoordinator,
        )

        guard_home = Path(sys.argv[1])
        role = sys.argv[2]
        ready_path = Path(sys.argv[3])
        release_path = Path(sys.argv[4])
        log_path = Path(sys.argv[5])
        dead_path = Path(sys.argv[6])
        dead_check_log = Path(sys.argv[7])
        request_id = sys.argv[8]
        lock_timeout = float(sys.argv[9])
        stopped = {"value": False}
        owner_marker = live_process_identity.process_owner_marker(os.getpid())
        assert owner_marker is not None
        identity = ProcessIdentity(
            pid=41,
            generation="target-generation",
            runtime="runtime-1",
            guard_home=guard_home,
            user=owner_marker,
            start_marker="start-target",
        )

        def persist(home, snapshot):
            with log_path.open("a", encoding="utf-8") as stream:
                stream.write(f"{role} {snapshot['phase']}\\n")
            cli._persist_snapshot(home, snapshot)

        def stop(_identity, _remaining):
            if role == "owner":
                ready_path.write_text("ready", encoding="utf-8")
                return StopResult(False, "worker_exit_unconfirmed")
            stopped["value"] = True
            return StopResult(True)

        def process_dead(_identity):
            if (
                _identity.pid != 41
                or _identity.generation != "target-generation"
                or _identity.start_marker != "start-target"
            ):
                raise AssertionError("reconciliation identity changed")
            with dead_check_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{_identity.pid} {_identity.generation} {_identity.start_marker}\\n")
            stopped["value"] = dead_path.exists()
            return stopped["value"]

        def inspect(_home, _state):
            reason_code = (
                "service_missing"
                if role == "contender" and stopped["value"]
                else "service_unresponsive"
            )
            return ServiceInspection(
                "unavailable",
                reason_code,
                None if reason_code == "service_missing" else identity,
                reason_code != "service_missing",
            )

        hooks = RecoveryHooks(
            load_state=lambda _home: {"state": "fixture"},
            inspect_service=inspect,
            protection_posture=lambda _home: "on",
            update_busy=lambda _home: False,
            authorize=lambda _home: True,
            recovery_lock=lambda home, timeout: manager._guard_daemon_recovery_lock(
                home, timeout_seconds=timeout
            ),
            stop_process=stop,
            process_dead=process_dead,
            start_process=lambda _home, _remaining: StartResult(True, identity),
            verify_ready=lambda _home, current, _remaining: ReadyResult(True, current),
            protection_health=lambda _home, _identity, _remaining: ProtectionResult("verified", "healthy"),
            load_snapshot=cli._load_latest_snapshot,
            persist_snapshot=persist,
        )

        def make_coordinator(home, *, home_dir=None, hooks=None):
            return CoreCoordinator(
                home,
                hooks=globals()["hooks"],
                active_budget_seconds=5.0,
                lock_timeout_seconds=lock_timeout,
            )

        cli.UserRecoveryCoordinator = make_coordinator
        output = io.StringIO()
        errors = io.StringIO()
        code = cli.dispatch_daemon_recovery(
            argparse.Namespace(
                daemon_recovery_command="restart",
                request_id=request_id,
                json_lines=True,
            ),
            guard_home=guard_home,
            home_dir=None,
            lifecycle_authorized=True,
            stdout=output,
            stderr=errors,
        )
        print(code, flush=True)
        if role == "owner":
            while not release_path.exists():
                time.sleep(0.01)
        """
    )
    owner_id = "11111111-1111-4111-8111-111111111111"
    contender_id = "22222222-2222-4222-8222-222222222222"
    owner = subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
            str(guard_home),
            "owner",
            str(owner_ready),
            str(release_owner),
            str(persisted_log),
            str(worker_dead),
            str(dead_check_log),
            owner_id,
            "5.0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5.0
        while not owner_ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert owner_ready.exists(), owner.communicate(timeout=1)[1]

        contender = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(guard_home),
                "contender",
                str(owner_ready),
                str(release_owner),
                str(persisted_log),
                str(worker_dead),
                str(dead_check_log),
                contender_id,
                "0.05",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        assert contender.returncode == 0, contender.stderr
        assert contender.stdout.strip() == "3"
        assert "contender " not in persisted_log.read_text(encoding="utf-8")

        worker_dead.write_text("proven", encoding="utf-8")
        reconciler = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(guard_home),
                "contender",
                str(owner_ready),
                str(release_owner),
                str(persisted_log),
                str(worker_dead),
                str(dead_check_log),
                contender_id,
                "0.05",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        assert reconciler.returncode == 0, reconciler.stderr
        assert reconciler.stdout.strip() == "0"
        persisted = persisted_log.read_text(encoding="utf-8")
        assert "contender starting" in persisted
        assert "contender stopping" not in persisted
        assert all(
            line == "41 target-generation start-target"
            for line in dead_check_log.read_text(encoding="utf-8").splitlines()
        )
    finally:
        release_owner.write_text("release", encoding="utf-8")
        stdout, stderr = owner.communicate(timeout=5)
        assert owner.returncode == 0, stderr
        assert stdout.strip() == "3"


def test_cli_stopping_receipt_blocks_retry_when_timeout_persistence_fails(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    owner_ready = tmp_path / "owner-ready"
    release_owner = tmp_path / "release-owner"
    worker_dead = tmp_path / "worker-dead"
    dead_check_log = tmp_path / "dead-check.log"
    mutation_log = tmp_path / "mutation.log"
    persisted_log = tmp_path / "persisted.log"
    script = textwrap.dedent(
        """
        from __future__ import annotations

        import argparse
        import io
        import os
        import sys
        import time
        from pathlib import Path

        from codex_plugin_scanner.guard import live_process_identity
        from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
        from codex_plugin_scanner.guard.daemon import manager
        from codex_plugin_scanner.guard.daemon.user_recovery import (
            ProcessIdentity,
            ProtectionResult,
            ReadyResult,
            RecoveryHooks,
            ServiceInspection,
            StartResult,
            StopResult,
            UserRecoveryCoordinator as CoreCoordinator,
        )

        guard_home = Path(sys.argv[1])
        role = sys.argv[2]
        owner_ready = Path(sys.argv[3])
        release_owner = Path(sys.argv[4])
        worker_dead = Path(sys.argv[5])
        dead_check_log = Path(sys.argv[6])
        mutation_log = Path(sys.argv[7])
        persisted_log = Path(sys.argv[8])
        request_id = sys.argv[9]
        lock_timeout = float(sys.argv[10])
        stopped = {"value": False}
        owner_marker = live_process_identity.process_owner_marker(os.getpid())
        assert owner_marker is not None
        identity = ProcessIdentity(
            pid=41,
            generation="target-generation",
            runtime="runtime-1",
            guard_home=guard_home,
            user=owner_marker,
            start_marker="start-target",
        )

        def persist(home, snapshot):
            with persisted_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{role} {snapshot['phase']}\\n")
            if role == "owner" and snapshot["phase"] in {"timed_out_waiting", "failed"}:
                raise OSError("simulated final snapshot write failure")
            cli._persist_snapshot(home, snapshot)

        def process_dead(current):
            if (
                current.pid != 41
                or current.generation != "target-generation"
                or current.start_marker != "start-target"
            ):
                raise AssertionError("reconciliation identity changed")
            with dead_check_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{current.pid} {current.generation} {current.start_marker}\\n")
            stopped["value"] = worker_dead.exists()
            return stopped["value"]

        def stop(_identity, _remaining):
            with mutation_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{role} stop\\n")
            if role == "owner":
                owner_ready.write_text("ready", encoding="utf-8")
                return StopResult(False, "worker_exit_unconfirmed")
            stopped["value"] = True
            return StopResult(True)

        def inspect(_home, _state):
            reason_code = "service_missing" if stopped["value"] else "service_unresponsive"
            return ServiceInspection(
                "unavailable",
                reason_code,
                None if reason_code == "service_missing" else identity,
                reason_code != "service_missing",
            )

        hooks = RecoveryHooks(
            load_state=lambda _home: {"state": "fixture"},
            inspect_service=inspect,
            protection_posture=lambda _home: "on",
            update_busy=lambda _home: False,
            authorize=lambda _home: True,
            recovery_lock=lambda home, timeout: manager._guard_daemon_recovery_lock(
                home, timeout_seconds=timeout
            ),
            stop_process=stop,
            process_dead=process_dead,
            start_process=lambda _home, _remaining: StartResult(True, identity),
            verify_ready=lambda _home, current, _remaining: ReadyResult(True, current),
            protection_health=lambda _home, _identity, _remaining: ProtectionResult("verified", "healthy"),
            load_snapshot=cli._load_latest_snapshot,
            persist_snapshot=persist,
        )

        def make_coordinator(home, *, home_dir=None, hooks=None):
            return CoreCoordinator(
                home,
                hooks=globals()["hooks"],
                active_budget_seconds=5.0,
                lock_timeout_seconds=lock_timeout,
            )

        cli.UserRecoveryCoordinator = make_coordinator
        output = io.StringIO()
        errors = io.StringIO()
        code = cli.dispatch_daemon_recovery(
            argparse.Namespace(
                daemon_recovery_command="restart",
                request_id=request_id,
                json_lines=True,
            ),
            guard_home=guard_home,
            home_dir=None,
            lifecycle_authorized=True,
            stdout=output,
            stderr=errors,
        )
        print(code, flush=True)
        if role == "owner":
            while not release_owner.exists():
                time.sleep(0.01)
        """
    )
    owner_id = "31313131-3131-4313-8313-313131313131"
    contender_id = "32323232-3232-4323-8323-323232323232"
    owner = subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
            str(guard_home),
            "owner",
            str(owner_ready),
            str(release_owner),
            str(worker_dead),
            str(dead_check_log),
            str(mutation_log),
            str(persisted_log),
            owner_id,
            "5.0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5.0
        while not owner_ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert owner_ready.exists(), owner.communicate(timeout=1)[1]
        persisted = recovery_cli._load_latest_snapshot(guard_home)
        assert persisted is not None
        assert persisted["phase"] == "stopping"

        contender = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(guard_home),
                "contender",
                str(owner_ready),
                str(release_owner),
                str(worker_dead),
                str(dead_check_log),
                str(mutation_log),
                str(persisted_log),
                contender_id,
                "0.05",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        assert contender.returncode == 0, contender.stderr
        assert contender.stdout.strip() == "3"
        assert "contender stop" not in mutation_log.read_text(encoding="utf-8")
        assert recovery_cli._load_latest_snapshot(guard_home)["phase"] == "stopping"

        worker_dead.write_text("proven", encoding="utf-8")
        reconciler = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(guard_home),
                "contender",
                str(owner_ready),
                str(release_owner),
                str(worker_dead),
                str(dead_check_log),
                str(mutation_log),
                str(persisted_log),
                contender_id,
                "0.05",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        assert reconciler.returncode == 0, reconciler.stderr
        assert reconciler.stdout.strip() == "0"
        mutation = mutation_log.read_text(encoding="utf-8")
        assert "contender stop" not in mutation
        assert "contender starting" in persisted_log.read_text(encoding="utf-8")
        assert all(
            line == "41 target-generation start-target"
            for line in dead_check_log.read_text(encoding="utf-8").splitlines()
        )
    finally:
        release_owner.write_text("release", encoding="utf-8")
        stdout, stderr = owner.communicate(timeout=5)
        assert owner.returncode == 0, stderr
        assert stdout.strip() == "3"


def test_cli_started_worker_receipt_blocks_second_start_until_proven_dead(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    owner_ready = tmp_path / "owner-ready"
    release_owner = tmp_path / "release-owner"
    worker_dead = tmp_path / "worker-dead"
    dead_check_log = tmp_path / "dead-check.log"
    mutation_log = tmp_path / "mutation.log"
    persisted_log = tmp_path / "persisted.log"
    script = textwrap.dedent(
        """
        from __future__ import annotations

        import argparse
        import io
        import os
        import sys
        import time
        from pathlib import Path

        from codex_plugin_scanner.guard import live_process_identity
        from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
        from codex_plugin_scanner.guard.daemon import manager
        from codex_plugin_scanner.guard.daemon.user_recovery import (
            ProcessIdentity,
            ProtectionResult,
            ReadyResult,
            RecoveryHooks,
            ServiceInspection,
            StartResult,
            StopResult,
            UserRecoveryCoordinator as CoreCoordinator,
        )

        guard_home = Path(sys.argv[1])
        role = sys.argv[2]
        owner_ready = Path(sys.argv[3])
        release_owner = Path(sys.argv[4])
        worker_dead = Path(sys.argv[5])
        dead_check_log = Path(sys.argv[6])
        mutation_log = Path(sys.argv[7])
        persisted_log = Path(sys.argv[8])
        request_id = sys.argv[9]
        lock_timeout = float(sys.argv[10])
        clock = {"value": 100.0}
        stopped = {"value": False}
        owner_marker = live_process_identity.process_owner_marker(os.getpid())
        assert owner_marker is not None
        identity = ProcessIdentity(
            pid=42,
            generation="started-generation",
            runtime="runtime-1",
            guard_home=guard_home,
            user=owner_marker,
            start_marker="start-started",
        )

        def persist(home, snapshot):
            with persisted_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{role} {snapshot['phase']}\\n")
            cli._persist_snapshot(home, snapshot)

        def inspect(_home, _state):
            if role == "owner":
                return ServiceInspection("unavailable", "service_missing")
            reason_code = "service_missing" if stopped["value"] else "service_unresponsive"
            return ServiceInspection(
                "unavailable",
                reason_code,
                None if reason_code == "service_missing" else identity,
                reason_code != "service_missing",
            )

        def process_dead(current):
            if (
                current.pid != 42
                or current.generation != "started-generation"
                or current.start_marker != "start-started"
            ):
                raise AssertionError("reconciliation identity changed")
            with dead_check_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{current.pid} {current.generation} {current.start_marker}\\n")
            stopped["value"] = worker_dead.exists()
            return stopped["value"]

        def start(_home, _remaining):
            with mutation_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{role} start\\n")
            return StartResult(True, identity)

        def stop(_identity, _remaining):
            with mutation_log.open("a", encoding="utf-8") as stream:
                stream.write(f"{role} stop\\n")
            stopped["value"] = True
            return StopResult(True)

        def ready(_home, current, _remaining):
            if role == "owner":
                clock["value"] = 101.0
                return ReadyResult(False, identity, "startup_failed")
            return ReadyResult(True, current or identity)

        hooks = RecoveryHooks(
            clock=lambda: clock["value"],
            load_state=lambda _home: {"state": "fixture"},
            inspect_service=inspect,
            protection_posture=lambda _home: "on",
            update_busy=lambda _home: False,
            authorize=lambda _home: True,
            recovery_lock=lambda home, timeout: manager._guard_daemon_recovery_lock(
                home, timeout_seconds=timeout
            ),
            stop_process=stop,
            process_dead=process_dead,
            start_process=start,
            verify_ready=ready,
            protection_health=lambda _home, _identity, _remaining: ProtectionResult("verified", "healthy"),
            load_snapshot=cli._load_latest_snapshot,
            persist_snapshot=persist,
        )

        def make_coordinator(home, *, home_dir=None, hooks=None):
            return CoreCoordinator(
                home,
                hooks=globals()["hooks"],
                active_budget_seconds=1.0,
                lock_timeout_seconds=lock_timeout,
            )

        cli.UserRecoveryCoordinator = make_coordinator
        output = io.StringIO()
        errors = io.StringIO()
        code = cli.dispatch_daemon_recovery(
            argparse.Namespace(
                daemon_recovery_command="restart",
                request_id=request_id,
                json_lines=True,
            ),
            guard_home=guard_home,
            home_dir=None,
            lifecycle_authorized=True,
            stdout=output,
            stderr=errors,
        )
        print(code, flush=True)
        if role == "owner":
            owner_ready.write_text("ready", encoding="utf-8")
            while not release_owner.exists():
                time.sleep(0.01)
        """
    )
    owner_id = "41414141-4141-4414-8414-414141414141"
    contender_id = "42424242-4242-4424-8424-424242424242"
    owner = subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
            str(guard_home),
            "owner",
            str(owner_ready),
            str(release_owner),
            str(worker_dead),
            str(dead_check_log),
            str(mutation_log),
            str(persisted_log),
            owner_id,
            "5.0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5.0
        while not owner_ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert owner_ready.exists(), owner.communicate(timeout=1)[1]
        persisted = recovery_cli._load_latest_snapshot(guard_home)
        assert persisted is not None
        assert persisted["phase"] == "failed"
        assert persisted["workerActive"] is True

        contender = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(guard_home),
                "contender",
                str(owner_ready),
                str(release_owner),
                str(worker_dead),
                str(dead_check_log),
                str(mutation_log),
                str(persisted_log),
                contender_id,
                "0.05",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        assert contender.returncode == 0, contender.stderr
        assert contender.stdout.strip() == "3"
        assert "contender " not in mutation_log.read_text(encoding="utf-8")
        assert recovery_cli._load_latest_snapshot(guard_home)["phase"] == "failed"

        worker_dead.write_text("proven", encoding="utf-8")
        reconciler = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(guard_home),
                "contender",
                str(owner_ready),
                str(release_owner),
                str(worker_dead),
                str(dead_check_log),
                str(mutation_log),
                str(persisted_log),
                contender_id,
                "0.05",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        assert reconciler.returncode == 0, reconciler.stderr
        assert reconciler.stdout.strip() == "0"
        mutation = mutation_log.read_text(encoding="utf-8")
        assert "contender start" in mutation
        assert all(
            line == "42 started-generation start-started"
            for line in dead_check_log.read_text(encoding="utf-8").splitlines()
        )
    finally:
        release_owner.write_text("release", encoding="utf-8")
        stdout, stderr = owner.communicate(timeout=5)
        assert owner.returncode == 0, stderr
        assert stdout.strip() == "3"


def test_required_authorization_releases_before_mutation(tmp_path: Path) -> None:
    calls: list[str] = []
    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        authorize=AuthorizationDecision(False, True, "approval_required"),
        calls=calls,
    )

    result = coordinator.restart("66666666-6666-4666-8666-666666666666")

    assert result["phase"] == "awaiting_approval"
    assert result["reasonCode"] == "approval_required"
    assert result["workerActive"] is False
    assert calls == ["inspect"]


def test_missing_authorization_hook_fails_closed(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    hooks = RecoveryHooks(
        load_state=lambda _home: None,
        inspect_service=lambda *_args: ServiceInspection("unavailable", "service_missing"),
        protection_posture=lambda _home: "on",
        update_busy=lambda _home: False,
    )

    result = UserRecoveryCoordinator(guard_home, hooks=hooks).restart("77777777-7777-4777-8777-777777777777")

    assert result["phase"] == "awaiting_approval"
    assert result["reasonCode"] == "approval_required"


def test_recovery_lock_is_acquired_before_start_lock(tmp_path: Path) -> None:
    calls: list[str] = []

    @contextmanager
    def lock(name: str):
        calls.append(f"enter:{name}")
        try:
            yield
        finally:
            calls.append(f"exit:{name}")

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_missing"),
        calls=calls,
        recovery_lock=lambda *_args: lock("recovery"),
        start_lock=lambda *_args: lock("start"),
        start_process=lambda *_args: StartResult(True, _identity(tmp_path / "guard-home")),
    )

    result = coordinator.restart("88888888-8888-4888-8888-888888888888")

    assert result["phase"] == "complete"
    assert calls.index("enter:recovery") < calls.index("enter:start")
    assert calls.index("exit:start") < calls.index("exit:recovery")


def test_generation_change_immediately_before_stop_never_mutates(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    original = _identity(guard_home)
    replacement = _identity(guard_home, generation="generation-2")
    inspections = 0
    calls: list[str] = []

    def inspect() -> ServiceInspection:
        nonlocal inspections
        inspections += 1
        identity = replacement if inspections >= 4 else original
        return ServiceInspection("unavailable", "service_unresponsive", identity, True)

    coordinator = _coordinator(
        tmp_path,
        ServiceInspection("unavailable", "service_unresponsive", original, True),
        inspect_service=inspect,
        calls=calls,
        stop_process=lambda *_args: calls.append("stop") or StopResult(True),
        start_process=lambda *_args: calls.append("start") or StartResult(True),
    )

    result = coordinator.restart("99999999-9999-4999-8999-999999999999")

    assert result["phase"] == "needs_action"
    assert result["reasonCode"] == "identity_unverified"
    assert "stop" not in calls
    assert "start" not in calls


def test_default_update_probe_uses_existing_update_owner(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon import dashboard_update

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    monkeypatch.setattr(dashboard_update, "dashboard_update_in_progress", lambda home: home == guard_home)

    coordinator = UserRecoveryCoordinator(guard_home)

    assert coordinator._update_busy() is True
