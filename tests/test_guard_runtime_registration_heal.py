"""Runtime registration self-heal after the guard_runtime_state row is lost."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard import store_connection_schema
from codex_plugin_scanner.guard.approvals import build_runtime_snapshot
from codex_plugin_scanner.guard.daemon import protection_repair_retry
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.protection_repair_retry import containment_repair_outcome
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.protection_health import ProtectionCheckStatus
from codex_plugin_scanner.guard.store import GuardStore
from tests.runtime_registration_support import (
    CONTAINMENT_CHECK_IDS,
    T0,
    assert_row_reappears_with_daemon_identity,
    delete_runtime_row,
    get_json,
    passing_containment_health,
    post_repair,
    protection_check,
    start_daemon,
    stub_supported_repair,
)


def test_snapshot_reports_missing_registration_while_serving(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    snapshot = build_runtime_snapshot(
        store=store,
        approval_center_url="http://127.0.0.1:9100",
        containment_health=passing_containment_health(),
        serving_runtime={
            "session_id": "daemon-1",
            "daemon_host": "127.0.0.1",
            "daemon_port": 9100,
            "started_at": T0,
            "last_heartbeat_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    runtime_state = cast(dict[str, object], snapshot["runtime_state"])
    assert runtime_state["registration_status"] == "missing"
    assert runtime_state["session_id"] == "daemon-1"
    assert protection_check(snapshot, "daemon") == {
        "check_id": "daemon",
        "status": "unknown",
        "reason_code": "daemon_registration_missing",
    }
    for check_id in CONTAINMENT_CHECK_IDS:
        check = protection_check(snapshot, check_id)
        assert check["reason_code"] != "containment_health_invalid"
        assert check["status"] == "pass"
    assert snapshot["headline_state"] != "setup"


def test_snapshot_without_serving_runtime_still_fails_closed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    snapshot = build_runtime_snapshot(
        store=store,
        approval_center_url=None,
        containment_health=passing_containment_health(),
    )

    assert snapshot["runtime_state"] is None
    assert protection_check(snapshot, "daemon") == {
        "check_id": "daemon",
        "status": "fail",
        "reason_code": "daemon_runtime_unavailable",
    }
    assert snapshot["headline_state"] == "setup"


def test_snapshot_stale_runtime_row_still_fails_closed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    stale = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    store.upsert_runtime_state(
        session_id="daemon-1",
        daemon_host="127.0.0.1",
        daemon_port=9100,
        started_at=T0,
        last_heartbeat_at=stale,
    )

    snapshot = build_runtime_snapshot(
        store=store,
        approval_center_url=None,
        serving_runtime={
            "session_id": "daemon-1",
            "daemon_host": "127.0.0.1",
            "daemon_port": 9100,
            "started_at": T0,
            "last_heartbeat_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    assert protection_check(snapshot, "daemon") == {
        "check_id": "daemon",
        "status": "fail",
        "reason_code": "daemon_heartbeat_stale",
    }


def test_daemon_re_registers_runtime_row_after_it_is_deleted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, daemon = start_daemon(tmp_path, monkeypatch)
    heartbeat = daemon._server.runtime_heartbeat  # pyright: ignore[reportPrivateUsage]
    original_touch = heartbeat.touch
    monkeypatch.setattr(heartbeat, "touch", lambda _at: None)
    try:
        delete_runtime_row(store)
        snapshot = get_json(daemon, "/v1/runtime")
        assert protection_check(snapshot, "daemon") == {
            "check_id": "daemon",
            "status": "unknown",
            "reason_code": "daemon_registration_missing",
        }
        assert snapshot["headline_state"] != "setup"

        original_touch(datetime.now(timezone.utc).isoformat())
        assert_row_reappears_with_daemon_identity(store, daemon)
    finally:
        daemon.stop()


def test_daemon_re_registers_after_fatal_store_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, daemon = start_daemon(tmp_path, monkeypatch)
    heartbeat = daemon._server.runtime_heartbeat  # pyright: ignore[reportPrivateUsage]
    original_touch = heartbeat.touch
    monkeypatch.setattr(heartbeat, "touch", lambda _at: None)
    monkeypatch.setattr(store, "_store_is_proven_unusable", lambda _error: True)
    monkeypatch.setattr(store_connection_schema, "restore_readable_sqlite_store", lambda **_kwargs: False)
    try:
        assert store._recover_fatal_sqlite_store(  # pyright: ignore[reportPrivateUsage]
            sqlite3.DatabaseError("database disk image is malformed")
        )
        assert store.get_runtime_state() is None

        snapshot = get_json(daemon, "/v1/runtime")
        assert protection_check(snapshot, "daemon") == {
            "check_id": "daemon",
            "status": "unknown",
            "reason_code": "daemon_registration_missing",
        }

        original_touch(datetime.now(timezone.utc).isoformat())
        assert_row_reappears_with_daemon_identity(store, daemon)
    finally:
        daemon.stop()


def test_shutdown_winning_the_publish_race_never_registers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    heartbeat = daemon._server.runtime_heartbeat  # pyright: ignore[reportPrivateUsage]
    published: list[str] = []
    monkeypatch.setattr(daemon, "_publish_listen_state", lambda: published.append("published"))
    monkeypatch.setattr(daemon, "_reconcile_runtime_artifacts_best_effort", lambda: None)
    monkeypatch.setattr(daemon, "_maintain_command_activity_best_effort", lambda: None)
    monkeypatch.setattr(
        daemon._server.hook_process_runner,  # pyright: ignore[reportPrivateUsage]
        "require_initial_capacity",
        lambda: None,
    )

    def win_shutdown_race() -> None:
        # Shutdown completed between the outer generation checks and the
        # post-listen publish/heartbeat start.
        daemon._shutdown_started.set()  # pyright: ignore[reportPrivateUsage]

    monkeypatch.setattr(daemon, "_persist_aibom_inventory_context", win_shutdown_race)
    try:
        with pytest.raises(RuntimeError, match="stopped during startup"):
            daemon._complete_owned_service_after_listen(0)  # pyright: ignore[reportPrivateUsage]

        assert published == []
        assert heartbeat._thread is None  # pyright: ignore[reportPrivateUsage]
        assert store.get_runtime_state() is None
    finally:
        daemon._server.server_close()  # pyright: ignore[reportPrivateUsage]
        daemon._diagnostics.close(timeout_seconds=0.5)  # pyright: ignore[reportPrivateUsage]


def test_protection_repair_all_restores_runtime_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub_supported_repair(monkeypatch)
    monkeypatch.setattr(
        daemon_server_module,
        "_repair_command_activity_persistence_health",
        lambda _store: None,
    )
    store, daemon = start_daemon(tmp_path, monkeypatch)
    heartbeat = daemon._server.runtime_heartbeat  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(heartbeat, "touch", lambda _at: None)
    try:
        delete_runtime_row(store)
        status, payload = post_repair(daemon, "all")

        assert status == 200
        assert payload["repaired"] is True
        assert "daemon" in cast(list[str], payload["check_ids"])
        state = store.get_runtime_state()
        assert state is not None
        assert state["session_id"] == daemon._server.runtime_session_id  # pyright: ignore[reportPrivateUsage]
    finally:
        daemon.stop()


def test_protection_repair_all_reports_unavailable_native_probe_truthfully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub_supported_repair(monkeypatch, stub_evidence_health=False)
    monkeypatch.setattr(daemon_server_module, "current_extension_control_snapshot", lambda: None)
    monkeypatch.setattr(
        daemon_server_module,
        "evaluate_command_native",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("native evaluation unavailable")),
    )
    store, daemon = start_daemon(tmp_path, monkeypatch)
    try:
        before = store.get_command_activity_persistence_health().persistence_error_count
        status, payload = post_repair(daemon, "all")
    finally:
        daemon.stop()

    assert status == 409
    assert payload["error"] == "protection_repair_incomplete"
    assert "decision_stream" in cast(list[str], payload["pending_check_ids"])
    check_reasons = cast(dict[str, str], payload["check_reasons"])
    assert check_reasons["decision_stream"] == "native_evaluation_unavailable"
    after = store.get_command_activity_persistence_health().persistence_error_count
    assert after == before


def test_containment_repair_outcome_reports_signal_reasons(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        protection_repair_retry,
        "containment_health_signals",
        lambda _value, **_kwargs: {
            "decision_plane_compatibility": SimpleNamespace(
                status=ProtectionCheckStatus.PASS,
                reason_code="decision_plane_compatible",
            ),
            "containment_compatibility": SimpleNamespace(
                status=ProtectionCheckStatus.FAIL,
                reason_code="containment_probe_stale",
            ),
            "sandbox": SimpleNamespace(
                status=ProtectionCheckStatus.FAIL,
                reason_code="unsupported_platform",
            ),
        },
    )

    repaired, failed, reasons = containment_repair_outcome(lambda: {"ok": True})

    assert repaired == ["decision_plane_compatibility"]
    assert failed == ["containment_compatibility"]
    assert reasons == {"containment_compatibility": "containment_probe_stale"}


def test_containment_repair_outcome_marks_unavailable_health(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_probe() -> dict[str, object]:
        raise RuntimeError("probe failed")

    repaired, failed, reasons = containment_repair_outcome(raise_probe, attempts=2)

    assert repaired == []
    assert failed == [
        "decision_plane_compatibility",
        "containment_compatibility",
        "sandbox",
    ]
    assert reasons == {
        "decision_plane_compatibility": "containment_health_unavailable",
        "containment_compatibility": "containment_health_unavailable",
        "sandbox": "containment_health_unavailable",
    }
