"""Runtime registration self-heal after the guard_runtime_state row is lost."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.approvals import build_runtime_snapshot
from codex_plugin_scanner.guard.daemon import protection_repair_retry
from codex_plugin_scanner.guard.daemon.protection_repair_retry import containment_repair_outcome
from codex_plugin_scanner.guard.runtime.protection_health import ProtectionCheckStatus
from codex_plugin_scanner.guard.store import GuardStore
from tests.daemon_control_patching import patch_daemon_global
from tests.runtime_registration_support import (
    CONTAINMENT_CHECK_IDS,
    T0,
    delete_runtime_row,
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


def test_protection_repair_all_restores_runtime_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub_supported_repair(monkeypatch)
    patch_daemon_global(
        monkeypatch,
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


def test_protection_repair_all_clears_degraded_evidence_without_a_native_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub_supported_repair(monkeypatch, stub_evidence_health=False)
    store, daemon = start_daemon(tmp_path, monkeypatch)
    store.record_command_activity_persistence_failure(
        error_code="pre_record_failed",
        occurred_at=datetime.now(timezone.utc),
    )
    try:
        _status, payload = post_repair(daemon, "all")
    finally:
        daemon.stop()

    assert "decision_stream" in cast(list[str], payload["check_ids"])
    assert "decision_stream" not in cast(dict[str, str], payload["check_reasons"])
    assert store.get_command_activity_persistence_health().active_error_count == 0


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
