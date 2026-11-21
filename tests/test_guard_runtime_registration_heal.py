"""Runtime registration self-heal after the guard_runtime_state row is lost."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.approvals import build_runtime_snapshot
from codex_plugin_scanner.guard.store import GuardStore
from tests.runtime_registration_support import (
    CONTAINMENT_CHECK_IDS,
    T0,
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
