"""Guard Cloud local runtime snapshot contract tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approvals import build_runtime_snapshot
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cloud_local_sync_helpers import (
    _digest_only_runtime_status_policy_bundle,
    _seed_guard_cloud,
    _signed_runtime_status_policy_bundle,
)
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring


def test_build_runtime_snapshot_calls_oauth_health_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    calls = 0
    original = store.get_oauth_local_credential_health

    def counted_health() -> dict[str, object]:
        nonlocal calls
        calls += 1
        return original()

    monkeypatch.setattr(store, "get_oauth_local_credential_health", counted_health)

    build_runtime_snapshot(store=store, approval_center_url=None)

    assert calls == 1


def test_runtime_snapshot_exposes_safe_trust_status(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    snapshot = build_runtime_snapshot(store=store, approval_center_url=None)

    trust_status = snapshot["trust_status"]
    assert trust_status["runtime_protection"] in {"protected", "degraded", "unknown"}
    assert trust_status["remembered_rules"] in {"enforced", "disabled_degraded", "unknown"}
    assert trust_status["cloud_policies"] in {"available", "setup_unavailable", "unknown"}
    assert trust_status["last_proof"] is None
    serialized = json.dumps(snapshot, sort_keys=True)
    assert "key_id" not in serialized


def test_runtime_snapshot_trust_status_does_not_refresh_integrity_state(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    cached_state = {
        "backend": "cached-backend",
        "mode": "degraded",
        "enforcement": "disabled",
        "degraded_reasons": ["policy_integrity_key_unavailable"],
    }
    store.set_sync_payload("policy_integrity", cached_state, "2026-06-18T00:00:00+00:00")

    snapshot = build_runtime_snapshot(store=store, approval_center_url=None)

    assert snapshot["trust_status"]["runtime_protection"] == "degraded"
    assert snapshot["trust_status"]["remembered_rules"] == "disabled_degraded"
    assert store.get_sync_payload("policy_integrity") == cached_state


def test_runtime_snapshot_treats_naive_sync_timestamps_as_utc(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    store.set_sync_payload(
        "guard_events_v1_summary",
        {"synced_at": "2000-01-01T00:00:00"},
        "2000-01-01T00:00:00+00:00",
    )

    snapshot = build_runtime_snapshot(store=store, approval_center_url=None)

    assert snapshot["cloud_sync_health"]["state"] == "stale"
    assert snapshot["cloud_sync_health"]["last_synced_at"] == "2000-01-01T00:00:00"


def test_runtime_snapshot_reports_endpoint_unavailable_sync_as_degraded(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    store.set_sync_payload(
        "sync_summary",
        {"synced_at": datetime.now(timezone.utc).isoformat()},
        datetime.now(timezone.utc).isoformat(),
    )
    store.set_sync_payload(
        "guard_events_v1_summary",
        {
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "sync_skipped": True,
            "sync_reason": "guard_events_endpoint_unavailable",
        },
        datetime.now(timezone.utc).isoformat(),
    )

    snapshot = build_runtime_snapshot(store=store, approval_center_url=None)

    assert snapshot["cloud_sync_health"]["state"] == "degraded"
    assert snapshot["cloud_sync_health"]["label"] == "Cloud sync degraded"


def test_runtime_snapshot_exposes_local_device_without_cloud_pairing(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    device = store.get_device_metadata()

    snapshot = build_runtime_snapshot(
        store=store,
        approval_center_url=None,
        now="2026-04-24T00:00:00+00:00",
    )

    assert snapshot["device"] == {
        "installation_id": device["installation_id"],
        "device_label": device["device_label"],
        "local_registered": True,
    }
    assert snapshot["latest_connect_state"] is None
    assert snapshot["cloud_sync_health"]["state"] == "disabled"
    assert snapshot["cloud_sync_health"]["label"] == "Cloud optional"
    assert "Local Guard is active" in snapshot["cloud_sync_health"]["detail"]
    assert "Guard Cloud is optional" in snapshot["cloud_state_detail"]
    assert snapshot["proof_status"] == {
        "state": "not_connected",
        "label": "Cloud proof not started",
        "detail": "Connect Guard Cloud to sync this device proof.",
        "request_id": None,
        "pairing_completed_at": None,
        "first_synced_at": None,
        "runtime_session_id": None,
        "runtime_session_synced_at": None,
        "receipts_stored": 0,
        "inventory_items": 0,
    }


def test_runtime_snapshot_exposes_cloud_policy_bundle_fields(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-06-01T00:00:00+00:00"
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-alpha"),
        now,
    )
    policy_bundle = _signed_runtime_status_policy_bundle(workspace_id="workspace-alpha")
    store.set_sync_payload(
        "policy_bundle",
        policy_bundle,
        now,
    )
    device = store.get_device_metadata()
    store.set_sync_payload(
        "policy_bundle_ack",
        {
            "appliedAt": "2026-06-01T12:00:00+00:00",
            "bundleHash": policy_bundle["bundleHash"],
            "bundleVersion": policy_bundle["bundleVersion"],
            "deviceId": device["installation_id"],
            "deviceName": device["device_label"],
            "status": "synced",
        },
        now,
    )
    store.set_sync_payload(
        "policy_bundle_last_error",
        {"reason": "sync_failed"},
        now,
    )

    snapshot = build_runtime_snapshot(store=store, approval_center_url=None)

    assert snapshot["cloud_policy_bundle_version"] == "policy-2026-05-01.3"
    assert snapshot["cloud_policy_bundle_hash"] == policy_bundle["bundleHash"]
    assert snapshot["cloud_policy_rollout_state"] == "enforcing"
    assert snapshot["cloud_policy_sync_error"] == "sync_failed"
    assert snapshot["cloud_policy_last_ack_at"] == "2026-06-01T12:00:00+00:00"


def test_runtime_snapshot_ignores_policy_bundle_ack_for_another_device(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-06-01T00:00:00+00:00"
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-alpha"),
        now,
    )
    policy_bundle = _signed_runtime_status_policy_bundle(workspace_id="workspace-alpha")
    store.set_sync_payload("policy_bundle", policy_bundle, now)
    store.set_sync_payload(
        "policy_bundle_ack",
        {
            "appliedAt": "2026-06-01T12:00:00+00:00",
            "bundleHash": policy_bundle["bundleHash"],
            "bundleVersion": policy_bundle["bundleVersion"],
            "deviceId": "another-device",
            "status": "synced",
        },
        now,
    )

    snapshot = build_runtime_snapshot(store=store, approval_center_url=None)

    assert snapshot["cloud_policy_last_ack_at"] is None


def test_runtime_snapshot_rejects_digest_only_cached_bundle_metadata(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-06-01T00:00:00+00:00"
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-alpha"),
        now,
    )
    store.set_sync_payload(
        "policy_bundle",
        _digest_only_runtime_status_policy_bundle(workspace_id="workspace-alpha"),
        now,
    )
    store.set_sync_payload("policy_bundle_last_error", {"reason": "sync_failed"}, now)

    snapshot = build_runtime_snapshot(store=store, approval_center_url=None)

    assert snapshot["cloud_policy_bundle_version"] is None
    assert snapshot["cloud_policy_bundle_hash"] is None
    assert snapshot["cloud_policy_rollout_state"] is None
    assert snapshot["cloud_policy_sync_error"] == "unsupported_signature_algorithm"
    assert snapshot["cloud_policy_last_ack_at"] is None


def test_runtime_snapshot_exposes_latest_connect_proof_without_pairing_secrets(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    request_id = "connect-imported-state"
    with store._connect() as connection:
        connection.execute(
            """
            insert into guard_connect_states (
              request_id,
              sync_url,
              allowed_origin,
              status,
              milestone,
              reason,
              created_at,
              updated_at,
              expires_at,
              completed_at,
              proof_json
            )
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                "https://hol.org/api/guard/receipts/sync",
                "https://hol.org",
                "connected",
                "first_sync_succeeded",
                None,
                "2026-04-24T00:00:00+00:00",
                "2026-04-24T00:02:00+00:00",
                "2026-04-24T00:05:00+00:00",
                "2026-04-24T00:01:00+00:00",
                json.dumps(
                    {
                        "pairing_completed_at": "2026-04-24T00:01:00+00:00",
                        "first_synced_at": "2026-04-24T00:02:00+00:00",
                        "receipts_stored": 3,
                        "inventory_items": 5,
                        "runtime_session_id": "runtime-session-1",
                        "runtime_session_synced_at": "2026-04-24T00:01:30+00:00",
                    }
                ),
            ),
        )

    snapshot = build_runtime_snapshot(
        store=store,
        approval_center_url=None,
        now="2026-04-24T00:03:00+00:00",
    )
    latest_connect_state = snapshot["latest_connect_state"]
    proof_status = snapshot["proof_status"]

    assert isinstance(latest_connect_state, dict)
    assert latest_connect_state["request_id"] == request_id
    assert latest_connect_state["status"] == "connected"
    assert latest_connect_state["milestone"] == "first_sync_succeeded"
    assert "sync_url" not in latest_connect_state
    assert "allowed_origin" not in latest_connect_state
    assert "secret-browser-session-token" not in json.dumps(latest_connect_state)
    assert latest_connect_state["proof"] == {
        "pairing_completed_at": "2026-04-24T00:01:00+00:00",
        "first_synced_at": "2026-04-24T00:02:00+00:00",
        "receipts_stored": 3,
        "inventory_items": 5,
        "runtime_session_id": "runtime-session-1",
        "runtime_session_synced_at": "2026-04-24T00:01:30+00:00",
    }
    assert proof_status == {
        "state": "synced",
        "label": "First proof synced",
        "detail": "This device completed its first Guard Cloud proof sync.",
        "request_id": request_id,
        "pairing_completed_at": "2026-04-24T00:01:00+00:00",
        "first_synced_at": "2026-04-24T00:02:00+00:00",
        "runtime_session_id": "runtime-session-1",
        "runtime_session_synced_at": "2026-04-24T00:01:30+00:00",
        "receipts_stored": 3,
        "inventory_items": 5,
    }


def test_runtime_snapshot_marks_connected_state_retry_required_when_oauth_missing(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request_id = "connect-missing-oauth"
    with store._connect() as connection:
        connection.execute(
            """
            insert into guard_connect_states (
              request_id,
              sync_url,
              allowed_origin,
              status,
              milestone,
              reason,
              created_at,
              updated_at,
              expires_at,
              completed_at,
              proof_json
            )
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                "https://hol.org/api/guard/receipts/sync",
                "https://hol.org",
                "connected",
                "first_sync_succeeded",
                None,
                "2026-04-24T00:00:00+00:00",
                "2026-04-24T00:02:00+00:00",
                "2026-04-24T00:05:00+00:00",
                "2026-04-24T00:01:00+00:00",
                json.dumps(
                    {
                        "pairing_completed_at": "2026-04-24T00:01:00+00:00",
                        "first_synced_at": "2026-04-24T00:02:00+00:00",
                        "receipts_stored": 3,
                        "inventory_items": 5,
                    }
                ),
            ),
        )

    snapshot = build_runtime_snapshot(
        store=store,
        approval_center_url=None,
        now="2026-04-24T00:03:00+00:00",
    )
    latest_connect_state = snapshot["latest_connect_state"]

    assert isinstance(latest_connect_state, dict)
    assert latest_connect_state["request_id"] == request_id
    assert latest_connect_state["status"] == "retry_required"
    assert latest_connect_state["milestone"] == "first_sync_failed"
    assert latest_connect_state["reason"] == (
        "Guard Cloud authorization on this machine is incomplete. Run hol-guard connect again."
    )
    assert snapshot["cloud_state"] == "local_only"
    assert snapshot["sync_configured"] is False
    assert snapshot["proof_status"]["state"] == "failed"


@pytest.mark.parametrize(
    ("status", "milestone", "expected_state", "expected_label", "expected_detail"),
    [
        (
            "connected",
            "first_sync_pending",
            "pending",
            "First proof pending",
            (
                "Browser sign-in finished. Local Guard will retry the first proof sync automatically "
                "while the daemon is running, or you can run hol-guard sync now."
            ),
        ),
        (
            "retry_required",
            "first_sync_failed",
            "failed",
            "First proof needs retry",
            "Guard Cloud sign-in on this machine needs repair. Run hol-guard connect again.",
        ),
        (
            "waiting",
            "waiting_for_browser",
            "waiting",
            "Waiting for browser sign-in",
            "Open the sign-in link to register this local Guard device.",
        ),
        (
            "expired",
            "expired",
            "expired",
            "Sign-in expired",
            "The sign-in link expired. Run hol-guard connect again.",
        ),
    ],
)
def test_runtime_snapshot_uses_oauth_connect_copy_for_proof_statuses(
    tmp_path: Path,
    status: str,
    milestone: str,
    expected_state: str,
    expected_label: str,
    expected_detail: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    if status == "connected":
        _seed_guard_cloud(store, workspace_id="workspace-alpha")
    request_id = f"connect-{expected_state}"
    with store._connect() as connection:
        connection.execute(
            """
            insert into guard_connect_states (
              request_id,
              sync_url,
              allowed_origin,
              status,
              milestone,
              reason,
              created_at,
              updated_at,
              expires_at,
              completed_at,
              proof_json
            )
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                "https://hol.org/api/guard/receipts/sync",
                "https://hol.org",
                status,
                milestone,
                None,
                "2026-04-24T00:00:00+00:00",
                "2026-04-24T00:00:30+00:00",
                "2026-04-24T00:05:00+00:00",
                None,
                json.dumps({}),
            ),
        )

    snapshot = build_runtime_snapshot(
        store=store,
        approval_center_url=None,
        now="2026-04-24T00:01:00+00:00",
    )
    proof_status = snapshot["proof_status"]

    assert proof_status["state"] == expected_state
    assert proof_status["label"] == expected_label
    assert proof_status["detail"] == expected_detail
    assert "pairing" not in expected_label.lower()
    assert "pairing" not in expected_detail.lower()


def test_runtime_snapshot_counts_large_history_without_shipping_every_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt_limits: list[int] = []

    def list_limited_receipts(
        limit: int = 50,
        harness: str | None = None,
    ) -> list[dict[str, object]]:
        receipt_limits.append(limit)
        return [
            {
                "receipt_id": "receipt-large-history",
                "harness": "codex",
                "artifact_id": "codex:demo",
                "artifact_hash": "hash-demo",
                "policy_decision": "allow",
                "capabilities_summary": "command reviewed",
                "changed_capabilities": [],
                "provenance_summary": "local",
                "user_override": None,
                "artifact_name": "demo command",
                "source_scope": None,
                "timestamp": "2026-04-24T00:00:00+00:00",
            }
        ]

    monkeypatch.setattr(store, "list_receipts", list_limited_receipts)
    monkeypatch.setattr(store, "count_receipts", lambda harness=None: 100_000)

    snapshot = build_runtime_snapshot(store=store, approval_center_url=None)

    assert snapshot["receipt_count"] == 100_000
    assert len(snapshot["latest_receipts"]) == 1
    assert receipt_limits == [25]
