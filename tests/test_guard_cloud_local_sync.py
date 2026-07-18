"""Guard Cloud local sync contract tests."""

from __future__ import annotations

import json
import os
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approvals import build_runtime_snapshot
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import evaluate_detection
from codex_plugin_scanner.guard.edge_events import build_runtime_session_event
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.policy_bundle_parser import (
    computed_policy_bundle_hash,
    payload_hash_for_policy_bundle,
)
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.shims import install_package_shims
from codex_plugin_scanner.guard.store import GuardStore
from tests.cloud_exception_bundle_fixtures import build_cloud_exception_policy_bundle
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


def _signed_runtime_status_policy_bundle(*, workspace_id: str) -> dict[str, object]:
    policy_bundle = build_cloud_exception_policy_bundle(workspace_id=workspace_id)
    policy_bundle["bundleVersion"] = "policy-2026-05-01.3"
    policy_bundle["rolloutState"] = "enforcing"
    policy_bundle["acknowledgements"] = [
        {
            "deviceId": "device-alpha",
            "acknowledgedAt": "2026-06-01T12:00:00+00:00",
            "status": "synced",
        }
    ]
    return sign_policy_bundle(policy_bundle, workspace_id=workspace_id)


def _digest_only_runtime_status_policy_bundle(*, workspace_id: str) -> dict[str, object]:
    policy_bundle = _signed_runtime_status_policy_bundle(workspace_id=workspace_id)
    policy_bundle["verifier"] = {
        "algorithm": "sha256",
        "keyId": "attacker-recomputed-digest",
        "signature": None,
    }
    policy_bundle["bundleHash"] = computed_policy_bundle_hash(policy_bundle)
    policy_bundle["payloadHash"] = payload_hash_for_policy_bundle(policy_bundle)
    return policy_bundle


def _artifact(tmp_path: Path) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="codex:project:workspace-tools",
        name="workspace-tools",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
        command="node",
        args=("workspace.js",),
        transport="stdio",
    )


def _detection(artifact: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )


def test_sync_credentials_preserve_installation_id_when_cloud_workspace_changes(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    installation_id = store.get_or_create_installation_id()

    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    _seed_guard_cloud(store, workspace_id="workspace-beta")

    assert store.get_or_create_installation_id() == installation_id
    assert store.get_cloud_workspace_id() == "workspace-beta"
    _seed_guard_cloud(store)
    store.set_sync_payload("policy", {"policy": "team"}, "2026-04-24T00:00:00+00:00")

    _seed_guard_cloud(store, workspace_id="workspace-alpha")

    assert store.get_cloud_workspace_id() == "workspace-alpha"
    assert store.get_sync_payload("policy") == {"policy": "team"}


def test_evaluate_detection_queues_access_graph_snapshot_without_syncing(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    artifact = _artifact(tmp_path)
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

    evaluation = evaluate_detection(_detection(artifact), store, config, default_action="allow", persist=True)
    pending = store.list_guard_events_v1(uploaded=False, limit=10)
    snapshot_events = [item for item in pending if item["event_type"] == "access_graph.snapshot"]

    assert evaluation["blocked"] is False
    assert len(snapshot_events) == 1
    payload = snapshot_events[0]["payload"]
    assert payload["workspaceId"] == "workspace-alpha"
    assert payload["deviceId"] == store.get_or_create_installation_id()
    assert payload["payload"]["entities"][0]["entityType"] == "device"
    assert any(entity["entityType"] == "mcp_server" for entity in payload["payload"]["entities"])


def test_evaluate_detection_queues_instruction_access_graph_edges(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    instruction_path = tmp_path / "workspace" / "AGENTS.md"
    instruction_path.parent.mkdir(parents=True)
    instruction_path.write_text("# Agent rules\n\nReview changes before using tools.\n", encoding="utf-8")
    artifact = GuardArtifact(
        artifact_id="codex:project:instruction:agents-md",
        name="AGENTS.md",
        harness="codex",
        artifact_type="instruction",
        source_scope="project",
        config_path=str(instruction_path),
    )
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

    evaluation = evaluate_detection(_detection(artifact), store, config, default_action="allow", persist=True)
    pending = store.list_guard_events_v1(uploaded=False, limit=10)
    snapshot_events = [item for item in pending if item["event_type"] == "access_graph.snapshot"]
    payload = snapshot_events[0]["payload"]
    graph_payload = payload["payload"]

    assert evaluation["blocked"] is False
    assert any(entity["entityType"] == "instruction" for entity in graph_payload["entities"])
    assert any(edge["edgeType"] == "agent_uses_instruction" for edge in graph_payload["edges"])


def test_evaluate_detection_queues_access_graph_snapshot_without_cloud_workspace(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store)
    artifact = _artifact(tmp_path)
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

    evaluation = evaluate_detection(_detection(artifact), store, config, default_action="allow", persist=True)
    pending = store.list_guard_events_v1(uploaded=False, limit=10)
    snapshot_events = [item for item in pending if item["event_type"] == "access_graph.snapshot"]

    assert evaluation["blocked"] is False
    assert len(snapshot_events) == 1
    payload = snapshot_events[0]["payload"]
    assert payload["workspaceId"] is None
    assert payload["deviceId"] == store.get_or_create_installation_id()
    assert any(entity["entityType"] == "mcp_server" for entity in payload["payload"]["entities"])


class _FailingAccessGraphEventStore(GuardStore):
    def add_guard_event_v1(self, event) -> None:
        if event.event_type == "access_graph.snapshot":
            raise RuntimeError("sync failed for sk-live-secret-token")
        super().add_guard_event_v1(event)


def test_access_graph_queue_failure_does_not_block_local_approval_decision(tmp_path: Path) -> None:
    store = _FailingAccessGraphEventStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    artifact = _artifact(tmp_path)
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

    evaluation = evaluate_detection(_detection(artifact), store, config, default_action="allow", persist=True)
    failure_events = store.list_events(limit=5, event_name="access_graph_snapshot_queue_failed")

    assert evaluation["blocked"] is False
    assert failure_events[0]["payload"]["error_type"] == "RuntimeError"
    assert "sk-live-secret-token" not in json.dumps(failure_events[0]["payload"])


def test_guard_cloud_event_queue_backpressures_without_dropping_pending_events(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home", guard_event_queue_limit=3)

    for index in range(3):
        event = build_runtime_session_event(
            session_id=f"session-{index}",
            occurred_at=f"2026-04-24T00:00:0{index}+00:00",
            payload={"sessionSecret": "sk-live-secret-token", "index": index},
            workspace_id="workspace-alpha",
            device_id="device-1",
        )
        store.add_guard_event_v1(event)

    store.add_guard_event_v1(
        build_runtime_session_event(
            session_id="session-3",
            occurred_at="2026-04-24T00:00:03+00:00",
            payload={"sessionSecret": "sk-live-secret-token", "index": 3},
            workspace_id="workspace-alpha",
            device_id="device-1",
        )
    )

    pending = store.list_guard_events_v1(uploaded=False, limit=10)
    assert [item["payload"]["payload"]["index"] for item in pending] == [0, 1, 2]
    assert store.get_sync_payload("guard_event_queue_capacity") == {
        "exhausted": True,
        "firstRejectedAt": "2026-04-24T00:00:03+00:00",
        "lastRejectedAt": "2026-04-24T00:00:03+00:00",
        "limit": 3,
        "pendingCount": 3,
        "rejectedCount": 1,
        "rejectedEventType": "runtime.session",
    }
    store.mark_guard_events_v1_uploaded(
        [str(pending[0]["event_id"])],
        "2026-04-24T00:01:00+00:00",
    )
    assert store.get_sync_payload("guard_event_queue_capacity") == {
        "exhausted": False,
        "firstRejectedAt": "2026-04-24T00:00:03+00:00",
        "lastRejectedAt": "2026-04-24T00:00:03+00:00",
        "limit": 3,
        "pendingCount": 2,
        "recoveredAt": "2026-04-24T00:01:00+00:00",
        "rejectedCount": 1,
        "rejectedEventType": "runtime.session",
    }


def test_sync_guard_events_records_failed_backoff_without_dropping_pending_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    store.add_guard_event_v1(
        build_runtime_session_event(
            session_id="session-1",
            occurred_at="2026-04-24T00:00:00+00:00",
            payload={"sessionSecret": "sk-live-secret-token"},
            workspace_id="workspace-alpha",
            device_id="device-1",
        )
    )

    def _raise_url_error(request, timeout):
        raise urllib.error.URLError("sk-live-secret-token timed out")

    monkeypatch.setattr(guard_runner_module.urllib.request, "urlopen", _raise_url_error)

    with pytest.raises(RuntimeError):
        guard_runner_module.sync_guard_events(store)

    summary = store.get_sync_payload("guard_events_v1_summary")
    pending = store.list_guard_events_v1(uploaded=False, limit=10)

    assert isinstance(summary, dict)
    assert summary["status"] == "failed"
    assert summary["retry_after_seconds"] == 120
    assert "next_retry_after" in summary
    assert "sk-live-secret-token" not in json.dumps(summary)
    assert len(pending) == 1


def test_guard_cloud_event_queue_backpressures_large_backlog_without_sqlite_limit(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home", guard_event_queue_limit=1100)

    for index in range(1005):
        store.add_guard_event_v1(
            build_runtime_session_event(
                session_id=f"session-{index}",
                occurred_at=f"2026-04-24T00:{index // 60:02d}:{index % 60:02d}+00:00",
                payload={"index": index},
                workspace_id="workspace-alpha",
                device_id="device-1",
            )
        )
    store._guard_event_queue_limit = 2
    store.add_guard_event_v1(
        build_runtime_session_event(
            session_id="session-1005",
            occurred_at="2026-04-24T00:16:45+00:00",
            payload={"index": 1005},
            workspace_id="workspace-alpha",
            device_id="device-1",
        )
    )

    assert store.count_guard_events_v1(uploaded=False) == 1005
    assert store.get_sync_payload("guard_event_queue_capacity") == {
        "exhausted": True,
        "firstRejectedAt": "2026-04-24T00:16:45+00:00",
        "lastRejectedAt": "2026-04-24T00:16:45+00:00",
        "limit": 2,
        "pendingCount": 1005,
        "rejectedCount": 1,
        "rejectedEventType": "runtime.session",
    }


def test_sync_guard_events_preserves_pending_events_when_v1_endpoint_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", guard_event_queue_limit=400)
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    for index in range(250):
        store.add_guard_event_v1(
            build_runtime_session_event(
                session_id=f"session-{index}",
                occurred_at=f"2026-04-24T00:{index // 60:02d}:{index % 60:02d}+00:00",
                payload={"index": index},
                workspace_id="workspace-alpha",
                device_id="device-1",
            )
        )

    def _raise_not_found(**_kwargs):
        raise urllib.error.HTTPError(
            url="https://hol.org/api/v1/guard/events",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None,
        )

    monkeypatch.setattr(
        guard_runner_module,
        "_urlopen_json_with_timeout_retry",
        _raise_not_found,
    )

    result = guard_runner_module.sync_guard_events(store)

    assert result["sync_reason"] == "guard_events_endpoint_unavailable"
    assert result["skipped"] == 0
    assert result["pending_count"] == 200  # first batch of 200 attempted
    # All events must remain pending — 404 must NOT silently drop data
    assert store.count_guard_events_v1(uploaded=False) == 250
    assert store.count_guard_events_v1(uploaded=True) == 0


def test_sync_guard_events_preserves_unavailable_summary_when_no_events_pending(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    store.set_sync_payload(
        "guard_events_v1_summary",
        {
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "sync_skipped": True,
            "sync_reason": "guard_events_endpoint_unavailable",
        },
        datetime.now(timezone.utc).isoformat(),
    )

    result = guard_runner_module.sync_guard_events(store)
    stored = store.get_sync_payload("guard_events_v1_summary")

    assert result["sync_reason"] == "guard_events_endpoint_unavailable"
    assert result["sync_skipped"] is True
    assert stored == result


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


def test_runtime_session_sync_skips_v1_event_when_ingest_was_recently_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    store.set_sync_payload(
        "guard_events_v1_summary",
        {
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "sync_skipped": True,
            "sync_reason": "guard_events_endpoint_unavailable",
        },
        datetime.now(timezone.utc).isoformat(),
    )

    def _runtime_sync_response(**_kwargs):
        return {"syncedAt": "2026-04-24T00:01:00+00:00", "items": []}

    monkeypatch.setattr(
        guard_runner_module,
        "_urlopen_json_with_timeout_retry",
        _runtime_sync_response,
    )

    result = guard_runner_module.sync_runtime_session(
        store,
        session={
            "harness": "codex",
            "surface": "cli",
            "status": "active",
        },
    )

    assert result["runtime_session_synced_at"] == "2026-04-24T00:01:00+00:00"
    assert store.list_guard_events_v1(uploaded=False, limit=10) == []


def test_sync_runtime_session_emits_package_manager_coverage_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HOL_GUARD_POLICY_YAML_IMPORT", raising=False)
    monkeypatch.delenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", raising=False)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    context = HarnessContext(
        home_dir=store.guard_home,
        workspace_dir=workspace_dir,
        guard_home=store.guard_home,
    )
    install_payload = install_package_shims(context, managers=("npm",))
    shim_dir = Path(str(install_payload["shim_dir"]))
    original_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{original_path}")
    store.set_sync_payload(
        "supply_chain_bundle_summary",
        {
            "synced_at": "2026-04-24T00:00:00+00:00",
        },
        "2026-04-24T00:00:00+00:00",
    )

    captured_body: dict[str, object] = {}

    def _runtime_sync_response(**kwargs):
        request = kwargs["request"]
        captured_body.update(json.loads(request.data.decode("utf-8")))
        return {"syncedAt": "2026-04-24T00:01:00+00:00", "items": []}

    monkeypatch.setattr(
        guard_runner_module,
        "_urlopen_json_with_timeout_retry",
        _runtime_sync_response,
    )

    guard_runner_module.sync_runtime_session(
        store,
        session={
            **guard_runner_module._local_guard_runtime_session(),
            "updatedAt": "2026-04-24T00:01:00+00:00",
            "workspace": str(workspace_dir),
        },
    )

    session_payload = captured_body["session"]
    assert isinstance(session_payload, dict)
    assert session_payload["deviceId"] == store.get_or_create_installation_id()
    assert session_payload["deviceName"] == store.get_device_metadata()["device_label"]
    assert session_payload["localIdentity"]["lastSyncedAt"] == "2026-04-24T00:01:00+00:00"
    assert session_payload["localIdentitySource"]["daemonId"] == "local-guard"
    assert session_payload["localIdentitySource"]["daemonVersion"] == "local-guard"
    assert session_payload["localIdentitySource"]["daemonStatus"] == "local-guard"
    assert session_payload["localIdentitySource"]["relayState"] == "local-guard"
    assert session_payload["packageManagerCoverage"] == {
        "generatedAt": "2026-04-24T00:01:00+00:00",
        "configuredManagers": ["npm"],
        "protectedManagers": ["npm"],
        "missingManagers": [],
        "pathActive": True,
        "bypasses": [],
        "staleIntel": {
            "status": "fresh",
            "lastSyncedAt": "2026-04-24T00:00:00+00:00",
            "nextRefreshAt": "2026-04-24T00:15:00+00:00",
        },
    }
    assert session_payload["policyDocumentVersions"] == ["guard.hashgraphonline.com/v1alpha1"]
    assert session_payload["policyBundleVersions"] == [
        "guard-policy-bundle.v1",
        "guard-policy-bundle.v2",
    ]
    assert session_payload["policyContracts"] == [
        "guard-policy-bundle/v1",
        "guard-policy-bundle/v2",
    ]
    assert session_payload["yamlImport"] is False
    assert "canonicalPolicyEnforcement" not in session_payload


def test_local_runtime_session_advertises_enabled_policy_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")

    session = guard_runner_module._local_guard_runtime_session()

    assert session["policy_document_versions"] == ["guard.hashgraphonline.com/v1alpha1"]
    assert session["policy_bundle_versions"] == [
        "guard-policy-bundle.v1",
        "guard-policy-bundle.v2",
    ]
    assert session["policy_contracts"] == [
        "guard-policy-bundle/v1",
        "guard-policy-bundle/v2",
    ]
    assert session["yaml_import"] is True
    assert session["canonical_policy_enforcement"] is True


def test_local_runtime_session_applies_stable_policy_rollout_cohorts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "25")

    cohort = [
        guard_runner_module._canonical_policy_enforcement_enabled(
            device_id=f"device-{index}",
            workspace_id="workspace-alpha",
        )
        for index in range(100)
    ]

    assert any(cohort)
    assert not all(cohort)
    assert cohort == [
        guard_runner_module._canonical_policy_enforcement_enabled(
            device_id=f"device-{index}",
            workspace_id="workspace-alpha",
        )
        for index in range(100)
    ]


def test_sync_runtime_session_prefers_latest_sync_summary_for_package_manager_coverage_freshness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    context = HarnessContext(
        home_dir=store.guard_home,
        workspace_dir=workspace_dir,
        guard_home=store.guard_home,
    )
    install_payload = install_package_shims(context, managers=("npm",))
    shim_dir = Path(str(install_payload["shim_dir"]))
    original_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{original_path}")
    store.set_sync_payload(
        "supply_chain_bundle_summary",
        {
            "synced_at": "2026-04-24T00:00:00+00:00",
        },
        "2026-04-24T00:00:00+00:00",
    )
    store.set_sync_payload(
        "sync_summary",
        {
            "synced_at": "2026-04-24T00:20:00+00:00",
        },
        "2026-04-24T00:20:00+00:00",
    )

    captured_body: dict[str, object] = {}

    def _runtime_sync_response(**kwargs):
        request = kwargs["request"]
        captured_body.update(json.loads(request.data.decode("utf-8")))
        return {"syncedAt": "2026-04-24T00:21:00+00:00", "items": []}

    monkeypatch.setattr(
        guard_runner_module,
        "_urlopen_json_with_timeout_retry",
        _runtime_sync_response,
    )

    guard_runner_module.sync_runtime_session(
        store,
        session={
            "harness": "codex",
            "surface": "cli",
            "status": "active",
            "updatedAt": "2026-04-24T00:21:00+00:00",
            "workspace": str(workspace_dir),
        },
    )

    session_payload = captured_body["session"]
    assert isinstance(session_payload, dict)
    assert session_payload["packageManagerCoverage"]["staleIntel"] == {
        "status": "fresh",
        "lastSyncedAt": "2026-04-24T00:20:00+00:00",
        "nextRefreshAt": "2026-04-24T00:35:00+00:00",
    }


def test_sync_runtime_session_prefers_ipv6_private_identity_when_ipv4_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    monkeypatch.setattr(guard_runner_module, "_safe_private_ip", lambda: None)
    monkeypatch.setattr(guard_runner_module, "_safe_private_ipv6", lambda: "fd00::42")
    captured_body: dict[str, object] = {}

    def _runtime_sync_response(**kwargs):
        request = kwargs["request"]
        captured_body.update(json.loads(request.data.decode("utf-8")))
        return {"syncedAt": "2026-04-24T00:01:00+00:00", "items": []}

    monkeypatch.setattr(
        guard_runner_module,
        "_urlopen_json_with_timeout_retry",
        _runtime_sync_response,
    )

    guard_runner_module.sync_runtime_session(
        store,
        session={
            "harness": "codex",
            "surface": "cli",
            "status": "active",
            "updatedAt": "2026-04-24T00:01:00+00:00",
            "workspace": str(tmp_path / "workspace"),
        },
    )

    session_payload = captured_body["session"]
    assert isinstance(session_payload, dict)
    assert session_payload["localIdentity"]["ipAddress"] == "fd00::42"
    assert session_payload["localIdentity"]["privateIpAddress"] == "fd00::42"
    assert session_payload["localIdentitySource"]["privateIpAddress"] == "local-guard"


def test_sync_runtime_session_keeps_local_identity_when_package_coverage_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    monkeypatch.setattr(
        guard_runner_module,
        "package_shim_cloud_coverage",
        lambda *_args, **_kwargs: {
            "generatedAt": "2026-04-24T00:01:00+00:00",
            "configuredManagers": [],
            "protectedManagers": [],
            "missingManagers": [],
            "pathActive": False,
            "bypasses": [],
            "staleIntel": {
                "status": "unknown",
                "lastSyncedAt": None,
                "nextRefreshAt": None,
            },
        },
    )
    captured_body: dict[str, object] = {}

    def _runtime_sync_response(**kwargs):
        request = kwargs["request"]
        captured_body.update(json.loads(request.data.decode("utf-8")))
        return {"syncedAt": "2026-04-24T00:01:00+00:00", "items": []}

    monkeypatch.setattr(
        guard_runner_module,
        "_urlopen_json_with_timeout_retry",
        _runtime_sync_response,
    )

    guard_runner_module.sync_runtime_session(
        store,
        session={
            "harness": "codex",
            "surface": "cli",
            "status": "active",
            "updatedAt": "2026-04-24T00:01:00+00:00",
            "workspace": str(tmp_path / "workspace"),
        },
    )

    session_payload = captured_body["session"]
    assert isinstance(session_payload, dict)
    assert "daemonId" not in session_payload["localIdentity"]
    assert session_payload["localIdentitySource"]["daemonId"] == "local-guard"


def test_sync_guard_events_preserves_pending_events_when_rate_limited(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On HTTP 429, events must remain pending and the summary must report rate-limited state."""
    store = GuardStore(tmp_path / "guard-home", guard_event_queue_limit=400)
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    store.add_guard_event_v1(
        build_runtime_session_event(
            session_id="session-rate-limited",
            occurred_at="2026-06-25T00:00:00+00:00",
            payload={"test": "rate_limit"},
            workspace_id="workspace-alpha",
            device_id="device-1",
        )
    )

    def _raise_rate_limited(**_kwargs):
        raise urllib.error.HTTPError(
            url="https://hol.org/api/v1/guard/events",
            code=429,
            msg="Too Many Requests",
            hdrs={"Retry-After": "30"},
            fp=None,
        )

    monkeypatch.setattr(
        guard_runner_module,
        "_urlopen_json_with_timeout_retry",
        _raise_rate_limited,
    )

    result = guard_runner_module.sync_guard_events(store)

    assert result["sync_reason"] == "guard_events_rate_limited"
    assert result["skipped"] == 0
    assert result["pending_count"] == 1
    assert result["retry_after_seconds"] == 30
    # Events must remain pending — 429 must NOT silently drop data
    assert store.count_guard_events_v1(uploaded=False) == 1
    assert store.count_guard_events_v1(uploaded=True) == 0
