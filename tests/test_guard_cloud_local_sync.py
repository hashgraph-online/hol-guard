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
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection, PolicyDecision
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.shims import install_package_shims
from codex_plugin_scanner.guard.store import GuardStore


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

    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
    )
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-two",
        "2026-04-24T00:01:00+00:00",
        workspace_id="workspace-beta",
    )

    assert store.get_or_create_installation_id() == installation_id
    assert store.get_cloud_workspace_id() == "workspace-beta"


def test_sync_credentials_refresh_preserves_existing_cloud_workspace_id(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
    )
    store.set_sync_payload("policy", {"policy": "team"}, "2026-04-24T00:00:00+00:00")

    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:01:00+00:00",
    )

    assert store.get_cloud_workspace_id() == "workspace-alpha"
    assert store.get_sync_payload("policy") == {"policy": "team"}


def test_sync_credentials_token_rotation_clears_stale_cloud_workspace_id(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
    )
    store.set_sync_payload("policy", {"policy": "team"}, "2026-04-24T00:00:00+00:00")

    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-two",
        "2026-04-24T00:01:00+00:00",
    )

    assert store.get_cloud_workspace_id() is None
    assert store.get_sync_payload("policy") is None


def test_sync_credentials_workspace_metadata_update_preserves_cached_policy(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
    )
    store.set_sync_payload("policy", {"policy": "team"}, "2026-04-24T00:00:00+00:00")

    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:01:00+00:00",
        workspace_id="workspace-alpha",
    )

    assert store.get_cloud_workspace_id() == "workspace-alpha"
    assert store.get_sync_payload("policy") == {"policy": "team"}


def test_sync_credentials_workspace_switch_clears_stale_cloud_policy_allows(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
    )
    store.set_sync_payload("policy", {"policy": "workspace-alpha"}, "2026-04-24T00:00:00+00:00")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="harness",
            action="allow",
            source="cloud-sync",
            reason="workspace alpha cloud allow",
        ),
        "2026-04-24T00:00:00+00:00",
    )

    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:01:00+00:00",
        workspace_id="workspace-beta",
    )

    assert store.get_cloud_workspace_id() == "workspace-beta"
    assert store.get_sync_payload("policy") is None
    assert not any(item["source"] in {"cloud-sync", "team-policy"} for item in store.list_policy_decisions())


def test_evaluate_detection_queues_access_graph_snapshot_without_syncing(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
    )
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


def test_evaluate_detection_queues_access_graph_snapshot_without_cloud_workspace(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
    )
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
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
    )
    artifact = _artifact(tmp_path)
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

    evaluation = evaluate_detection(_detection(artifact), store, config, default_action="allow", persist=True)
    failure_events = store.list_events(limit=5, event_name="access_graph_snapshot_queue_failed")

    assert evaluation["blocked"] is False
    assert failure_events[0]["payload"]["error_type"] == "RuntimeError"
    assert "sk-live-secret-token" not in json.dumps(failure_events[0]["payload"])


def test_guard_cloud_event_queue_is_bounded_and_overflow_log_is_redacted(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", guard_event_queue_limit=3)

    for index in range(4):
        event = build_runtime_session_event(
            session_id=f"session-{index}",
            occurred_at=f"2026-04-24T00:00:0{index}+00:00",
            payload={"sessionSecret": "sk-live-secret-token", "index": index},
            workspace_id="workspace-alpha",
            device_id="device-1",
        )
        store.add_guard_event_v1(event)

    pending = store.list_guard_events_v1(uploaded=False, limit=10)
    overflow_events = store.list_events(limit=5, event_name="cloud_event_queue_overflow")

    assert [item["event_type"] for item in pending] == ["runtime.session", "runtime.session", "runtime.session"]
    assert pending[0]["payload"]["payload"]["index"] == 1
    assert overflow_events[0]["payload"]["dropped_count"] == 1
    assert "sk-live-secret-token" not in json.dumps(overflow_events[0]["payload"])


def test_sync_guard_events_records_failed_backoff_without_dropping_pending_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
    )
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


def test_guard_cloud_event_queue_handles_large_overflow_without_sqlite_parameter_limit(tmp_path: Path) -> None:
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

    pending = store.list_guard_events_v1(uploaded=False, limit=10)
    overflow_events = store.list_events(limit=5, event_name="cloud_event_queue_overflow")

    assert [item["payload"]["payload"]["index"] for item in pending] == [1004, 1005]
    assert overflow_events[0]["payload"]["dropped_count"] == 1004


def test_sync_guard_events_drains_all_pending_events_when_v1_endpoint_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", guard_event_queue_limit=400)
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
    )
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
    assert result["skipped"] == 250
    assert store.count_guard_events_v1(uploaded=False) == 0
    assert store.count_guard_events_v1(uploaded=True) == 250


def test_sync_guard_events_preserves_unavailable_summary_when_no_events_pending(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
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

    result = guard_runner_module.sync_guard_events(store)
    stored = store.get_sync_payload("guard_events_v1_summary")

    assert result["sync_reason"] == "guard_events_endpoint_unavailable"
    assert result["sync_skipped"] is True
    assert stored == result


def test_runtime_snapshot_treats_naive_sync_timestamps_as_utc(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
    )
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
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
    )
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


def test_runtime_snapshot_exposes_latest_connect_proof_without_pairing_secrets(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    connect_request = store.create_guard_connect_request(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now="2026-04-24T00:00:00+00:00",
    )
    request_id = str(connect_request["request_id"])
    store.complete_guard_connect_request(
        request_id=request_id,
        pairing_secret=str(connect_request["pairing_secret"]),
        token="secret-browser-session-token",
        now="2026-04-24T00:01:00+00:00",
    )
    store.record_guard_connect_result(
        request_id=request_id,
        status="connected",
        milestone="first_sync_succeeded",
        now="2026-04-24T00:02:00+00:00",
        sync_payload={
            "synced_at": "2026-04-24T00:02:00+00:00",
            "receipts_stored": 3,
            "inventory_tracked": 5,
            "runtime_session_id": "runtime-session-1",
            "runtime_session_synced_at": "2026-04-24T00:01:30+00:00",
        },
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
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
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
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
    )
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
            "harness": "codex",
            "surface": "cli",
            "status": "active",
            "updatedAt": "2026-04-24T00:01:00+00:00",
            "workspace": str(workspace_dir),
        },
    )

    session_payload = captured_body["session"]
    assert isinstance(session_payload, dict)
    assert session_payload["deviceId"] == store.get_or_create_installation_id()
    assert session_payload["deviceName"] == store.get_device_metadata()["device_label"]
    assert session_payload["localIdentity"]["daemonId"] == store.get_or_create_installation_id()
    assert session_payload["localIdentity"]["daemonVersion"] == guard_runner_module.__version__
    assert session_payload["localIdentity"]["daemonStatus"] == "healthy"
    assert session_payload["localIdentity"]["relayState"] == "online"
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


def test_sync_runtime_session_prefers_ipv6_private_identity_when_ipv4_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-ipv6",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
    )
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
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-no-coverage",
        "2026-04-24T00:00:00+00:00",
        workspace_id="workspace-alpha",
    )
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
    assert session_payload["localIdentity"]["daemonId"] == store.get_or_create_installation_id()
    assert session_payload["localIdentitySource"]["daemonId"] == "local-guard"
