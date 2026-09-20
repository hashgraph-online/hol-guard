"""Guard Cloud local event sync contract tests."""

from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import evaluate_detection
from codex_plugin_scanner.guard.edge_events import build_runtime_session_event
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cloud_local_sync_helpers import _artifact, _detection, _seed_guard_cloud
from tests.support.network import stub_authenticated_urlopen
from tests.support.optional_uploads import prepare_optional_uploads


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
    prepare_optional_uploads(store, monkeypatch)
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

    stub_authenticated_urlopen(monkeypatch, _raise_url_error)

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
    prepare_optional_uploads(store, monkeypatch)
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


def test_sync_guard_events_preserves_unavailable_summary_when_no_events_pending(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    prepare_optional_uploads(store, monkeypatch)
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


def test_sync_guard_events_preserves_pending_events_when_rate_limited(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On HTTP 429, events must remain pending and the summary must report rate-limited state."""
    store = GuardStore(tmp_path / "guard-home", guard_event_queue_limit=400)
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    prepare_optional_uploads(store, monkeypatch)
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
