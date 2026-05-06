"""Guard Cloud local sync contract tests."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import evaluate_detection
from codex_plugin_scanner.guard.edge_events import build_runtime_session_event
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
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
