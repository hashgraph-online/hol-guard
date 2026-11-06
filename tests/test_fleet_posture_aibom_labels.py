"""AI-tool labels and versions that Guard Cloud's inventory events carry."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.aibom_cloud_contract import cloud_syncable_snapshots, inventory_snapshot_event
from codex_plugin_scanner.guard.harness_tool_version import tool_version_from_artifacts, tool_version_from_detection
from codex_plugin_scanner.guard.inventory_contract import GuardAgentInventorySnapshot, _agent_type


@pytest.mark.parametrize("harness", ["copilot", "cline", "paseo", "devin", "claude-code", "codex"])
def test_harness_keeps_its_own_agent_type(harness: str) -> None:
    assert _agent_type(harness) == harness


def test_unknown_harness_still_falls_back_to_codex() -> None:
    assert _agent_type("not-a-harness") == "codex"


def test_paseo_snapshot_is_synced_under_its_own_type() -> None:
    snapshots = (
        GuardAgentInventorySnapshot("paseo:1", "paseo:agent", "paseo", "2026-10-16T00:00:00Z"),
        GuardAgentInventorySnapshot("cline:1", "cline:agent", "cline", "2026-10-16T00:00:00Z"),
    )
    assert cloud_syncable_snapshots(snapshots) == snapshots
    event = inventory_snapshot_event(
        snapshot=snapshots[0], workspace_id="workspace-1", device_id="device-1", generated_at="2026-10-16T00:00:00Z"
    )
    assert event["payload"]["snapshot"]["agentType"] == "paseo"


def test_tool_version_comes_from_the_host_artifact() -> None:
    artifacts = [
        {"artifact_type": "mcp_server", "metadata": {"version": "9.9.9"}},
        {"artifact_type": "harness_host", "metadata": {"version": "2.1.7"}},
    ]
    assert tool_version_from_artifacts(artifacts) == "2.1.7"
    assert tool_version_from_detection(SimpleNamespace(artifacts=tuple(artifacts))) == "2.1.7"


@pytest.mark.parametrize("version", ["unknown", "", "latest", "x" * 80, None, 3])
def test_non_version_host_text_is_ignored(version: object) -> None:
    artifacts = [{"artifact_type": "harness_host", "metadata": {"version": version}}]
    assert tool_version_from_artifacts(artifacts) is None
