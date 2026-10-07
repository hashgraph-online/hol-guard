from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.runtime.composio_workflows import composio_workflow_proposals
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import observed_mcp_tool
from codex_plugin_scanner.guard.store import GuardStore

_TOOL = "mcp__codex_apps__composio__composio_search_tools"
_FIRST = "2026-09-27T12:00:00Z"


def _result() -> dict[str, object]:
    return {
        "successful": True,
        "error": None,
        "data": {
            "success": True,
            "session": {"id": "PRIVATE_SESSION_NEVER_PERSIST"},
            "results": [
                {
                    "use_case": "Private personal request not retained",
                    "primary_tool_slugs": ["SLACK_SEARCH_MESSAGES", "SLACK_SEND_MESSAGE"],
                    "related_tool_slugs": ["SLACK_FIND_CHANNELS"],
                    "recommended_plan_steps": ["private user text not retained"],
                    "reference_workbench_snippets": ["do not persist code"],
                }
            ],
            "tool_schemas": {
                slug: {
                    "toolkit": "slack",
                    "tool_slug": slug,
                    "description": "Synthetic",
                    "input_schema": {"type": "object"},
                    "hasFullSchema": True,
                }
                for slug in ("SLACK_SEARCH_MESSAGES", "SLACK_SEND_MESSAGE")
            },
        },
    }


def test_optional_guidance_yields_only_action_dependencies():
    from codex_plugin_scanner.guard.runtime.composio_discovery import composio_discovered_actions

    proposals = composio_workflow_proposals(_TOOL, _result())
    assert len(proposals) == 1
    assert proposals[0].primary == ("SLACK_SEARCH_MESSAGES", "SLACK_SEND_MESSAGE")
    assert proposals[0].supporting == ("SLACK_FIND_CHANNELS",)
    assert proposals[0].guidance_present is True
    assert composio_discovered_actions(_TOOL, _result()) is not None
    without = _result()
    without["data"]["results"][0].pop("recommended_plan_steps")
    assert composio_workflow_proposals(_TOOL, without)[0].guidance_present is False
    without["data"].pop("results")
    assert composio_workflow_proposals(_TOOL, without) == ()
    for bad in ("../OTHER", "*"):
        corrupt = _result()
        corrupt["data"]["results"][0]["primary_tool_slugs"] = [bad]
        assert composio_workflow_proposals(_TOOL, corrupt) is None


def test_workflow_persistence_is_identity_bound_and_grant_neutral(tmp_path: Path):
    from codex_plugin_scanner.guard.runtime.composio_discovery import composio_discovered_actions

    store = GuardStore(tmp_path / "guard-home")
    source = observed_mcp_tool("codex", _TOOL)
    proposals = composio_workflow_proposals(_TOOL, _result())
    actions = composio_discovered_actions(_TOOL, _result())
    assert source and proposals and actions
    cli_id = store.record_composio_discovery(source, actions, proposals=proposals, seen_at=_FIRST)
    page = store.read_local_mcp_workflows(cli_id)
    assert page["next_offset"] is None
    proposal = page["proposals"][0]
    assert proposal["source"] == "composio-search-guidance"
    assert proposal["permissions_granted"] is False
    assert proposal["account_binding"] == "unverified"
    assert [entry["state"] for entry in proposal["requirements"]] == ["ask", "ask", "unresolved"]
    assert "PRIVATE_SESSION" not in str(page) and "private user text" not in str(page)
    assert "tool_schemas" not in str(page) and "recommended_plan_steps" not in str(page)
    assert store.read_mcp_provider_choices() == {}
    service = LocalCliApiService(store=store)
    assert service.provider_workflows({"cli_id": cli_id})["proposals"][0]["proposal_id"] == proposal["proposal_id"]
    with pytest.raises(LocalCliApiError) as error:
        service.provider_workflows({"cli_id": cli_id, "offset": True})
    assert error.value.status == 400
    with pytest.raises(ValueError, match="invalid_provider_workflow_page"):
        store.read_local_mcp_workflows(cli_id, offset=-1)
    other = observed_mcp_tool("opencode", "mcp__composio__composio_search_tools")
    assert other is not None
    other_cli = store.record_composio_discovery(other, actions, seen_at=_FIRST)
    assert store.read_local_mcp_workflows(other_cli)["proposals"] == []
    with store._connect() as connection:
        connection.execute("update local_cli_observation set identity_hash = ? where cli_id = ?", ("f" * 64, cli_id))
    assert store.read_local_mcp_workflows(cli_id)["proposals"] == []


def test_journal_recovery_accepts_old_record_and_rejects_corrupt_guidance():
    from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_journal import _McpDiscoveryRecord
    from codex_plugin_scanner.guard.runtime.composio_discovery import composio_discovered_actions

    source = observed_mcp_tool("codex", _TOOL)
    actions = composio_discovered_actions(_TOOL, _result())
    proposals = composio_workflow_proposals(_TOOL, _result())
    assert source and actions and proposals
    record = _McpDiscoveryRecord("a" * 32, "codex", _TOOL, _FIRST, actions, proposals)
    import json

    body = json.loads(record.serialized())
    assert _McpDiscoveryRecord.from_json(body).proposals == proposals
    old = dict(body)
    old.pop("workflow_proposals")
    assert _McpDiscoveryRecord.from_json(old).proposals == ()
    body["workflow_proposals"][0]["primary"] = ["../BAD"]
    assert _McpDiscoveryRecord.from_json(body) is None
