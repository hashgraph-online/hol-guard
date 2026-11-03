from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.runtime.composio_discovery import ComposioActionSchema
from codex_plugin_scanner.guard.runtime.composio_workflows import ComposioWorkflowProposal
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import observed_mcp_tool
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_store_shims import record_composio_discovery

_TOOL = "mcp__codex_apps__composio__composio_search_tools"
_FIRST = "2026-09-27T12:00:00Z"
_PRIMARY = ("SLACK_SEARCH_MESSAGES", "SLACK_SEND_MESSAGE")


def _actions() -> tuple[ComposioActionSchema, ...]:
    return tuple(ComposioActionSchema("slack", slug, "Synthetic", {"type": "object"}, True) for slug in _PRIMARY)


def _proposals() -> tuple[ComposioWorkflowProposal, ...]:
    return (ComposioWorkflowProposal(_PRIMARY, ("SLACK_FIND_CHANNELS",), True),)


def test_workflow_persistence_is_identity_bound_and_grant_neutral(tmp_path: Path):
    store = GuardStore(tmp_path / "guard-home")
    source = observed_mcp_tool("codex", _TOOL)
    proposals = _proposals()
    actions = _actions()
    assert source is not None
    cli_id = record_composio_discovery(store, source, actions, proposals=proposals, seen_at=_FIRST)
    page = store.read_local_mcp_workflows(cli_id)
    assert page["next_offset"] is None
    proposal = page["proposals"][0]
    assert proposal["source"] == "composio-search-guidance"
    assert proposal["permissions_granted"] is False
    assert proposal["account_binding"] == "unverified"
    assert [entry["state"] for entry in proposal["requirements"]] == ["ask", "ask", "unresolved"]
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
    other_cli = record_composio_discovery(store, other, actions, seen_at=_FIRST)
    assert store.read_local_mcp_workflows(other_cli)["proposals"] == []
    with store._connect() as connection:
        connection.execute("update local_cli_observation set identity_hash = ? where cli_id = ?", ("f" * 64, cli_id))
    assert store.read_local_mcp_workflows(cli_id)["proposals"] == []
