from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.runtime.composio_discovery import ComposioActionSchema
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import observed_mcp_tool
from codex_plugin_scanner.guard.store import GuardStore

_FIRST = "2026-09-27T12:00:00Z"
_SECOND = "2026-09-27T12:01:00Z"
_TOOL = "mcp__codex_apps__composio__composio_search_tools"


def _action(slug="SLACK_SEARCH_MESSAGES"):
    return ComposioActionSchema("slack", slug, "Synthetic metadata", {"type": "object"}, True)


def test_provider_metadata_is_a_subset_and_never_grants_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    source = observed_mcp_tool("codex", _TOOL)
    cli_id = store.record_composio_discovery(source, (_action(),), seen_at=_FIRST)
    assert store.read_local_cli_revision() == 0
    assert store.read_local_cli_grant(cli_id) is None
    item = store.list_local_cli_items()[0]
    assert "mcp_catalog" not in item
    assert item["provider_catalog"] == {
        "provider": "composio",
        "known_count": 1,
        "full_schema_count": 1,
        "updated_at": _FIRST,
        "coverage": "discovery-subset",
        "account_binding": "unverified",
    }
    action = store.read_local_mcp_provider_actions(cli_id)["actions"][0]
    assert action["permission_state"] == "review"
    assert action["allow_supported"] is False
    assert "input_schema_json" not in action


def test_discovery_subsets_merge_without_removal_and_authority_revision_is_separate(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    source = observed_mcp_tool("codex", _TOOL)
    cli_id = store.record_composio_discovery(source, (_action(),), seen_at=_FIRST)
    store.record_composio_discovery(source, (_action("SLACK_SEND_MESSAGE"),), seen_at=_SECOND)
    assert len(store.read_local_mcp_provider_actions(cli_id)["actions"]) == 2
    store.record_composio_discovery(source, (replace(_action(), description="New display text"),), seen_at=_SECOND)
    assert store.read_local_mcp_provider_actions(cli_id)["actions"][0]["revision"] == 1
    store.record_composio_discovery(
        source,
        (replace(_action(), input_schema={"type": "object", "required": ["query"]}),),
        seen_at=_SECOND,
    )
    assert store.read_local_mcp_provider_actions(cli_id)["actions"][0]["revision"] == 2
    store.record_composio_discovery(source, (replace(_action(), toolkit="other"),), seen_at=_SECOND)
    assert store.read_local_mcp_provider_actions(cli_id, search="SEARCH")["actions"][0]["revision"] == 3
    assert store.read_local_cli_revision() == 0


def test_provider_catalogs_keep_host_boundaries_and_literal_search(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    codex = store.record_composio_discovery(observed_mcp_tool("codex", _TOOL), (_action(),), seen_at=_FIRST)
    claude = store.record_composio_discovery(
        observed_mcp_tool("claude", _TOOL), (_action("SLACK_SEND_MESSAGE"),), seen_at=_FIRST
    )
    assert codex != claude
    result = store.read_local_mcp_provider_actions(codex, search="SEARCH")
    assert result["actions"][0]["tool_slug"] == "SLACK_SEARCH_MESSAGES"
    assert store.read_local_mcp_provider_actions(codex, search="%")["actions"] == []
    assert store.read_local_mcp_provider_actions(codex, search="SEND")["actions"] == []
    assert len(store.list_local_cli_items()) == 2


def test_provider_catalog_pages_are_stable_and_bounded(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    cli_id = store.record_composio_discovery(
        observed_mcp_tool("codex", _TOOL),
        (_action("A"), _action("B"), _action("C")),
        seen_at=_FIRST,
    )
    first = store.read_local_mcp_provider_actions(cli_id, limit=2)
    assert [action["tool_slug"] for action in first["actions"]] == ["A", "B"]
    assert first["next_offset"] == 2
    last = store.read_local_mcp_provider_actions(cli_id, limit=2, offset=first["next_offset"])
    assert [action["tool_slug"] for action in last["actions"]] == ["C"]
    assert last["next_offset"] is None


def test_provider_catalog_capacity_failure_rolls_back_the_whole_update(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    source = observed_mcp_tool("codex", _TOOL)
    cli_id = store.record_composio_discovery(source, (_action(),), seen_at=_FIRST)
    with pytest.raises(ValueError, match="capacity exceeded"):
        store.record_composio_discovery(
            source,
            (
                replace(_action(), description="Changed before failure"),
                replace(_action("OTHER"), description="x" * 2_000_001),
            ),
            seen_at=_SECOND,
        )
    actions = store.read_local_mcp_provider_actions(cli_id)["actions"]
    assert len(actions) == 1
    assert actions[0]["description"] == "Synthetic metadata"
    assert actions[0]["updated_at"] == _FIRST


def test_provider_action_api_reads_cached_metadata_without_mutating_choices(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    cli_id = store.record_composio_discovery(observed_mcp_tool("codex", _TOOL), (_action(),), seen_at=_FIRST)
    service = LocalCliApiService(store=store)
    page = service.provider_actions({"cli_id": cli_id, "search": "SEARCH", "limit": 50})
    assert page["cli_id"] == cli_id
    assert page["actions"][0]["tool_slug"] == "SLACK_SEARCH_MESSAGES"
    assert service.list_items()["items"][0]["provider_catalog"]["account_binding"] == "unverified"
    assert store.read_local_cli_revision() == 0
    for payload in [
        {"cli_id": cli_id, "limit": True},
        {"cli_id": cli_id, "offset": -1},
        {"cli_id": cli_id, "limit": 101},
        {"cli_id": cli_id, "search": "x" * 129},
    ]:
        with pytest.raises(LocalCliApiError) as error:
            service.provider_actions(payload)
        assert error.value.status == 400
