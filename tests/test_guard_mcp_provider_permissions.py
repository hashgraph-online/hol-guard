import pytest

from codex_plugin_scanner.guard.runtime.mcp_provider_permissions import (
    composio_provider_action_floor,
    provider_action_selector,
    valid_provider_action_selector,
)
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import observed_mcp_tool

_PREFIX = "mcp__codex_apps__composio__"
_SOURCE = observed_mcp_tool("codex", _PREFIX + "composio_search_tools")


def _choices():
    return {provider_action_selector(_SOURCE, "SLACK_SEND_MESSAGE"): "block"}


def test_provider_action_identity_is_distinct_and_does_not_cross_hosts_or_connectors() -> None:
    key = provider_action_selector(_SOURCE, "SLACK_SEND_MESSAGE")
    assert valid_provider_action_selector(key)
    assert "composio:all-accounts:SLACK_SEND_MESSAGE" in key
    assert not valid_provider_action_selector(key.replace("all-accounts", "work"))
    assert not valid_provider_action_selector(key + ":extra")
    for harness, prefix in [("claude", _PREFIX), ("codex", "mcp__codex_apps__github__")]:
        floor = composio_provider_action_floor(_choices(), harness=harness,
                                              tool_name=prefix + "composio_multi_execute_tool", arguments={"tools": [
            {"tool_slug": "SLACK_SEND_MESSAGE", "arguments": {}},
        ]})
        assert floor.action == "review"


def test_denied_member_blocks_the_entire_batch_including_malformed_siblings() -> None:
    for sibling in [{"tool_slug": "SLACK_SEARCH_MESSAGES", "arguments": {}}, {}]:
        floor = composio_provider_action_floor(_choices(), harness="codex",
                                              tool_name=_PREFIX + "composio_multi_execute_tool", arguments={"tools": [
            sibling, {"tool_slug": "SLACK_SEND_MESSAGE", "arguments": {}, "account": "unverified-alias"},
        ]})
        assert floor.action == "block"
        assert floor.reason == "denied-batch-member"


@pytest.mark.parametrize("name", ["composio_remote_workbench", "composio_remote_bash_tool", "composio_future_executor"])
def test_opaque_execution_cannot_bypass_active_inner_denies(name: str) -> None:
    floor = composio_provider_action_floor(_choices(), harness="codex", tool_name=_PREFIX + name, arguments={})
    assert floor.action == "block"
    assert floor.reason == "opaque-execution-with-deny"


def test_unknown_account_and_unseen_action_never_receive_allow() -> None:
    floor = composio_provider_action_floor(
        {}, harness="codex", tool_name=_PREFIX + "composio_multi_execute_tool",
        arguments={"tools": [{"tool_slug": "SLACK_SEARCH_MESSAGES", "arguments": {}}]},
    )
    assert floor.action == "review"
    assert floor.reason == "unresolved-actions"
    assert composio_provider_action_floor(_choices(), harness="codex",
                                         tool_name=_PREFIX + "composio_search_tools", arguments={}) is None
