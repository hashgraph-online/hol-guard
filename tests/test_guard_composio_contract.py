from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.composio_contract import (
    composio_batch_actions,
    composio_requires_action_review,
    composio_tool_role,
)


def test_hosted_batch_preserves_actions_accounts_and_arguments() -> None:
    parsed = composio_batch_actions({"tools": [
        {"tool_slug": "SLACK_SEARCH_MESSAGES", "account": "work", "arguments": {"query": "test"}},
        {"tool_slug": "SLACK_SEND_MESSAGE", "arguments": {"channel": "test"}},
    ]})
    assert parsed is not None
    assert [action.tool_slug for action in parsed] == ["SLACK_SEARCH_MESSAGES", "SLACK_SEND_MESSAGE"]
    assert parsed[0].account == "work"
    assert parsed[1].account is None  # Missing identity is not guessed from the toolkit.
    assert parsed[0].arguments == {"query": "test"}


@pytest.mark.parametrize("member", [
    None, {}, {"tool_slug": "SLACK_SEND_MESSAGE"},
    {"tool_slug": " SLACK_SEND_MESSAGE", "arguments": {}},
    {"tool_slug": "SLACK_SEND_MESSAGE", "arguments": [], "account": "work"},
    {"tool_slug": "SLACK_SEND_MESSAGE", "arguments": {}, "account": ""},
    {"tool_slug": "SLACK_SEND_MESSAGE", "arguments": {}, "account": 1},
    {"tool_slug": "SLACK_SEND_MESSAGE", "arguments": {}, "unrecognized_scope": "admin"},
])
def test_bad_member_invalidates_entire_batch(member: object) -> None:
    assert composio_batch_actions({"tools": [
        {"tool_slug": "SLACK_SEARCH_MESSAGES", "arguments": {"query": "test"}}, member,
    ]}) is None


@pytest.mark.parametrize("tools", [[], None, {}, [
    {"tool_slug": "SLACK_SEARCH_MESSAGES", "arguments": {}}
] * 51])
def test_batch_limits_are_explicit(tools: object) -> None:
    assert composio_batch_actions({"tools": tools}) is None


def test_discovery_does_not_authorize_execution() -> None:
    assert composio_tool_role("mcp__codex_apps__composio__composio_search_tools") == "discovery"
    assert not composio_requires_action_review("COMPOSIO_SEARCH_TOOLS")
    assert composio_requires_action_review("mcp__codex_apps__composio__composio_multi_execute_tool")
    assert composio_requires_action_review("COMPOSIO_REMOTE_WORKBENCH")
    assert composio_requires_action_review("COMPOSIO_REMOTE_BASH_TOOL")
    assert composio_requires_action_review("COMPOSIO_MANAGE_CONNECTIONS")
    assert composio_tool_role("COMPOSIO_FUTURE_EXECUTOR") == "unknown"
    assert composio_requires_action_review("COMPOSIO_FUTURE_EXECUTOR")
