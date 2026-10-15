from __future__ import annotations

from codex_plugin_scanner.guard.runtime.composio_contract import (
    composio_requires_action_review,
    composio_tool_role,
)


def test_discovery_does_not_authorize_execution() -> None:
    assert composio_tool_role("mcp__codex_apps__composio__composio_search_tools") == "discovery"
    assert not composio_requires_action_review("COMPOSIO_SEARCH_TOOLS")
    assert composio_requires_action_review("mcp__codex_apps__composio__composio_multi_execute_tool")
    assert composio_requires_action_review("COMPOSIO_REMOTE_WORKBENCH")
    assert composio_requires_action_review("COMPOSIO_REMOTE_BASH_TOOL")
    assert composio_requires_action_review("COMPOSIO_MANAGE_CONNECTIONS")
    assert composio_tool_role("COMPOSIO_FUTURE_EXECUTOR") == "unknown"
    assert composio_requires_action_review("COMPOSIO_FUTURE_EXECUTOR")
