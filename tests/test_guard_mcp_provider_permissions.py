from codex_plugin_scanner.guard.runtime.mcp_provider_permissions import (
    provider_action_selector,
    valid_provider_action_selector,
)
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import observed_mcp_tool

_PREFIX = "mcp__codex_apps__composio__"
_SOURCE = observed_mcp_tool("codex", _PREFIX + "composio_search_tools")


def test_provider_action_identity_is_distinct_and_does_not_cross_hosts_or_connectors() -> None:
    key = provider_action_selector(_SOURCE, "SLACK_SEND_MESSAGE")
    assert valid_provider_action_selector(key)
    assert "composio:all-accounts:SLACK_SEND_MESSAGE" in key
    assert not valid_provider_action_selector(key.replace("all-accounts", "work"))
    assert not valid_provider_action_selector(key + ":extra")
