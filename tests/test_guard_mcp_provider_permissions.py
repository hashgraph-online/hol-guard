import re

from codex_plugin_scanner.guard.runtime.mcp_provider_permissions import (
    provider_action_selector,
)
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import observed_mcp_tool

_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def valid_provider_action_selector(selector: str) -> bool:
    parts = selector.split(":")
    if len(parts) != 5 or parts[2:4] != ["composio", "all-accounts"] or not _SLUG.fullmatch(parts[4]):
        return False
    source = observed_mcp_tool(parts[0], parts[1] + "probe")
    return source is not None and source.harness == parts[0] and source.namespace == parts[1]


_PREFIX = "mcp__codex_apps__composio__"
_SOURCE = observed_mcp_tool("codex", _PREFIX + "composio_search_tools")


def test_provider_action_identity_is_distinct_and_does_not_cross_hosts_or_connectors() -> None:
    key = provider_action_selector(_SOURCE, "SLACK_SEND_MESSAGE")
    assert valid_provider_action_selector(key)
    assert "composio:all-accounts:SLACK_SEND_MESSAGE" in key
    assert not valid_provider_action_selector(key.replace("all-accounts", "work"))
    assert not valid_provider_action_selector(key + ":extra")
