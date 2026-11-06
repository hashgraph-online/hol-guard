"""Hosted MCP DNS root-dot normalization remains fail closed."""

from codex_plugin_scanner.guard.runtime.mcp_server_contribution import normalized_remote_mcp_url


def test_remote_mcp_dns_root_dot_normalization() -> None:
    assert normalized_remote_mcp_url("https://app.instapods.com./api/mcp") == "https://app.instapods.com/api/mcp"
    assert normalized_remote_mcp_url("https://app.instapods.com../api/mcp") is None
