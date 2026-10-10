"""Regression coverage for hosted MCP endpoint validation and Copilot identity."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    normalized_remote_mcp_url,
    validate_mcp_contribution,
)

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401


def _remote_payload(url: str) -> dict[str, object]:
    return {
        "schemaVersion": "guard.mcp-server-contribution.v1",
        "id": "mcp.example-remote",
        "version": "1.0.0",
        "name": "Example Remote MCP",
        "description": "Remote example",
        "trustClass": "external",
        "activation": "opt-in",
        "publisher": {"id": "example.test", "displayName": "Example"},
        "icon": {"kind": "none"},
        "launch": {
            "kind": "remote-http",
            "url": url,
            "serverNames": ["example"],
        },
        "riskClasses": ["remote"],
        "tools": [{"name": "write_data", "state": "review"}],
        "saferAlternatives": ["Keep the tool on normal review."],
    }


@pytest.mark.parametrize(
    "url",
    (
        "https://example.test/mcp\x00tail",
        "https://example.test/mcp?token=ok\x00tail",
        "https://example.test/mcp\\tail",
        "https://example.test/mcp?filter={bad}",
        "https://example.test/mcp%00tail",
    ),
)
def test_remote_http_url_contract_rejects_invalid_uri_characters(url: str) -> None:
    with pytest.raises(ValueError, match=r"schema|public HTTPS endpoint"):
        validate_mcp_contribution(_remote_payload(url))
    assert normalized_remote_mcp_url(url) is None
