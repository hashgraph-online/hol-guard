"""Hosted MCP endpoint identities fit the shared receipt contract."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    normalized_remote_mcp_url,
    validate_mcp_contribution,
)


def _remote_payload(url: str) -> dict[str, object]:
    return {
        "schemaVersion": "guard.mcp-server-contribution.v1",
        "id": "mcp.endpoint-length",
        "version": "1.0.0",
        "name": "Endpoint Length",
        "description": "Endpoint length contract fixture",
        "trustClass": "external",
        "activation": "opt-in",
        "publisher": {"id": "example.test", "displayName": "Example"},
        "icon": {"kind": "none"},
        "launch": {
            "kind": "remote-http",
            "url": url,
            "serverNames": ["endpoint-length"],
        },
        "riskClasses": ["remote"],
        "tools": [{"name": "write_data", "state": "review"}],
        "saferAlternatives": ["Keep the tool on normal review."],
    }


def test_remote_http_endpoint_identity_accepts_shared_maximum() -> None:
    prefix = "https://example.test/"
    url = prefix + "a" * (260 - len(prefix))
    assert len(url) == 260
    validate_mcp_contribution(_remote_payload(url))
    assert normalized_remote_mcp_url(url) == url


def test_remote_http_endpoint_identity_rejects_above_shared_maximum() -> None:
    prefix = "https://example.test/"
    url = prefix + "a" * (261 - len(prefix))
    assert len(url) == 261
    with pytest.raises(ValueError, match="schema"):
        validate_mcp_contribution(_remote_payload(url))
    assert normalized_remote_mcp_url(url) is None


def test_remote_http_endpoint_identity_rejects_non_ascii_value() -> None:
    url = "https://example.test/mcp/\U0001f512"
    with pytest.raises(ValueError, match="schema"):
        validate_mcp_contribution(_remote_payload(url))
    assert normalized_remote_mcp_url(url) is None
