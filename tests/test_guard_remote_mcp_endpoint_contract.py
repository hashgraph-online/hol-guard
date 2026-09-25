"""Focused remote MCP endpoint identity and catalog safety coverage."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.cli.commands_support_runtime_resolution import (
    _copilot_runtime_server_identity,
    _CopilotMcpRuntimeServer,
)
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.runtime.command_permission_catalog import CommandPermissionSpec
from codex_plugin_scanner.guard.runtime.mcp_protection import (
    build_mcp_server_identity,
    mcp_server_identity_metadata,
)
from codex_plugin_scanner.guard.runtime.mcp_server_catalog import _values_for_payload
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    load_mcp_contribution_payloads,
    normalized_remote_mcp_url,
    remote_mcp_endpoint_identity,
)
from codex_plugin_scanner.guard.runtime.mcp_server_grants import (
    _matches_remote_http_contribution,
    matching_mcp_contribution,
)


def _remote_payload(url: str, *, mcp_id: str, server_name: str) -> dict[str, object]:
    return {
        "schemaVersion": "guard.mcp-server-contribution.v1",
        "id": mcp_id,
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
            "serverNames": [server_name],
        },
        "riskClasses": ["remote"],
        "tools": [{"name": "write_data", "state": "review"}],
        "saferAlternatives": ["Keep the tool on normal review."],
    }


def test_remote_url_preserves_trailing_slash_route_identity() -> None:
    without_slash = "https://example.test/mcp"
    with_slash = "https://example.test/mcp/"

    assert normalized_remote_mcp_url(without_slash) == without_slash
    assert normalized_remote_mcp_url(with_slash) == with_slash
    assert remote_mcp_endpoint_identity(without_slash) == without_slash
    assert remote_mcp_endpoint_identity(with_slash) == with_slash


def test_remote_path_dot_segments_have_one_endpoint_identity() -> None:
    expected = "https://example.test/api/mcp"
    variants = (
        "https://example.test/api/./mcp",
        "https://example.test/api/%2e/mcp",
        "https://example.test/api/route/../mcp",
        "https://example.test/api/route/%2E%2E/mcp",
    )

    for variant in variants:
        assert normalized_remote_mcp_url(variant) == expected
        assert remote_mcp_endpoint_identity(variant) == expected


def test_remote_runtime_matches_equivalent_dot_segment_route() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="https://example.test/api/route/../mcp",
        args=(),
        transport="http",
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="example",
        tool_name="write_data",
        source_scope="project",
        config_path=".mcp.json",
        transport="http",
        server_identity=identity,
    )
    launch = {
        "kind": "remote-http",
        "url": "https://example.test/api/mcp",
        "serverNames": ["example"],
    }

    assert _matches_remote_http_contribution(artifact, launch)


def test_remote_path_percent_escapes_have_one_endpoint_identity() -> None:
    lower = "https://example.test/api/%7euser/a%2fb"
    upper = "https://example.test/api/~user/a%2Fb"
    expected = "https://example.test/api/~user/a%2Fb"

    assert normalized_remote_mcp_url(lower) == expected
    assert normalized_remote_mcp_url(upper) == expected
    assert remote_mcp_endpoint_identity(lower) == expected
    assert remote_mcp_endpoint_identity(upper) == expected


def test_remote_route_variants_are_distinct_contribution_endpoints(tmp_path: Path) -> None:
    plain = _remote_payload(
        "https://example.test/mcp",
        mcp_id="mcp.route-plain",
        server_name="route-plain",
    )
    slash = _remote_payload(
        "https://example.test/mcp/",
        mcp_id="mcp.route-slash",
        server_name="route-slash",
    )
    (tmp_path / "mcp.route-plain.json").write_text(json.dumps(plain), encoding="utf-8")
    (tmp_path / "mcp.route-slash.json").write_text(json.dumps(slash), encoding="utf-8")

    payloads = load_mcp_contribution_payloads(tmp_path)
    assert {payload["id"] for payload in payloads} == {"mcp.route-plain", "mcp.route-slash"}


def test_equivalent_percent_encoded_routes_are_duplicate_endpoints(tmp_path: Path) -> None:
    lower = _remote_payload(
        "https://example.test/api/%7euser/a%2fb",
        mcp_id="mcp.route-lower",
        server_name="route-lower",
    )
    upper = _remote_payload(
        "https://example.test/api/~user/a%2Fb",
        mcp_id="mcp.route-upper",
        server_name="route-upper",
    )
    (tmp_path / "mcp.route-lower.json").write_text(json.dumps(lower), encoding="utf-8")
    (tmp_path / "mcp.route-upper.json").write_text(json.dumps(upper), encoding="utf-8")

    try:
        load_mcp_contribution_payloads(tmp_path)
    except ValueError as error:
        assert "duplicate MCP remote endpoint" in str(error)
    else:
        raise AssertionError("equivalent percent-encoded MCP routes were accepted as distinct endpoints")


def test_remote_runtime_does_not_cross_match_trailing_slash_routes() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="https://example.test/mcp/",
        args=(),
        transport="http",
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="example",
        tool_name="write_data",
        source_scope="project",
        config_path=".mcp.json",
        transport="http",
        server_identity=identity,
    )

    without_slash = {"kind": "remote-http", "url": "https://example.test/mcp", "serverNames": ["example"]}
    with_slash = {"kind": "remote-http", "url": "https://example.test/mcp/", "serverNames": ["example"]}

    assert not _matches_remote_http_contribution(artifact, without_slash)
    assert _matches_remote_http_contribution(artifact, with_slash)


def test_remote_runtime_matches_equivalent_percent_encoded_routes() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="https://example.test/api/%7euser/a%2fb",
        args=(),
        transport="http",
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="example",
        tool_name="write_data",
        source_scope="project",
        config_path=".mcp.json",
        transport="http",
        server_identity=identity,
    )
    launch = {
        "kind": "remote-http",
        "url": "https://example.test/api/~user/a%2Fb",
        "serverNames": ["example"],
    }

    assert _matches_remote_http_contribution(artifact, launch)


def test_copilot_long_query_credentials_keep_hosted_safeguards(tmp_path: Path) -> None:
    secret = "s" * 320
    server = _CopilotMcpRuntimeServer(
        server_name="instapods",
        source_scope="project",
        config_path=str(tmp_path / ".mcp.json"),
        server_config={"url": f"https://app.instapods.com/api/mcp?token={secret}"},
    )

    identity, fingerprint, transport = _copilot_runtime_server_identity(server, launch_cwd=tmp_path)
    serialized_identity = mcp_server_identity_metadata(identity)
    assert serialized_identity["command"] == "https://app.instapods.com/api/mcp"
    assert secret not in str(serialized_identity)
    artifact = build_tool_call_artifact(
        harness="copilot",
        server_name="instapods",
        tool_name="delete_pod",
        source_scope="project",
        config_path=server.config_path,
        transport=transport,
        server_fingerprint=fingerprint,
        server_identity=identity,
    )
    assert secret not in str(artifact.to_dict())
    payload = matching_mcp_contribution(artifact)
    assert payload is not None
    assert payload["id"] == "mcp.instapods"


def test_remote_catalog_example_strips_query_credentials() -> None:
    secret = "".join(("runtime", "-", "secret"))
    payload = _remote_payload(
        f"https://example.test/mcp?token={secret}",
        mcp_id="mcp.catalog-secret",
        server_name="catalog-secret",
    )

    values = _values_for_payload(payload)
    permissions = values["permissions"]
    assert isinstance(permissions, tuple)
    assert len(permissions) == 1
    permission = permissions[0]
    assert isinstance(permission, CommandPermissionSpec)
    assert permission.example_command == "https://example.test/mcp"
    assert secret not in str(permission.to_dict())
