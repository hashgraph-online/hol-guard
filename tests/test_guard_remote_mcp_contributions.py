"""Remote HTTP MCP contributions stay opt-in and can only strengthen policy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_resolution import (
    _copilot_runtime_server_identity,
    _CopilotMcpRuntimeServer,
)
from codex_plugin_scanner.guard.mcp_tool_calls import (
    ToolCallDecision,
    _apply_temporary_mcp_grant,
    build_tool_call_artifact,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.mcp_protection import (
    build_mcp_server_identity,
    mcp_server_identity_metadata,
)
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    load_mcp_contribution_payloads,
    normalized_remote_mcp_url,
    validate_mcp_contribution,
)
from codex_plugin_scanner.guard.runtime.mcp_server_grants import (
    _matches_remote_http_contribution,
    apply_contributed_mcp_decision,
    matching_mcp_contribution,
)


def _layer(extension_id: str) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, extension_id),
                state=ControlState.ENABLED,
            ),
        ),
    )


class _AuthorityStore:
    def read_extension_control_authority_for_registry(self, registry: object) -> ExtensionControlAuthorityView:
        digest = getattr(registry, "catalog_digest", "0" * 64)
        assert isinstance(digest, str)
        return ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=1,
            catalog_digest=digest,
            layers=(_layer("command.mcp-instapods"),),
        )


def _remote_artifact(tool_name: str, *, server_name: str = "instapods", transport: str = "http"):
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="https://app.instapods.com/api/mcp",
        args=(),
        transport=transport,
    )
    return build_tool_call_artifact(
        harness="codex",
        server_name=server_name,
        tool_name=tool_name,
        source_scope="project",
        config_path=".mcp.json",
        transport=transport,
        server_identity=identity,
    )


def _remote_payload(url: str, *, state: str = "review") -> dict[str, object]:
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
        "tools": [{"name": "write_data", "state": state}],
        "saferAlternatives": ["Keep the tool on normal review."],
    }


def test_remote_instapods_matches_exact_endpoint_even_with_custom_server_name() -> None:
    payload = matching_mcp_contribution(_remote_artifact("delete_pod", server_name="production-pods"))
    assert payload is not None
    assert payload["id"] == "mcp.instapods"


def test_remote_instapods_sse_transport_receives_review_default() -> None:
    artifact = _remote_artifact("change_plan", transport="sse")
    payload = matching_mcp_contribution(artifact)
    assert payload is not None
    assert payload["id"] == "mcp.instapods"
    decision = apply_contributed_mcp_decision(_AuthorityStore(), artifact, "allow")
    assert decision is not None
    assert decision[0] == "review"


def test_remote_instapods_review_default_strengthens_allow() -> None:
    decision = apply_contributed_mcp_decision(_AuthorityStore(), _remote_artifact("change_plan"), "allow")
    assert decision is not None
    assert decision[0] == "review"
    assert decision[1] == "catalog-mcp-extension"


def test_remote_instapods_review_default_strengthens_allow_in_runtime_path() -> None:
    current = ToolCallDecision(
        action="allow",
        source="base-policy",
        signals=(),
        summary="Allowed by base policy.",
    )
    decision = _apply_temporary_mcp_grant(
        store=_AuthorityStore(),
        artifact=_remote_artifact("change_plan"),
        artifact_hash="test-hash",
        arguments={},
        current=current,
    )
    assert decision.action == "review"
    assert decision.source == "catalog-mcp-extension"


def test_remote_instapods_manage_pod_inherits() -> None:
    assert apply_contributed_mcp_decision(_AuthorityStore(), _remote_artifact("manage_pod"), "allow") is None


def test_remote_instapods_does_not_match_wrong_remote_endpoint() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="https://example.com/api/mcp",
        args=(),
        transport="http",
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="instapods",
        tool_name="delete_pod",
        source_scope="project",
        config_path=".mcp.json",
        transport="http",
        server_identity=identity,
    )
    assert matching_mcp_contribution(artifact) is None


def test_remote_http_url_contract_accepts_public_https_endpoint() -> None:
    payload = _remote_payload("https://app.instapods.com/api/mcp")
    validate_mcp_contribution(payload)
    assert normalized_remote_mcp_url("https://app.instapods.com/api/mcp") == "https://app.instapods.com/api/mcp"


def test_remote_http_url_contract_accepts_explicit_standard_https_port() -> None:
    payload = _remote_payload("https://app.instapods.com:443/api/mcp")
    validate_mcp_contribution(payload)
    assert normalized_remote_mcp_url("https://app.instapods.com:443/api/mcp") == "https://app.instapods.com/api/mcp"


@pytest.mark.parametrize(
    "url",
    (
        "https://user:pass@example.com/api/mcp",
        "https://example.com:8443/api/mcp",
    ),
)
def test_remote_http_url_contract_rejects_unsafe_authority(url: str) -> None:
    with pytest.raises(ValueError, match=r"schema|public HTTPS endpoint"):
        validate_mcp_contribution(_remote_payload(url))
    assert normalized_remote_mcp_url(url) is None


@pytest.mark.parametrize(
    "url",
    (
        "https://localhost/mcp",
        "https://127.0.0.1/mcp",
        "https://127.1/mcp",
        "https://10.0.0.1/mcp",
        "https://10.1/mcp",
        "https://[::1]/mcp",
    ),
)
def test_remote_http_url_contract_rejects_non_public_hosts(url: str) -> None:
    with pytest.raises(ValueError, match=r"schema|public HTTPS endpoint"):
        validate_mcp_contribution(_remote_payload(url))
    assert normalized_remote_mcp_url(url) is None


@pytest.mark.parametrize(
    "url",
    (
        "https://invalid host.example/mcp",
        "https://bad_host.example/mcp",
        "https://-bad.example/mcp",
        "https://bad-.example/mcp",
        "https://bad..example/mcp",
        f"https://{'a' * 64}.example/mcp",
        "https://" + ".".join(("a" * 63,) * 4) + "/mcp",
    ),
)
def test_remote_http_url_contract_rejects_malformed_dns_hosts(url: str) -> None:
    with pytest.raises(ValueError, match=r"schema|public HTTPS endpoint"):
        validate_mcp_contribution(_remote_payload(url))
    assert normalized_remote_mcp_url(url) is None


def test_remote_http_url_contract_canonicalizes_public_ipv6() -> None:
    compressed = "https://[2606:4700:4700::1111]/mcp"
    expanded = "https://[2606:4700:4700:0:0:0:0:1111]/mcp"
    validate_mcp_contribution(_remote_payload(compressed))
    validate_mcp_contribution(_remote_payload(expanded))
    assert normalized_remote_mcp_url(compressed) == compressed
    assert normalized_remote_mcp_url(expanded) == compressed


def test_remote_http_runtime_matches_equivalent_ipv6_spellings() -> None:
    compressed = "https://[2606:4700:4700::1111]/mcp"
    expanded = "https://[2606:4700:4700:0:0:0:0:1111]/mcp"
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command=expanded,
        args=(),
        transport="http",
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="ipv6-service",
        tool_name="write_data",
        source_scope="project",
        config_path=".mcp.json",
        transport="http",
        server_identity=identity,
    )
    launch = {"kind": "remote-http", "url": compressed, "serverNames": ["ipv6-service"]}
    assert _matches_remote_http_contribution(artifact, launch)


def test_remote_http_contributions_reject_equivalent_ipv6_endpoints(tmp_path: Path) -> None:
    compressed = _remote_payload("https://[2606:4700:4700::1111]/mcp")
    compressed["id"] = "mcp.ipv6-compressed"
    compressed_launch = compressed["launch"]
    assert isinstance(compressed_launch, dict)
    compressed_launch["serverNames"] = ["ipv6-compressed"]
    expanded = _remote_payload("https://[2606:4700:4700:0:0:0:0:1111]/mcp")
    expanded["id"] = "mcp.ipv6-expanded"
    expanded_launch = expanded["launch"]
    assert isinstance(expanded_launch, dict)
    expanded_launch["serverNames"] = ["ipv6-expanded"]
    (tmp_path / "mcp.ipv6-compressed.json").write_text(json.dumps(compressed), encoding="utf-8")
    (tmp_path / "mcp.ipv6-expanded.json").write_text(json.dumps(expanded), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate MCP remote endpoint"):
        load_mcp_contribution_payloads(tmp_path)


def test_copilot_remote_identity_matches_with_headers_and_standard_port(tmp_path: Path) -> None:
    server = _CopilotMcpRuntimeServer(
        server_name="instapods",
        source_scope="project",
        config_path=str(tmp_path / ".mcp.json"),
        server_config={
            "url": "https://app.instapods.com:443/api/mcp",
            "headers": {"Authorization": "Bearer runtime-secret"},
        },
    )
    identity, fingerprint, transport = _copilot_runtime_server_identity(server, launch_cwd=tmp_path)
    assert identity.command == "https://app.instapods.com/api/mcp"
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
    payload = matching_mcp_contribution(artifact)
    assert payload is not None
    assert payload["id"] == "mcp.instapods"


def test_copilot_remote_identity_redacts_query_credentials_and_still_matches(tmp_path: Path) -> None:
    secret = "runtime-secret"
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


def test_invalid_remote_endpoint_does_not_fall_back_to_server_name(tmp_path: Path) -> None:
    server = _CopilotMcpRuntimeServer(
        server_name="instapods",
        source_scope="project",
        config_path=str(tmp_path / ".mcp.json"),
        server_config={"url": "http://app.instapods.com/api/mcp"},
    )
    identity, fingerprint, transport = _copilot_runtime_server_identity(server, launch_cwd=tmp_path)
    assert identity.command == "<unresolved>"
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
    assert matching_mcp_contribution(artifact) is None


def test_remote_http_contributions_reject_query_identity_collisions(tmp_path: Path) -> None:
    alpha = _remote_payload("https://example.test/mcp?tenant=alpha")
    alpha["id"] = "mcp.query-alpha"
    alpha_launch = alpha["launch"]
    assert isinstance(alpha_launch, dict)
    alpha_launch["serverNames"] = ["query-alpha"]
    beta = _remote_payload("https://example.test/mcp?tenant=beta")
    beta["id"] = "mcp.query-beta"
    beta_launch = beta["launch"]
    assert isinstance(beta_launch, dict)
    beta_launch["serverNames"] = ["query-beta"]
    (tmp_path / "mcp.query-alpha.json").write_text(json.dumps(alpha), encoding="utf-8")
    (tmp_path / "mcp.query-beta.json").write_text(json.dumps(beta), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate MCP remote endpoint"):
        load_mcp_contribution_payloads(tmp_path)


def test_remote_http_contribution_rejects_allow_default() -> None:
    try:
        validate_mcp_contribution(_remote_payload("https://example.test/mcp", state="allow"))
    except ValueError as error:
        assert "cannot declare allow defaults" in str(error)
    else:
        raise AssertionError("remote HTTP contribution accepted an allow default")
