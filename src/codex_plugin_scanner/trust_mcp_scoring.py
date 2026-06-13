"""HCS-style MCP trust scoring."""

from __future__ import annotations

from pathlib import Path

from .models import CategoryResult
from .trust_helpers import (
    build_adapter_score,
    build_domain_score,
    category_checks,
    check_percent,
    is_https_url,
    load_mcp_payload,
    round_trust_score,
)
from .trust_models import TrustDomainScore
from .trust_specs import MCP_TRUST_SPEC


def build_mcp_domain(plugin_dir: Path, categories: tuple[CategoryResult, ...]) -> TrustDomainScore | None:
    payload_state = load_mcp_payload(plugin_dir)
    if payload_state is None:
        return None

    payload = payload_state.payload
    security_checks = category_checks(categories, "Security")
    remotes = payload.get("remotes")
    servers = payload.get("mcpServers")
    remote_entries = remotes if isinstance(remotes, list) else []
    local_servers = servers if isinstance(servers, dict) else {}
    has_named_surfaces = bool(remote_entries) or bool(local_servers)
    secure_remote_urls = (
        all(isinstance(entry, dict) and is_https_url(str(entry.get("url", ""))) for entry in remote_entries)
        if remote_entries
        else True
    )
    local_commands_valid = True
    if local_servers:
        for config in local_servers.values():
            if not isinstance(config, dict):
                local_commands_valid = False
                break
            args_value = config.get("args")
            args_valid = args_value is None or (
                isinstance(args_value, list) and all(isinstance(value, str) for value in args_value)
            )
            if not (isinstance(config.get("command"), str) and bool(config.get("command")) and args_valid):
                local_commands_valid = False
                break
    config_shape = payload_state.parse_valid and (
        (remotes is None or isinstance(remotes, list)) and (servers is None or isinstance(servers, dict))
    )

    spec_by_id = {adapter.adapter_id: adapter for adapter in MCP_TRUST_SPEC.adapters}
    adapters = (
        build_adapter_score(
            spec_by_id["verification.config-integrity"],
            component_scores={"score": 100.0} if payload_state.parse_valid else None,
            rationales={
                "score": (
                    "The .mcp.json file parsed successfully."
                    if payload_state.parse_valid
                    else "The .mcp.json file did not parse, so config-integrity remains 0."
                )
            },
        ),
        build_adapter_score(
            spec_by_id["verification.execution-safety"],
            component_scores={"score": check_percent(security_checks, "No dangerous MCP commands")},
            rationales={"score": "Execution safety follows the scanner's dangerous-command check."},
        ),
        build_adapter_score(
            spec_by_id["verification.transport-security"],
            component_scores={"score": check_percent(security_checks, "MCP remote transports are hardened")},
            rationales={"score": "Transport security follows the scanner's hardened-remote check."},
        ),
        build_adapter_score(
            spec_by_id["metadata.server-naming"],
            component_scores={"score": 100.0} if has_named_surfaces else None,
            rationales={
                "score": (
                    "At least one MCP surface is explicitly named."
                    if has_named_surfaces
                    else "No local or remote MCP surfaces are declared."
                )
            },
        ),
        build_adapter_score(
            spec_by_id["metadata.command-or-endpoint"],
            component_scores=(
                {"score": 100.0} if has_named_surfaces and secure_remote_urls and local_commands_valid else None
            ),
            rationales={
                "score": (
                    "Every MCP surface declares a concrete command or HTTPS endpoint."
                    if has_named_surfaces and secure_remote_urls and local_commands_valid
                    else "At least one MCP surface is missing a valid command or secure endpoint."
                )
            },
        ),
        build_adapter_score(
            spec_by_id["metadata.config-shape"],
            component_scores={"score": 100.0} if config_shape else None,
            rationales={
                "score": (
                    "The top-level MCP config containers match the expected shape."
                    if config_shape
                    else "The MCP config containers do not match the expected shape."
                )
            },
        ),
    )
    return build_domain_score(domain="mcp", spec=MCP_TRUST_SPEC, adapters=adapters)


def build_mcp_surface_domain(
    *,
    name: str | None,
    command: str | None,
    url: str | None,
    transport: str | None,
) -> TrustDomainScore | None:
    normalized_name = name.strip() if isinstance(name, str) else ""
    normalized_command = command.strip() if isinstance(command, str) else ""
    normalized_url = url.strip() if isinstance(url, str) else ""
    normalized_transport = transport.strip().lower() if isinstance(transport, str) else ""

    has_command = bool(normalized_command)
    has_endpoint = bool(normalized_url)
    has_surface = bool(normalized_name) or has_command or has_endpoint
    if not has_surface:
        return None

    secure_endpoint = is_https_url(normalized_url)
    stdio_like = normalized_transport == "stdio"
    transport_declared = bool(normalized_transport)

    if stdio_like:
        transport_score = 100.0
    elif secure_endpoint:
        transport_score = 85.0
    elif has_endpoint:
        transport_score = 25.0
    else:
        transport_score = 40.0 if transport_declared else 0.0

    if transport_declared and (has_command or has_endpoint):
        config_shape_score = 100.0
    elif has_command or has_endpoint:
        config_shape_score = 60.0
    else:
        config_shape_score = 0.0

    spec_by_id = {adapter.adapter_id: adapter for adapter in MCP_TRUST_SPEC.adapters}
    adapters = (
        build_adapter_score(
            spec_by_id["verification.config-integrity"],
            component_scores=None,
            rationales={
                "score": (
                    "Config-defined MCP fallback does not claim config-integrity without a parseable .mcp.json payload."
                )
            },
        ),
        build_adapter_score(
            spec_by_id["verification.execution-safety"],
            component_scores=None,
            rationales={
                "score": (
                    "Config-defined MCP fallback does not infer execution-safety "
                    "without scanner or payload-backed evidence."
                )
            },
        ),
        build_adapter_score(
            spec_by_id["verification.transport-security"],
            component_scores={"score": round_trust_score(transport_score)} if transport_score > 0 else None,
            rationales={"score": "Transport security was inferred from the MCP transport and endpoint protocol."},
        ),
        build_adapter_score(
            spec_by_id["metadata.server-naming"],
            component_scores={"score": 100.0} if normalized_name else None,
            rationales={
                "score": (
                    "The MCP server definition provides an explicit server name."
                    if normalized_name
                    else "No MCP server name was available from the agent configuration."
                )
            },
        ),
        build_adapter_score(
            spec_by_id["metadata.command-or-endpoint"],
            component_scores={"score": 100.0} if has_command or has_endpoint else None,
            rationales={
                "score": (
                    "The MCP server definition includes a concrete command or endpoint."
                    if has_command or has_endpoint
                    else "The MCP server definition is missing both command and endpoint details."
                )
            },
        ),
        build_adapter_score(
            spec_by_id["metadata.config-shape"],
            component_scores={"score": round_trust_score(config_shape_score)} if config_shape_score > 0 else None,
            rationales={
                "score": (
                    "The MCP server definition has enough structure to infer command, endpoint, and transport shape."
                )
            },
        ),
    )
    return build_domain_score(domain="mcp", spec=MCP_TRUST_SPEC, adapters=adapters)
