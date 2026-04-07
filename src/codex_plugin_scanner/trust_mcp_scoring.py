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
    local_commands_valid = (
        all(
            isinstance(config, dict)
            and isinstance(config.get("command"), str)
            and bool(config.get("command"))
            and (
                "args" not in config
                or (
                    isinstance(config.get("args"), list) and all(isinstance(value, str) for value in config.get("args"))
                )
            )
            for config in local_servers.values()
        )
        if local_servers
        else True
    )
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
