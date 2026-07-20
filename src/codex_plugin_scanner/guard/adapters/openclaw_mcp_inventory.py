"""Effective OpenClaw MCP inventory and source precedence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

# OpenClaw's canonical map wins over compatibility maps for duplicate active
# names. Disabled entries are source-local, so they do not mask an enabled
# definition from another supported map.
_MCP_SOURCES = (
    ("mcp.servers", ("mcp", "servers")),
    ("mcp.mcpServers", ("mcp", "mcpServers")),
    ("mcpServers", ("mcpServers",)),
)


@dataclass(frozen=True, slots=True)
class OpenClawMcpDefinition:
    """One MCP server definition and its source provenance."""

    name: str
    config: dict[str, object]
    source_key: str
    source_scope: str
    precedence: int
    enabled: bool
    config_identity_sha256: str
    identity_sha256: str


@dataclass(frozen=True, slots=True)
class OpenClawMcpServer:
    """Effective MCP server plus every shadowed or disabled definition."""

    effective: OpenClawMcpDefinition
    definitions: tuple[OpenClawMcpDefinition, ...]
    conflicting_active_definitions: bool


@dataclass(frozen=True, slots=True)
class OpenClawMcpInventory:
    """Deterministic effective inventory shared by detection and overlays."""

    servers: tuple[OpenClawMcpServer, ...]
    warnings: tuple[dict[str, object], ...]


def effective_mcp_inventory(payload: dict[str, object]) -> OpenClawMcpInventory:
    """Visit all supported maps and apply canonical-first active precedence."""

    definitions_by_name: dict[str, list[OpenClawMcpDefinition]] = {}
    warnings: list[dict[str, object]] = []
    for precedence, (source_scope, path) in enumerate(_MCP_SOURCES):
        raw_map = _path_value(payload, path)
        if raw_map is None:
            continue
        if not isinstance(raw_map, dict):
            warnings.append(
                {
                    "reason": "invalid_mcp_server_map",
                    "source_scope": source_scope,
                }
            )
            continue
        for raw_name, raw_config in raw_map.items():
            if not isinstance(raw_name, str) or not raw_name.strip() or not isinstance(raw_config, dict):
                warnings.append(
                    {
                        "reason": "invalid_mcp_server_definition",
                        "source_scope": source_scope,
                    }
                )
                continue
            name = raw_name.strip()
            config = dict(raw_config)
            enabled = config.get("enabled", True) is not False
            config_identity = _server_identity(name=name, config=config, source_scope=None)
            definition = OpenClawMcpDefinition(
                name=name,
                config=config,
                source_key=f"{source_scope}.{name}",
                source_scope=source_scope,
                precedence=precedence,
                enabled=enabled,
                config_identity_sha256=config_identity,
                identity_sha256=_server_identity(name=name, config=config, source_scope=source_scope),
            )
            definitions_by_name.setdefault(name, []).append(definition)

    servers: list[OpenClawMcpServer] = []
    for name in sorted(definitions_by_name):
        definitions = tuple(sorted(definitions_by_name[name], key=lambda item: item.precedence))
        active = tuple(definition for definition in definitions if definition.enabled)
        if not active:
            continue
        effective = active[0]
        conflict = any(
            definition.config_identity_sha256 != effective.config_identity_sha256 for definition in active[1:]
        )
        if len(active) > 1:
            warnings.append(
                {
                    "reason": "conflicting_mcp_server_definitions" if conflict else "shadowed_mcp_server_definition",
                    "server_name": name,
                    "effective_source": effective.source_scope,
                    "shadowed_sources": [definition.source_scope for definition in active[1:]],
                }
            )
        servers.append(
            OpenClawMcpServer(
                effective=effective,
                definitions=definitions,
                conflicting_active_definitions=conflict,
            )
        )
    return OpenClawMcpInventory(servers=tuple(servers), warnings=tuple(warnings))


def _path_value(payload: dict[str, object], path: tuple[str, ...]) -> object:
    value: object = payload
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _server_identity(*, name: str, config: dict[str, object], source_scope: str | None) -> str:
    command = _optional_string(config.get("command"))
    url = _optional_string(config.get("url"))
    transport = _optional_string(config.get("transport"))
    if transport is None:
        transport = "http" if url is not None else "stdio"
    args = config.get("args")
    normalized_args = (
        [str(item) for item in args if isinstance(item, (str, int, float, bool))] if isinstance(args, list) else []
    )
    env = config.get("env")
    headers = config.get("headers")
    identity = {
        "args": normalized_args,
        "command": command,
        "envKeys": _mapping_keys(env),
        "headerKeys": _mapping_keys(headers),
        "name": name,
        "sourceScope": source_scope,
        "transport": transport.lower(),
        "url": url,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _mapping_keys(value: object) -> list[str]:
    if not isinstance(value, dict):
        return []
    return sorted(str(key) for key in value if isinstance(key, str))


def _optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None
