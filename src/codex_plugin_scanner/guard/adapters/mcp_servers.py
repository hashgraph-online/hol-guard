"""Shared managed MCP server helpers for harness adapters."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePath

from ..models import GuardArtifact, HarnessDetection


@dataclass(frozen=True, slots=True)
class ManagedMcpServer:
    """A local stdio MCP server that Guard can wrap at runtime."""

    harness: str
    name: str
    source_scope: str
    config_path: str
    command: str
    args: tuple[str, ...]
    transport: str
    env: dict[str, str]
    enabled: bool


_GUARD_PROXY_COMMANDS = frozenset(
    {
        "codex-mcp-proxy",
        "opencode-mcp-proxy",
        "copilot-mcp-proxy",
        "mcp-proxy",
    }
)


def managed_stdio_servers(detection: HarnessDetection) -> tuple[ManagedMcpServer, ...]:
    """Extract local stdio MCP servers from a harness detection payload."""

    managed: list[ManagedMcpServer] = []
    for artifact in detection.artifacts:
        server = _managed_stdio_server(artifact)
        if server is None:
            continue
        managed.append(server)
    return tuple(managed)


def skipped_stdio_server_names(detection: HarnessDetection) -> tuple[str, ...]:
    """Return server names Guard cannot manage through the runtime proxy."""

    skipped: list[str] = []
    for artifact in detection.artifacts:
        if artifact.artifact_type != "mcp_server" or not artifact.name.strip():
            continue
        if _managed_stdio_server(artifact) is not None:
            continue
        skipped.append(artifact.name)
    return tuple(skipped)


def proxy_cli_args(
    *,
    proxy_command: str,
    guard_home: str,
    server: ManagedMcpServer,
    home: str | None = None,
    workspace: str | None = None,
) -> list[str]:
    """Build common CLI args for a Guard-managed MCP proxy command."""

    args = [
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        proxy_command,
        "--guard-home",
        guard_home,
        "--server-name",
        server.name,
        "--server-id",
        stable_mcp_server_identifier(server),
        "--source-scope",
        server.source_scope,
        "--config-path",
        server.config_path,
        "--transport",
        server.transport,
        "--command",
        server.command,
    ]
    if home is not None:
        args.extend(["--home", home])
    if workspace is not None:
        args.extend(["--workspace", workspace])
    for value in server.args:
        args.append(f"--arg={value}")
    return args


def stable_mcp_server_identifier(server: ManagedMcpServer) -> str:
    """Build a Cloud-stable MCP server ID without local config path material."""

    harness = server.harness.strip().lower()
    source_scope = server.source_scope.strip().lower()
    server_name = _stable_server_name(server.name)
    payload = {
        "harness": harness,
        "source_scope": source_scope,
        "name": server_name,
        "command": _stable_command_name(server.command),
        "args": [_stable_arg_token(value) for value in server.args],
        "transport": server.transport,
    }
    digest = sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:20]
    return f"mcp_server:{harness}:{source_scope}:{server_name}:{digest}"


def _managed_stdio_server(artifact: GuardArtifact) -> ManagedMcpServer | None:
    if artifact.artifact_type != "mcp_server":
        return None
    if artifact.command is None or not artifact.name.strip():
        return None
    if is_guard_proxy_command(artifact.command, artifact.args):
        return None
    transport = artifact.transport or "stdio"
    if transport not in {"stdio", "local"}:
        return None
    env = _string_env(artifact.metadata.get("env"))
    enabled = _bool_metadata(artifact.metadata.get("enabled"), default=True)
    return ManagedMcpServer(
        harness=artifact.harness,
        name=artifact.name,
        source_scope=artifact.source_scope,
        config_path=artifact.config_path,
        command=artifact.command,
        args=artifact.args,
        transport=transport,
        env=env,
        enabled=enabled,
    )


def _stable_arg_token(value: str) -> str:
    key, separator, item = value.partition("=")
    if separator and (_looks_like_path_assignment(key, item) or _looks_like_path_token(item)):
        return f"{key}=<path>"
    if _looks_like_path_token(value):
        return "<path>"
    return value


def _stable_server_name(value: str) -> str:
    return value.strip().lower() or "unnamed"


def _stable_command_name(value: str) -> str:
    return PurePath(value.replace("\\", "/")).name.lower()


def _looks_like_path_assignment(key: str, value: str) -> bool:
    normalized_key = key.strip().lstrip("-/").lower().replace("_", "-")
    path_keys = {
        "cache",
        "config",
        "cwd",
        "dir",
        "directory",
        "file",
        "folder",
        "path",
        "root",
        "workspace",
        "workdir",
    }
    return normalized_key in path_keys and value.strip().replace("\\", "/").startswith("/")


def _looks_like_path_token(value: str) -> bool:
    normalized = value.strip().replace("\\", "/")
    if normalized.startswith(("~/", "./", "../")):
        return True
    if normalized.startswith("/"):
        return "/" in normalized[1:]
    return len(normalized) >= 3 and normalized[0].isalpha() and normalized[1:3] == ":/"


def _string_env(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    env: dict[str, str] = {}
    for key, item in value.items():
        if isinstance(key, str) and isinstance(item, str):
            env[key] = item
    return env


def _bool_metadata(value: object, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    return default


def is_guard_proxy_command(command: str | None, args: tuple[str, ...]) -> bool:
    if not isinstance(command, str):
        return False
    if "codex_plugin_scanner.cli" not in args or "guard" not in args:
        return False
    return any(value in _GUARD_PROXY_COMMANDS for value in args)


__all__ = [
    "ManagedMcpServer",
    "is_guard_proxy_command",
    "managed_stdio_servers",
    "proxy_cli_args",
    "skipped_stdio_server_names",
    "stable_mcp_server_identifier",
]
