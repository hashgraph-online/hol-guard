"""Shared managed MCP server helpers for harness adapters."""

from __future__ import annotations

from dataclasses import dataclass

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


def _managed_stdio_server(artifact: GuardArtifact) -> ManagedMcpServer | None:
    if artifact.artifact_type != "mcp_server":
        return None
    if artifact.command is None or not artifact.name.strip():
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


__all__ = [
    "ManagedMcpServer",
    "managed_stdio_servers",
    "proxy_cli_args",
    "skipped_stdio_server_names",
]
