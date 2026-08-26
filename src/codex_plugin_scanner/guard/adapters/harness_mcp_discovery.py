"""Read configured stdio MCP servers from detected harnesses."""

from __future__ import annotations

import os
import shlex
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ..models import HarnessDetection
from ..runtime.local_cli_identity import UnlistedCliIdentity
from ..runtime.mcp_protection import McpServerIdentity
from .contracts import display_name_for
from .mcp_servers import ManagedMcpServer, managed_stdio_servers

MAX_DISCOVERED_MCP_SERVERS = 40


@dataclass(frozen=True, slots=True)
class DiscoveredHarnessMcpServer:
    """One stdio MCP server found in a harness config."""

    identity: UnlistedCliIdentity
    server_identity: McpServerIdentity
    source_label: str
    launch_command: str


def discover_harness_mcp_servers(
    *,
    home_dir: Path,
    guard_home: Path,
    workspace_dir: Path | None = None,
    detections: Sequence[HarnessDetection] | None = None,
) -> tuple[DiscoveredHarnessMcpServer, ...]:
    """Return unique stdio MCP servers from harness configs. Does not probe."""

    loaded = detections if detections is not None else _safe_detections(home_dir, guard_home, workspace_dir)
    groups: dict[tuple[str, str], _DiscoveryGroup] = {}
    for detection in loaded:
        for server in managed_stdio_servers(detection):
            built = _identity_for(server)
            if built is None:
                continue
            identity, server_identity = built
            key = (server_identity.command, server_identity.args_hash)
            label = display_name_for(server.harness)
            current = groups.get(key)
            launch_command = _raw_launch_label(server.command, server.args)
            if current is None:
                groups[key] = _DiscoveryGroup(
                    identity=identity,
                    server_identity=server_identity,
                    launch_command=launch_command,
                    labels=[label],
                    env_key_count=len(server_identity.env_keys),
                )
                continue
            if label not in current.labels:
                current.labels.append(label)
            if len(server_identity.env_keys) > current.env_key_count:
                current.identity = identity
                current.server_identity = server_identity
                current.launch_command = launch_command
                current.env_key_count = len(server_identity.env_keys)
    ranked = sorted(
        groups.values(),
        key=lambda group: (
            _join_labels(group.labels).lower(),
            group.identity.name.lower(),
            group.server_identity.command,
            group.server_identity.args_hash,
        ),
    )
    return tuple(
        DiscoveredHarnessMcpServer(
            identity=group.identity,
            server_identity=group.server_identity,
            source_label=_join_labels(group.labels),
            launch_command=group.launch_command,
        )
        for group in ranked[:MAX_DISCOVERED_MCP_SERVERS]
    )


def persist_discovered_harness_mcp_servers(
    store: object,
    servers: Sequence[DiscoveredHarnessMcpServer],
    *,
    seen_at: str,
) -> dict[str, str]:
    """Persist observations and return cli_id to source_label."""

    ensure = getattr(store, "ensure_local_mcp_observation", None)
    if not callable(ensure):
        return {}
    labels: dict[str, str] = {}
    for server in servers:
        cli_id = ensure(
            server.identity,
            seen_at=seen_at,
            server_identity_hash=server.server_identity.identity_hash,
            server_command=server.server_identity.command,
            server_args_hash=server.server_identity.args_hash,
            source_label=server.source_label,
        )
        if isinstance(cli_id, str) and cli_id:
            labels[cli_id] = server.source_label
    return labels


def discovered_server_for_observation(
    servers: Sequence[DiscoveredHarnessMcpServer],
    *,
    cli_id: str | None = None,
    server_command: str | None = None,
    args_hash: str | None = None,
) -> DiscoveredHarnessMcpServer | None:
    """Return the live discovered server for a stored observation. Does not persist."""

    for server in servers:
        if cli_id and server.identity.cli_id == cli_id:
            return server
        if (
            server_command
            and args_hash
            and server.server_identity.command == server_command
            and server.server_identity.args_hash == args_hash
        ):
            return server
    return None


def apply_source_labels(items: list[dict[str, object]], labels: dict[str, str]) -> list[dict[str, object]]:
    """Overlay harness source labels onto listed custom extensions."""

    for item in items:
        cli_id = item.get("cli_id")
        if not isinstance(cli_id, str):
            continue
        label = labels.get(cli_id)
        if label:
            item["source_label"] = label
    return items


@dataclass
class _DiscoveryGroup:
    identity: UnlistedCliIdentity
    server_identity: McpServerIdentity
    launch_command: str
    labels: list[str]
    env_key_count: int


def _safe_detections(home_dir: Path, guard_home: Path, workspace_dir: Path | None) -> list[HarnessDetection]:
    from . import list_adapters
    from .base import HarnessContext

    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)
    detections: list[HarnessDetection] = []
    for adapter in list_adapters():
        try:
            detections.append(adapter.detect(context))
        except (OSError, RuntimeError, TypeError, ValueError, KeyError, UnicodeError):
            continue
    return detections


def _identity_for(server: ManagedMcpServer) -> tuple[UnlistedCliIdentity, McpServerIdentity] | None:
    server_identity = server.identity
    if server_identity is None or not server.command.strip():
        return None
    name = server.name.strip() or server_identity.package_name or Path(server.command).name or "mcp-server"
    return (
        UnlistedCliIdentity(
            cli_id=f"local-cli.mcp-{server_identity.identity_hash[:8]}",
            name=name[:120],
            kind="executable",
            identity_hash=server_identity.identity_hash,
            example_label=_launch_label(server.command, server.args),
        ),
        server_identity,
    )


def _join_labels(labels: Sequence[str]) -> str:
    unique = list(dict.fromkeys(label for label in labels if label.strip()))
    if len(unique) <= 3:
        return ", ".join(unique)
    return f"{unique[0]}, {unique[1]}, and {len(unique) - 2} more"


def _launch_label(command: str, args: tuple[str, ...]) -> str:
    return _join_tokens(_redact_launch_tokens((command, *args)))


def _raw_launch_label(command: str, args: tuple[str, ...]) -> str:
    return _join_tokens((command, *args))


def _join_tokens(tokens: Sequence[str]) -> str:
    values = list(tokens)
    if os.name == "nt":
        return subprocess.list2cmdline(values)[:160]
    return shlex.join(values)[:160]


_SECRET_FLAG_NAMES = frozenset(
    {
        "access-token",
        "api-key",
        "apikey",
        "auth",
        "authorization",
        "bearer",
        "client-secret",
        "password",
        "passwd",
        "secret",
        "token",
    }
)


def _redact_launch_tokens(tokens: Sequence[str]) -> list[str]:
    redacted: list[str] = []
    hide_next = False
    for token in tokens:
        if hide_next:
            redacted.append("*****")
            hide_next = False
            continue
        key, separator, _value = token.partition("=")
        if separator and _is_secret_flag(key):
            redacted.append(f"{key}=*****")
            continue
        if token.startswith("-") and _is_secret_flag(token):
            redacted.append(token)
            hide_next = True
            continue
        redacted.append(_redact_embedded_assignment(token))
    return redacted


def _redact_embedded_assignment(value: str) -> str:
    lower = value.lower()
    if any(token in lower for token in ("apikey=", "api_key=", "api-key=", "token=", "secret=")):
        key, separator, _rest = value.partition("=")
        return f"{key}{separator}*****" if separator else value
    return value


def _is_secret_flag(value: str) -> bool:
    name = value.strip().lstrip("-").lower().replace("_", "-")
    if name in _SECRET_FLAG_NAMES:
        return True
    return name.endswith("-token") or name.endswith("-secret") or name.endswith("-password")
