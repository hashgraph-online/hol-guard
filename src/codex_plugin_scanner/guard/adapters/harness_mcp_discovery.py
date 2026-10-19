"""Read configured MCP servers, stdio and remote, from detected harnesses."""

from __future__ import annotations

import logging
import os
import shlex
import sqlite3
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import HarnessDetection
from ..runtime.local_cli_identity import UnlistedCliIdentity
from ..runtime.local_mcp_probe import mcp_launch_tokens
from ..runtime.mcp_connection_identity import McpConnectionIdentity, build_mcp_connection_identity
from ..runtime.mcp_protection import McpServerIdentity, build_mcp_server_identity
from .contracts import display_name_for
from .harness_mcp_remote import (
    MAX_DISCOVERED_MCP_SERVERS,
    DiscoveredRemoteMcpServer,
    _remote_servers,
    remote_scan_harnesses,
)
from .mcp_servers import ManagedMcpServer, observable_stdio_servers_with_proxy, proxy_process_env
from .remote_mcp_origin import remote_mcp_origin as remote_mcp_origin

if TYPE_CHECKING:
    from .base import HarnessContext

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DiscoveredHarnessMcpServer:
    """One stdio MCP server found in a harness config."""

    identity: UnlistedCliIdentity
    server_identity: McpServerIdentity
    source_label: str
    launch_command: str
    env: tuple[tuple[str, str], ...] = ()
    connection_identity: McpConnectionIdentity | None = None
    harness: str = ""


def discover_harness_mcp_servers(
    *,
    home_dir: Path,
    guard_home: Path,
    workspace_dir: Path | None = None,
    detections: Sequence[HarnessDetection] | None = None,
) -> tuple[DiscoveredHarnessMcpServer, ...]:
    """Return unique stdio MCP servers from harness configs. Does not probe."""

    loaded = detections if detections is not None else _safe_detections(home_dir, guard_home, workspace_dir)
    return _stdio_servers(loaded)


def discover_remote_mcp_servers(
    *,
    home_dir: Path,
    guard_home: Path,
    workspace_dir: Path | None = None,
    detections: Sequence[HarnessDetection] | None = None,
) -> tuple[DiscoveredRemoteMcpServer, ...]:
    """Return unique remote MCP servers from harness configs. Never connects."""

    loaded = detections if detections is not None else _safe_detections(home_dir, guard_home, workspace_dir)
    return _remote_servers(loaded)


def configured_mcp_server_names(loaded: Sequence[HarnessDetection]) -> dict[str, tuple[str, ...]]:
    """Map each harness to the MCP server names its configs declare, stdio or remote."""

    names: dict[str, dict[str, None]] = {}
    for detection in loaded:
        for artifact in detection.artifacts:
            if artifact.artifact_type == "mcp_server" and artifact.name.strip():
                names.setdefault(artifact.harness, {})[artifact.name.strip()] = None
    return {harness: tuple(found) for harness, found in names.items()}


def configured_harness_detections(
    home_dir: Path, guard_home: Path, workspace_dir: Path | None = None
) -> list[HarnessDetection]:
    """One detection pass that both ``discover_*`` functions can share."""

    return _safe_detections(home_dir, guard_home, workspace_dir)


def _stdio_servers(loaded: Sequence[HarnessDetection]) -> tuple[DiscoveredHarnessMcpServer, ...]:
    groups: dict[str, _DiscoveryGroup] = {}
    for detection in loaded:
        for server in observable_stdio_servers_with_proxy(detection):
            built = _identity_for(server)
            if built is None:
                continue
            identity, server_identity, connection_identity = built
            key = identity.identity_hash
            label = display_name_for(server.harness)
            current = groups.get(key)
            launch_command = _raw_launch_label(server.command, server.args)
            env = tuple(sorted(proxy_process_env(server.env).items()))
            if current is None:
                groups[key] = _DiscoveryGroup(
                    identity=identity,
                    server_identity=server_identity,
                    launch_command=launch_command,
                    labels=[label],
                    env=env,
                    connection_identity=connection_identity,
                    harness=server.harness,
                )
                continue
            if label not in current.labels:
                current.labels.append(label)
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
            env=group.env,
            connection_identity=group.connection_identity,
            harness=group.harness,
        )
        for group in ranked[:MAX_DISCOVERED_MCP_SERVERS]
    )


def persist_discovered_harness_mcp_servers(
    store: object,
    servers: Sequence[DiscoveredHarnessMcpServer],
    *,
    seen_at: str,
    remote: Sequence[DiscoveredRemoteMcpServer] = (),
    remote_harnesses: Sequence[str] | None = None,
) -> dict[str, str]:
    """Persist observations and return cli_id to source_label.

    ``remote_harnesses`` names the harnesses whose configs ``remote`` fully
    covers; their remote declarations missing from ``remote`` are forgotten.
    """

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
            connection_identity_hash=server.connection_identity.identity_hash
            if server.connection_identity is not None
            else None,
            declared_source=f"{server.harness}:stdio" if server.harness else None,
        )
        if isinstance(cli_id, str) and cli_id:
            labels[cli_id] = server.source_label
    remote_ids: list[str] = []
    for declared in remote:
        server_identity = declared.tool.server_identity
        cli_id = ensure(
            declared.tool.identity,
            seen_at=seen_at,
            server_identity_hash=server_identity.identity_hash,
            server_command=server_identity.command,
            server_args_hash=server_identity.args_hash,
            source_label=declared.source_label,
            remote_origin=declared.origin,
            declared_source=f"{declared.tool.harness}:remote",
        )
        if isinstance(cli_id, str) and cli_id:
            labels[cli_id] = declared.source_label
            remote_ids.append(cli_id)
    reconcile = getattr(store, "reconcile_remote_mcp_declarations", None)
    if remote_harnesses is not None and callable(reconcile) and len(remote_ids) == len(remote):
        try:
            reconcile(harnesses=remote_harnesses, declared_cli_ids=remote_ids)
        except (OSError, RuntimeError, TypeError, ValueError, KeyError, sqlite3.Error) as error:
            # The cleanup is display-only; the observations above still stand.
            logger.debug("remote MCP declaration reconcile skipped: %s", type(error).__name__)
    return labels


def observe_configured_mcp_servers(store: object, *, context: HarnessContext, seen_at: str, stdio: bool = True) -> int:
    """Record every configured MCP server so Protect lists it before first use.

    Best effort: setup commands must not fail because a harness config is
    unreadable. Returns the number of connectors recorded. With ``stdio=False``
    only remote servers are recorded: a stdio observation may carry a legacy
    denial into a new grant, which a read-only caller must not do.
    """

    try:
        detections = _safe_detections(context.home_dir, context.guard_home, context.workspace_dir)
        remote = _remote_servers(detections)
        labels = persist_discovered_harness_mcp_servers(
            store,
            _stdio_servers(detections) if stdio else (),
            seen_at=seen_at,
            remote=remote,
            remote_harnesses=remote_scan_harnesses(detections, remote),
        )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError, UnicodeError, sqlite3.Error) as exc:
        logger.debug("configured MCP servers not recorded after %s", type(exc).__name__)
        return 0
    return len(labels)


def discovered_server_for_observation(
    servers: Sequence[DiscoveredHarnessMcpServer],
    *,
    cli_id: str | None = None,
    server_command: str | None = None,
    args_hash: str | None = None,
    server_identity_hash: str | None = None,
    source_label: str | None = None,
) -> DiscoveredHarnessMcpServer | None:
    """Return the live discovered server for a stored observation. Does not persist."""

    if cli_id:
        matches = [
            server
            for server in servers
            if server.identity.cli_id == cli_id
            and (not server_identity_hash or server.server_identity.identity_hash == server_identity_hash)
        ]
        if (
            not matches
            and server_identity_hash
            and server_command
            and args_hash
            and source_label
            and cli_id == f"local-cli.mcp-{server_identity_hash[:8]}"
        ):
            matches = [
                server
                for server in servers
                if server.server_identity.identity_hash == server_identity_hash
                and server.server_identity.command == server_command
                and server.server_identity.args_hash == args_hash
                and server.source_label == source_label
            ]
    elif server_identity_hash:
        matches = [server for server in servers if server.server_identity.identity_hash == server_identity_hash]
    else:
        matches = [
            server
            for server in servers
            if server_command
            and args_hash
            and server.server_identity.command == server_command
            and server.server_identity.args_hash == args_hash
        ]
    return matches[0] if len(matches) == 1 else None


def extra_env_for_mcp_launch(
    servers: Sequence[DiscoveredHarnessMcpServer],
    *,
    command: str,
    cli_id: str | None = None,
) -> dict[str, str]:
    """Return harness-configured env for a listing probe. Values stay in memory."""

    matched = discovered_server_for_observation(servers, cli_id=cli_id)
    if matched is None and not cli_id:
        tokens = mcp_launch_tokens(command, cwd=Path.home(), home_dir=Path.home())
        if tokens is not None:
            identity = build_mcp_server_identity(
                config_path="",
                command=tokens[0],
                args=tuple(tokens[1:]),
                transport="stdio",
            )
            matched = discovered_server_for_observation(
                servers,
                server_command=identity.command,
                args_hash=identity.args_hash,
            )
    if matched is None:
        return {}
    extra = dict(matched.env)
    for key in matched.server_identity.env_keys:
        current = extra.get(key)
        if key in os.environ and (current is None or _looks_unresolved(current)):
            extra[key] = os.environ[key]
    return extra


def _looks_unresolved(value: str) -> bool:
    stripped = value.strip()
    return len(stripped) >= 4 and stripped.startswith("${") and stripped.endswith("}")


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
    env: tuple[tuple[str, str], ...]
    connection_identity: McpConnectionIdentity
    harness: str


def _safe_detections(home_dir: Path, guard_home: Path, workspace_dir: Path | None) -> list[HarnessDetection]:
    from . import list_adapters
    from .base import HarnessContext

    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)
    detections: list[HarnessDetection] = []
    for adapter in list_adapters():
        contexts = (context,)
        if adapter.harness == "codex" and workspace_dir is not None:
            # A managed Codex hook manifest binds the installation workspace
            # and whether home was explicit. Both contexts still authenticate
            # that manifest before their inventory can be used.
            contexts = (
                replace(context, home_override_explicit=True, workspace_override_explicit=True),
                replace(context, home_override_explicit=False, workspace_override_explicit=True),
            )
        for adapter_context in contexts:
            try:
                detections.append(adapter.detect(adapter_context))
                break
            except (OSError, RuntimeError, UnicodeError) as exc:
                logger.debug("MCP inventory skipped %s adapter after %s", adapter.harness, type(exc).__name__)
                continue
            except (TypeError, ValueError, KeyError) as exc:
                logger.warning(
                    "MCP inventory skipped %s adapter after invalid data (%s)",
                    adapter.harness,
                    type(exc).__name__,
                )
                continue
    return detections


def _identity_for(
    server: ManagedMcpServer,
) -> tuple[UnlistedCliIdentity, McpServerIdentity, McpConnectionIdentity] | None:
    server_identity = server.identity
    if server_identity is None or not server.command.strip():
        return None
    name = server.name.strip() or server_identity.package_name or Path(server.command).name or "mcp-server"
    connection = build_mcp_connection_identity(
        host=server.harness,
        source_scope=server.source_scope,
        config_path=server.config_path,
        server_name=server.name,
        server_identity_hash=server_identity.identity_hash,
    )
    return (
        UnlistedCliIdentity(
            cli_id=f"local-cli.mcp-{connection.identity_hash}",
            name=name[:120],
            kind="executable",
            identity_hash=connection.identity_hash,
            example_label=_launch_label(server.command, server.args),
        ),
        server_identity,
        connection,
    )


def _join_labels(labels: Sequence[str]) -> str:
    unique = list(dict.fromkeys(label for label in labels if label.strip()))
    if len(unique) <= 3:
        return ", ".join(unique)
    return f"{unique[0]}, {unique[1]}, and {len(unique) - 2} more"


def _launch_label(command: str, args: tuple[str, ...]) -> str:
    return _join_tokens(_redact_launch_tokens((command, *args)))


def _raw_launch_label(command: str, args: tuple[str, ...]) -> str:
    # Only presentation labels may be truncated; discovery must launch exact argv.
    if os.name == "nt":
        return subprocess.list2cmdline([command, *args])
    return shlex.join((command, *args))


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
