"""Read configured MCP servers, stdio and remote, from detected harnesses."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..models import HarnessDetection
from ..native_runner_authority import NativeRunnerAuthorityError
from ..runtime.local_cli_identity import UnlistedCliIdentity
from ..runtime.local_mcp_probe import mcp_launch_tokens
from ..runtime.mcp_connection_identity import McpConnectionIdentity
from ..runtime.mcp_protection import McpServerIdentity, build_mcp_server_identity
from .contracts import display_name_for
from .harness_mcp_remote import (
    MAX_DISCOVERED_MCP_SERVERS,
    DiscoveredRemoteMcpServer,
    _remote_servers,
    remote_scan_harnesses,
)
from .mcp_servers import ManagedMcpServer, observable_stdio_servers_with_proxy, proxy_process_env

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
    return _remote_servers(loaded, guard_home)


def configured_mcp_server_names(loaded: Sequence[HarnessDetection]) -> dict[str, tuple[str, ...]]:
    """Map each harness to the MCP server names its configs declare, stdio or remote."""

    names: dict[str, dict[str, None]] = {}
    for detection in loaded:
        for artifact in detection.artifacts:
            if artifact.artifact_type == "mcp_server" and artifact.name.strip():
                names.setdefault(artifact.harness, {})[artifact.name.strip()] = None
    return {harness: tuple(found) for harness, found in names.items()}


def configured_harness_detections(
    home_dir: Path, guard_home: Path, workspace_dir: Path | None = None, *, skipped: list[str] | None = None
) -> list[HarnessDetection]:
    """One detection pass both ``discover_*`` functions share; unreadable harnesses are named in ``skipped``."""

    return _safe_detections(home_dir, guard_home, workspace_dir, skipped)


_GROUP_KEYS = frozenset(
    {
        "index",
        "cli_id",
        "name",
        "identity_hash",
        "configuration_hash",
        "example_label",
        "launch_command",
        "source_label",
    }
)


def _stdio_servers(loaded: Sequence[HarnessDetection]) -> tuple[DiscoveredHarnessMcpServer, ...]:
    """Group every harness's stdio servers in one native call; labels are redacted there."""

    servers: list[ManagedMcpServer] = []
    entries: list[dict[str, object]] = []
    for detection in loaded:
        # One harness whose entries cannot be read must not hide every other
        # harness's connections. Safe to skip one harness here because stdio
        # persistence only adds observations. The remote list in
        # `harness_mcp_remote` stays all or nothing: `remote_scan_harnesses`
        # promises a full read, and a partial one would make reconciliation
        # forget the entries it could not parse.
        try:
            for server in observable_stdio_servers_with_proxy(detection):
                if server.identity is None:
                    continue
                entry = _group_entry(server, server.identity)
                _ = json.dumps(entry, ensure_ascii=False).encode("utf-8")
                servers.append(server)
                entries.append(entry)
        except (OSError, RuntimeError, TypeError, ValueError, KeyError, UnicodeError, sqlite3.Error) as exc:
            logger.warning(
                "MCP inventory skipped %s servers after invalid data (%s)",
                detection.harness,
                type(exc).__name__,
            )
            continue
    if not entries:
        return ()
    from ..native_runner_authority import native_runner_authority

    request = {"op": "group", "windows": os.name == "nt", "limit": MAX_DISCOVERED_MCP_SERVERS, "servers": entries}
    # A refused answer raises: an explicit scan reports it instead of caching an empty list.
    answer = native_runner_authority("harness_mcp_discovery", request)
    return tuple(_grouped_server(servers[index], item) for index, item in _group_items(answer, len(servers)))


def _group_entry(server: ManagedMcpServer, identity: McpServerIdentity) -> dict[str, object]:
    return {
        "harness": server.harness,
        "label": display_name_for(server.harness),
        "name": server.name,
        "command": server.command,
        "args": list(server.args),
        "source_scope": server.source_scope,
        "config_path": server.config_path,
        "identity_hash": identity.identity_hash,
        "package_name": identity.package_name,
        "server_command": identity.command,
        "args_hash": identity.args_hash,
    }


def _group_items(answer: object, count: int) -> list[tuple[int, dict[str, str]]]:
    servers = _exact(answer, frozenset({"servers"}))["servers"]
    if not isinstance(servers, list) or len(cast(list[object], servers)) > MAX_DISCOVERED_MCP_SERVERS:
        raise ValueError("harness_mcp_discovery group answer is malformed")
    items: list[tuple[int, dict[str, str]]] = []
    seen: set[int] = set()
    for raw in cast(list[object], servers):
        item = _exact(raw, _GROUP_KEYS)
        index = item.pop("index")
        texts = {key: value for key, value in item.items() if isinstance(value, str)}
        if type(index) is not int or not 0 <= index < count or index in seen or len(texts) != len(item):
            raise ValueError("harness_mcp_discovery group item is malformed")
        seen.add(index)
        items.append((index, texts))
    return items


def _exact(value: object, keys: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or frozenset(cast(dict[object, object], value)) != keys:
        raise ValueError("harness_mcp_discovery answer is malformed")
    return cast(dict[str, object], value)


def _grouped_server(server: ManagedMcpServer, item: dict[str, str]) -> DiscoveredHarnessMcpServer:
    server_identity = server.identity
    if server_identity is None:
        raise ValueError("harness_mcp_discovery group index names no identity")
    return DiscoveredHarnessMcpServer(
        identity=UnlistedCliIdentity(
            cli_id=item["cli_id"],
            name=item["name"],
            kind="executable",
            identity_hash=item["identity_hash"],
            example_label=item["example_label"],
        ),
        server_identity=server_identity,
        source_label=item["source_label"],
        launch_command=item["launch_command"],
        env=tuple(sorted(proxy_process_env(server.env).items())),
        connection_identity=McpConnectionIdentity(
            host=server.harness,
            source_scope=server.source_scope,
            configuration_hash=item["configuration_hash"],
            server_identity_hash=server_identity.identity_hash,
            identity_hash=item["identity_hash"],
        ),
        harness=server.harness,
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
        try:
            remote = _remote_servers(detections, context.guard_home)
            remote_harnesses = remote_scan_harnesses(detections, remote)
        except NativeRunnerAuthorityError as exc:
            # Local servers still record; with no remote read nothing is forgotten.
            logger.debug("configured remote MCP servers not read after %s", type(exc).__name__)
            remote, remote_harnesses = (), None
        try:
            stdio_servers = _stdio_servers(detections) if stdio else ()
        except (OSError, RuntimeError, ValueError) as exc:
            # Remote servers still record when the local grouping is refused.
            logger.debug("configured stdio MCP servers not read after %s", type(exc).__name__)
            stdio_servers = ()
        labels = persist_discovered_harness_mcp_servers(
            store,
            stdio_servers,
            seen_at=seen_at,
            remote=remote,
            remote_harnesses=remote_harnesses,
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

    if not servers:
        return None
    from ..native_runner_authority import native_runner_authority

    observed = [
        {
            "cli_id": server.identity.cli_id,
            "identity_hash": server.server_identity.identity_hash,
            "command": server.server_identity.command,
            "args_hash": server.server_identity.args_hash,
            "source_label": server.source_label,
        }
        for server in servers
    ]
    query = {
        "cli_id": cli_id,
        "server_command": server_command,
        "args_hash": args_hash,
        "server_identity_hash": server_identity_hash,
        "source_label": source_label,
    }
    answer: object = native_runner_authority(
        "harness_mcp_discovery", {"op": "match", "servers": observed, "query": query}
    )
    index = _exact(answer, frozenset({"index"}))["index"]
    if index is None:
        return None
    if type(index) is not int or not 0 <= index < len(servers):
        raise ValueError("harness_mcp_discovery match index is malformed")
    return servers[index]


def extra_env_for_mcp_launch(
    servers: Sequence[DiscoveredHarnessMcpServer],
    *,
    command: str,
    cli_id: str | None = None,
) -> dict[str, str]:
    """Return harness-configured env for a listing probe. Values stay in memory."""

    matched = None
    if cli_id:
        matched = discovered_server_for_observation(servers, cli_id=cli_id)
    else:
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


def _safe_detections(
    home_dir: Path, guard_home: Path, workspace_dir: Path | None, skipped: list[str] | None = None
) -> list[HarnessDetection]:
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
            except (TypeError, ValueError, KeyError, sqlite3.Error) as exc:
                logger.warning(
                    "MCP inventory skipped %s adapter after invalid data (%s)",
                    adapter.harness,
                    type(exc).__name__,
                )
                continue
        else:
            if skipped is not None:
                skipped.append(adapter.harness)
    return detections
