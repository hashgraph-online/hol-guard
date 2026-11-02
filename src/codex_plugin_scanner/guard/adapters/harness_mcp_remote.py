"""Remote MCP servers declared in harness configs. Guard never connects to them."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..models import GuardArtifact, HarnessDetection
from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from ..runtime.observed_mcp_tools import ObservedMcpTool, observed_mcp_tool
from .contracts import display_name_for

MAX_DISCOVERED_MCP_SERVERS = 100
# URLs per native request, far below its count and byte limits, so a config
# that declares thousands of servers is read in several requests, not refused.
_ORIGIN_BATCH = 256
_NAMESPACE_UNSAFE = re.compile(r"[^A-Za-z0-9_-]")


@dataclass(frozen=True, slots=True)
class DiscoveredRemoteMcpServer:
    """One remote MCP server found in a harness config.

    It shares the identity a call to its tools records, so a configured
    server and a used one are the same connector. Guard never connects to it.
    """

    tool: ObservedMcpTool
    origin: str
    source_label: str


def remote_mcp_origins(urls: Sequence[str], *, guard_home: Path | None = None) -> list[str | None]:
    """Each URL's recorded ``scheme://host/path`` origin from the native runtime, or ``None``.

    An unusable answer raises ``NativeRunnerAuthorityError``: a failed read that lists none and forgets nothing.
    """

    origins: list[object] = []
    for start in range(0, len(urls), _ORIGIN_BATCH):
        batch = list(urls[start : start + _ORIGIN_BATCH])
        answer = native_runner_authority("remote_mcp_origins", {"urls": batch}, guard_home=guard_home).get("origins")
        if not isinstance(answer, list) or len(cast(list[object], answer)) != len(batch):
            raise NativeRunnerAuthorityError("remote MCP origins are malformed")
        origins.extend(cast(list[object], answer))
    if not all(value is None or isinstance(value, str) for value in origins):
        raise NativeRunnerAuthorityError("remote MCP origins are malformed")
    return cast(list[str | None], origins)


def _remote_servers(
    loaded: Sequence[HarnessDetection], guard_home: Path | None = None
) -> tuple[DiscoveredRemoteMcpServer, ...]:
    candidates = [
        artifact
        for detection in loaded
        for artifact in detection.artifacts
        if artifact.artifact_type == "mcp_server" and not artifact.command and artifact.url
    ]
    origins = remote_mcp_origins([artifact.url or "" for artifact in candidates], guard_home=guard_home)
    found: dict[str, DiscoveredRemoteMcpServer] = {}
    for artifact, origin in zip(candidates, origins, strict=True):
        server = _remote_server(artifact, origin)
        if server is None or server.tool.identity.identity_hash in found:
            continue
        found[server.tool.identity.identity_hash] = server
    ranked = sorted(found.values(), key=lambda server: (server.source_label.lower(), server.tool.server_name.lower()))
    return tuple(ranked[:MAX_DISCOVERED_MCP_SERVERS])


def _remote_server(artifact: GuardArtifact, origin: str | None) -> DiscoveredRemoteMcpServer | None:
    # Harnesses put the server name in the tool namespace with every
    # character outside [A-Za-z0-9_-] replaced by `_`.
    name = _NAMESPACE_UNSAFE.sub("_", artifact.name.strip())
    if origin is None or not name.strip("_"):
        return None
    # The namespace a call to this server's tools carries on this harness. A
    # name whose calls nest another server under it (`codex_apps`) names no
    # single connector, so it is left to the calls that use it.
    tool = observed_mcp_tool(artifact.harness, f"mcp__{name}__tool")
    nested = observed_mcp_tool(artifact.harness, f"mcp__{name}__server__tool")
    if tool is None or nested is None or nested.namespace != tool.namespace:
        return None
    return DiscoveredRemoteMcpServer(
        tool=tool,
        origin=origin,
        source_label=f"{display_name_for(artifact.harness)} · configured server",
    )


def remote_scan_harnesses(
    detections: Sequence[HarnessDetection], remote: Sequence[DiscoveredRemoteMcpServer]
) -> tuple[str, ...] | None:
    """Harnesses a scan read in full, or ``None`` when the remote list hit its cap."""

    if len(remote) >= MAX_DISCOVERED_MCP_SERVERS:
        return None
    return tuple(sorted({detection.harness for detection in detections}))


__all__ = [
    "MAX_DISCOVERED_MCP_SERVERS",
    "DiscoveredRemoteMcpServer",
    "remote_mcp_origins",
    "remote_scan_harnesses",
]
