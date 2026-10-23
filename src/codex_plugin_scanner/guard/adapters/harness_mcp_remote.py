"""Remote MCP servers declared in harness configs. Guard never connects to them."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from ..models import GuardArtifact, HarnessDetection
from ..runtime.observed_mcp_tools import ObservedMcpTool, observed_mcp_tool
from .contracts import display_name_for
from .remote_mcp_origin import remote_mcp_origin

MAX_DISCOVERED_MCP_SERVERS = 100
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


def _remote_servers(loaded: Sequence[HarnessDetection]) -> tuple[DiscoveredRemoteMcpServer, ...]:
    found: dict[str, DiscoveredRemoteMcpServer] = {}
    for detection in loaded:
        for artifact in detection.artifacts:
            server = _remote_server(artifact)
            if server is None or server.tool.identity.identity_hash in found:
                continue
            found[server.tool.identity.identity_hash] = server
    ranked = sorted(found.values(), key=lambda server: (server.source_label.lower(), server.tool.server_name.lower()))
    return tuple(ranked[:MAX_DISCOVERED_MCP_SERVERS])


def _remote_server(artifact: GuardArtifact) -> DiscoveredRemoteMcpServer | None:
    if artifact.artifact_type != "mcp_server" or artifact.command or not artifact.url:
        return None
    origin = remote_mcp_origin(artifact.url)
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
    "remote_mcp_origin",
    "remote_scan_harnesses",
]
