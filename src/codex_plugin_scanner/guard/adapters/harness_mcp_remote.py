"""Remote MCP servers declared in harness configs. Guard never connects to them.

The native ``harness_mcp_discovery`` kind (``remote`` and ``remote_rank``)
parses each declared server into its recorded origin and tool namespace and
ranks one server per connector; this module only gathers the candidates and
wraps the answer.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..models import GuardArtifact, HarnessDetection
from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from ..runtime.observed_mcp_tools import ObservedMcpTool
from .contracts import display_name_for

MAX_DISCOVERED_MCP_SERVERS = 100
# Servers per native request, far below its count and byte limits, so a config
# that declares thousands of servers is read in several requests, not refused.
_CANDIDATE_BATCH = 256
_SERVER_KEYS = ("origin", "harness", "namespace", "name", "qualified_name", "server_name")


@dataclass(frozen=True, slots=True)
class DiscoveredRemoteMcpServer:
    """One remote MCP server found in a harness config.

    It shares the identity a call to its tools records, so a configured
    server and a used one are the same connector. Guard never connects to it.
    """

    tool: ObservedMcpTool
    origin: str
    source_label: str


def _native(request: dict[str, object], key: str, guard_home: Path | None) -> list[object]:
    answer = native_runner_authority("harness_mcp_discovery", request, guard_home=guard_home).get(key)
    if not isinstance(answer, list):
        raise NativeRunnerAuthorityError("remote MCP servers are malformed")
    return cast(list[object], answer)


def _parsed(artifact: GuardArtifact, item: object) -> DiscoveredRemoteMcpServer | None:
    if item is None:
        return None
    if not isinstance(item, dict):
        raise NativeRunnerAuthorityError("remote MCP servers are malformed")
    fields = cast(dict[str, object], item)
    if set(fields) != set(_SERVER_KEYS) or not all(isinstance(fields[key], str) for key in _SERVER_KEYS):
        raise NativeRunnerAuthorityError("remote MCP servers are malformed")
    value = cast(dict[str, str], fields)
    return DiscoveredRemoteMcpServer(
        tool=ObservedMcpTool(
            harness=value["harness"],
            namespace=value["namespace"],
            name=value["name"],
            qualified_name=value["qualified_name"],
            server_name=value["server_name"],
        ),
        origin=value["origin"],
        source_label=f"{display_name_for(artifact.harness)} · configured server",
    )


def _remote_servers(
    loaded: Sequence[HarnessDetection], guard_home: Path | None = None
) -> tuple[DiscoveredRemoteMcpServer, ...]:
    """The remote servers the configs declare, one per connector, as the native runtime ranks them.

    An unusable answer raises ``NativeRunnerAuthorityError``: a failed read that lists none and forgets nothing.
    """

    candidates = [
        artifact
        for detection in loaded
        for artifact in detection.artifacts
        if artifact.artifact_type == "mcp_server" and not artifact.command and artifact.url
    ]
    servers: list[DiscoveredRemoteMcpServer] = []
    for start in range(0, len(candidates), _CANDIDATE_BATCH):
        batch = candidates[start : start + _CANDIDATE_BATCH]
        request = [
            {"harness": artifact.harness, "name": artifact.name, "url": artifact.url or ""} for artifact in batch
        ]
        answer = _native({"op": "remote", "candidates": request}, "servers", guard_home)
        if len(answer) != len(batch):
            raise NativeRunnerAuthorityError("remote MCP servers are malformed")
        servers.extend(
            server
            for server in (_parsed(artifact, item) for artifact, item in zip(batch, answer, strict=True))
            if server is not None
        )
    if not servers:
        return ()
    ranked = [
        {
            "harness": server.tool.harness,
            "namespace": server.tool.namespace,
            "server_name": server.tool.server_name,
            "source_label": server.source_label,
        }
        for server in servers
    ]
    order = _native({"op": "remote_rank", "servers": ranked, "limit": MAX_DISCOVERED_MCP_SERVERS}, "order", guard_home)
    if (
        len(order) > MAX_DISCOVERED_MCP_SERVERS
        or not all(type(index) is int and 0 <= index < len(servers) for index in order)
        or len(set(cast(list[int], order))) != len(order)
    ):
        raise NativeRunnerAuthorityError("remote MCP servers are malformed")
    return tuple(servers[index] for index in cast(list[int], order))


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
    "remote_scan_harnesses",
]
