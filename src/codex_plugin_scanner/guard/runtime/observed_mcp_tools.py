"""Discover MCP connector catalogs from tool names, without executing tools.

An observed namespace is an identity on one harness, not a guessed server
endpoint. Catalog discovery never grants authority or invents a launch command.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING

from ..adapters.contracts import display_name_for
from ..local_cli_errors import LocalCliCatalogLimitError
from ..native_policy_snapshot_codec import _normalized_harness_selector_v3
from ..store_local_cli_retention import LocalCliReplaySkippedError
from .local_cli_commands import MAX_LOCAL_CLI_COMMANDS, LocalCliCommand
from .local_cli_identity import UnlistedCliIdentity
from .mcp_protection import McpServerIdentity, build_mcp_server_identity

if TYPE_CHECKING:
    from ..store import GuardStore

OBSERVED_MCP_PREFIX = "observed-mcp:"
MAX_OBSERVED_MCP_TOOLS = min(128, MAX_LOCAL_CLI_COMMANDS - 1)
_TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,120}\Z")


@dataclass(frozen=True, slots=True)
class ObservedMcpTool:
    harness: str
    namespace: str
    name: str
    qualified_name: str
    server_name: str

    @property
    def command_id(self) -> str:
        # Names that slug to the same text must retain separate permissions.
        return "tool-" + sha256(self.qualified_name.encode()).hexdigest()[:24]

    @property
    def server_identity(self) -> McpServerIdentity:
        return build_mcp_server_identity(
            config_path="",
            command=f"{OBSERVED_MCP_PREFIX}{self.harness}:{self.namespace}",
            args=(),
            transport="observed",
        )

    @property
    def identity(self) -> UnlistedCliIdentity:
        server = self.server_identity
        return UnlistedCliIdentity(
            cli_id=f"local-cli.mcp-{server.identity_hash[:16]}",
            name=self.server_name,
            kind="executable",
            identity_hash=server.identity_hash,
            example_label=self.namespace,
        )


def observed_mcp_tool(harness: object, tool_name: object) -> ObservedMcpTool | None:
    """Parse a fully qualified MCP name; retain the connector boundary."""

    if not isinstance(harness, str) or not isinstance(tool_name, str):
        return None
    harness = harness.strip().lower()
    if not _TOKEN.fullmatch(harness) or not tool_name.startswith("mcp__") or len(tool_name) > 160:
        return None
    canonical_harness = _normalized_harness_selector_v3(harness)
    if canonical_harness is None:
        return None
    harness = canonical_harness
    parts = tool_name[5:].split("__")
    if len(parts) < 2 or any(not _TOKEN.fullmatch(part) for part in parts):
        return None
    server = parts[0]
    split = 1
    if server == "codex_apps" and len(parts) >= 3:
        server = parts[1]
        split = 2
    name = "__".join(parts[split:])
    if len(name) > 120:
        return None
    namespace = "mcp__" + "__".join(parts[:split]) + "__"
    if len(namespace) > 155:
        return None
    return ObservedMcpTool(
        harness=harness,
        namespace=namespace,
        name=name,
        qualified_name=tool_name,
        server_name="Codex Apps" if server == "codex_apps" else server,
    )


def discover_observed_mcp_tools(
    store: GuardStore,
    *,
    seen_at: str,
    configured_servers: Mapping[str, Sequence[str]] | None = None,
) -> int:
    """Backfill connector suggestions. Existing grants and tool states survive.

    ``configured_servers`` maps a harness to the server names it is configured
    with, for harnesses whose tool names do not mark where the server ends.
    """

    # The resident reads the paused requests and receipts, parses each tool
    # label (splitting a flattened Oh My Pi name against the servers its
    # harness is configured with) and groups the tools into bounded connectors.
    # Paused requests count too: resolving a request must not make its
    # connector disappear from the picker.
    configured = {harness: list(names) for harness, names in (configured_servers or {}).items()}
    groups = store.observed_mcp_discovery(configured_servers=configured)
    saturated = 0
    for group in groups:
        tools = [
            ObservedMcpTool(
                harness=group["harness"],
                namespace=group["namespace"],
                name=tool["name"],
                qualified_name=tool["qualified_name"],
                server_name=group["server_name"],
            )
            for tool in group["tools"]
        ]
        if not tools:
            continue
        first = tools[0]
        server = first.server_identity
        # Replay records each connector at its own history time, so it can age
        # out and stays forgotten until the harness uses it again.
        history_seen_at = group["seen_at"] or seen_at
        try:
            cli_id = store.ensure_local_mcp_observation(
                first.identity,
                seen_at=history_seen_at,
                replayed=True,
                replay_now=seen_at,
                server_identity_hash=server.identity_hash,
                server_command=server.command,
                server_args_hash=server.args_hash,
                source_label=f"{display_name_for(first.harness)} · observed tools",
            )
        except LocalCliReplaySkippedError:
            continue
        catalog = [
            LocalCliCommand(
                command_id=tool.command_id,
                name=tool.name,
                usage=tool.qualified_name,
                description="Detected from this harness. Recommended keeps the usual review.",
            )
            for tool in tools
        ]
        # There is no allow-all fallback for an observed connector. Its catalog
        # is incomplete; unseen tools must retain their normal review.
        try:
            store.merge_local_cli_commands(cli_id, catalog, limit=MAX_OBSERVED_MCP_TOOLS)
        except LocalCliCatalogLimitError:
            # Keep this connector's prior choices, continue other connectors,
            # and let the caller report incomplete coverage.
            saturated += 1
            continue
    return saturated
