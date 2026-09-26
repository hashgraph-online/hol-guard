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

from ..native_policy_snapshot_codec import _normalized_harness_selector_v3
from ..native_policy_snapshot_constants import POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS
from .local_cli_commands import MAX_LOCAL_CLI_COMMANDS, OTHER_COMMAND_ID, LocalCliCommand
from .local_cli_identity import UnlistedCliIdentity
from .mcp_protection import McpServerIdentity, build_mcp_server_identity

if TYPE_CHECKING:
    from ..store import GuardStore

OBSERVED_MCP_PREFIX = "observed-mcp:"
MAX_OBSERVED_MCP_RECEIPTS = 2000
MAX_OBSERVED_MCP_SERVERS = 40
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


def tools_from_receipts(receipts: Sequence[Mapping[str, object]]) -> tuple[ObservedMcpTool, ...]:
    """Read only the tool label and harness from a bounded receipt batch."""

    tools: dict[tuple[str, str], ObservedMcpTool] = {}
    for receipt in receipts[:MAX_OBSERVED_MCP_RECEIPTS]:
        label = receipt.get("raw_command_text")
        label = label[5:] if isinstance(label, str) and label.startswith("tool:") else receipt.get("artifact_name")
        tool = observed_mcp_tool(receipt.get("harness"), label)
        if tool is not None:
            tools[(tool.harness, tool.qualified_name)] = tool
    return tuple(tools.values())


def discover_observed_mcp_tools(store: GuardStore, *, seen_at: str) -> None:
    """Backfill connector suggestions. Existing grants and tool states survive."""

    groups: dict[tuple[str, str], list[ObservedMcpTool]] = {}
    # Native receipts deliberately omit tool names. Paused native requests
    # retain the display label, so they are also a discovery source; resolving
    # a request must not make its connector disappear from the picker.
    records = store.list_approval_requests(status=None, limit=MAX_OBSERVED_MCP_RECEIPTS)
    observed = tools_from_receipts(records) + tools_from_receipts(
        store.list_receipts(limit=MAX_OBSERVED_MCP_RECEIPTS),
    )
    for tool in observed:
        key = (tool.harness, tool.namespace)
        if key not in groups and len(groups) >= MAX_OBSERVED_MCP_SERVERS:
            continue
        group = groups.setdefault(key, [])
        if tool not in group and len(group) < MAX_OBSERVED_MCP_TOOLS:
            group.append(tool)
    for tools in groups.values():
        first = tools[0]
        server = first.server_identity
        cli_id = store.ensure_local_mcp_observation(
            first.identity,
            seen_at=seen_at,
            server_identity_hash=server.identity_hash,
            server_command=server.command,
            server_args_hash=server.args_hash,
            source_label=f"{first.harness.title()} · observed tools",
        )
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
        store.merge_local_cli_commands(cli_id, catalog, limit=MAX_OBSERVED_MCP_TOOLS)


def native_observed_mcp_tool_actions(store: GuardStore) -> dict[str, str]:
    """Compile exact operator choices into the authenticated native policy.

    Only catalogued tools can be allowed. The fallback may block new tools,
    but cannot grant permission to tools the operator has never seen.
    """

    actions: dict[str, str] = {}
    for item in store.list_local_cli_items():
        if item.get("surface") != "mcp" or item.get("stale") is True:
            continue
        cli_id = item.get("cli_id")
        if not isinstance(cli_id, str):
            continue
        observation = store.find_local_mcp_observation(cli_id=cli_id)
        marker = observation.get("server_command") if observation is not None else None
        if not isinstance(marker, str) or not marker.startswith(OBSERVED_MCP_PREFIX):
            continue
        harness, separator, namespace = marker[len(OBSERVED_MCP_PREFIX) :].partition(":")
        if not separator:
            continue
        example = observed_mcp_tool(harness, namespace + "probe")
        if example is None or example.namespace != namespace:
            continue
        server = example.server_identity
        if item.get("identity_hash") != server.identity_hash:
            continue
        grant = store.read_local_mcp_grant(server.identity_hash)
        if grant is None:
            continue
        if grant.get("state") == "blocked":
            actions[f"{harness}:{namespace}*"] = "block"
            continue
        states = grant.get("command_states")
        commands = grant.get("commands")
        if not isinstance(states, Mapping) or not isinstance(commands, list):
            continue
        if states.get(OTHER_COMMAND_ID) == "block":
            actions[f"{harness}:{namespace}*"] = "block"
        for command in commands:
            if not isinstance(command, LocalCliCommand) or command.command_id == OTHER_COMMAND_ID:
                continue
            tool = observed_mcp_tool(harness, command.usage)
            if tool is None or tool.namespace != namespace or tool.command_id != command.command_id:
                continue
            state = states.get(command.command_id)
            if state in {"allow", "block"}:
                actions[f"{harness}:{tool.qualified_name}"] = str(state)
    blocks = {key: value for key, value in actions.items() if value == "block"}
    allows = {key: value for key, value in sorted(actions.items()) if value == "allow"}
    bounded = dict(sorted(blocks.items())[:POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS])
    for key, value in allows.items():
        if len(bounded) >= POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS:
            break
        bounded[key] = value
    return bounded
