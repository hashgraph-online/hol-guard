"""Ask the native runtime to check the MCP servers a worktree configures.

Guard's harness adapters already read every MCP configuration an agent would
load. Each server's launch command, arguments and URL go to the runtime over
stdin with the absolute path of the file that configures it and the worktree
root; its environment, headers and any other setting stay behind. The runtime
keeps only servers configured inside the worktree, reads no files and starts
nothing.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .models import HarnessDetection

MCP_CONFIG_COMMAND: Final = "mcp-config-assess"
MCP_CONFIG_FEATURE: Final = "mcp-config-assess-v1"
_REQUEST_SCHEMA: Final = "guard.workspace-mcp-config-request.v1"
_TIMEOUT_SECONDS: Final = 30.0
# Up to 200 findings, each repeating a path of up to 4 KiB and a server name of
# up to 1 KiB, both possibly escaped.
_OUTPUT_LIMIT_BYTES: Final = 8 * 1024 * 1024
_CHILD_ENVIRONMENT_KEYS: Final = ("SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP")


class McpConfigUnavailableError(RuntimeError):
    """The runtime has no MCP configuration check."""


@dataclass(frozen=True, slots=True)
class WorkspaceServers:
    """Every configured server, the worktree's roots and the harnesses Guard could not read."""

    servers: tuple[dict[str, object], ...]
    roots: tuple[str, ...]
    skipped_harnesses: tuple[str, ...]


def workspace_mcp_servers(store: Any, root: Path, *, home_dir: Path | None = None) -> WorkspaceServers:
    """The MCP servers Guard's adapters find for ``root``, wherever they are configured."""

    from .adapters.harness_mcp_discovery import configured_harness_detections

    skipped: list[str] = []
    detections = configured_harness_detections(
        home_dir if home_dir is not None else Path.home(), Path(store.guard_home), root, skipped=skipped
    )
    return WorkspaceServers(
        servers=server_rows(detections),
        roots=workspace_roots(root),
        skipped_harnesses=tuple(sorted(set(skipped))),
    )


def server_rows(detections: Sequence[HarnessDetection]) -> tuple[dict[str, object], ...]:
    """One request row per configured MCP server."""

    return tuple(
        {
            "config_path": artifact.config_path,
            "server": artifact.name,
            "command": artifact.command,
            "args": list(artifact.args),
            "url": artifact.url,
        }
        for detection in detections
        for artifact in detection.artifacts
        if artifact.artifact_type == "mcp_server" and artifact.config_path
    )


def workspace_roots(root: Path) -> tuple[str, ...]:
    """``root`` as named and with links followed, so a linked worktree still matches."""

    return tuple(dict.fromkeys((os.path.normpath(root), str(root.resolve()))))


def assess_mcp_servers(found: WorkspaceServers) -> dict[str, object]:
    """The runtime's result for the servers ``found``.

    Raises :class:`McpConfigUnavailableError` when the runtime lacks the check and
    ``RuntimeError`` when it could not answer.
    """

    from .codex_hook_launch_runtime import run_isolated_hook_process
    from .native_runtime import native_runtime_status

    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or MCP_CONFIG_FEATURE not in status.capabilities.features
    ):
        raise McpConfigUnavailableError("mcp_config_unavailable")
    runtime = status.identity.path
    completed = run_isolated_hook_process(
        (str(runtime), MCP_CONFIG_COMMAND, "--stdin"),
        input_text=json.dumps(
            {"schema": _REQUEST_SCHEMA, "roots": list(found.roots), "servers": list(found.servers)},
            separators=(",", ":"),
        ),
        cwd=runtime.parent,
        environment={key: value for key in _CHILD_ENVIRONMENT_KEYS if (value := os.environ.get(key))},
        timeout_seconds=_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    if (
        completed.returncode != 0
        or completed.timed_out
        or completed.output_limit_exceeded
        or completed.containment_failed
    ):
        raise RuntimeError("mcp_config_failed")
    try:
        reply = json.loads(completed.stdout)
    except ValueError as error:
        raise RuntimeError("mcp_config_failed") from error
    if not isinstance(reply, dict) or reply.get("ok") is not True or not isinstance(reply.get("result"), dict):
        raise RuntimeError("mcp_config_failed")
    return reply["result"]


__all__ = [
    "MCP_CONFIG_FEATURE",
    "McpConfigUnavailableError",
    "WorkspaceServers",
    "assess_mcp_servers",
    "server_rows",
    "workspace_mcp_servers",
    "workspace_roots",
]
