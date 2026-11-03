"""Project the native agent plugin check into workspace findings and coverage.

The native snapshot finds every Claude Code or Codex plugin manifest and Gemini
CLI extension in the worktree, reads the hooks and MCP servers each one ships
and runs them through the shared hook and MCP launch rules. It decides each
finding's stable ``finding_id``, the rule's severity and whether the check was
complete. A finding carries only the rule's fixed title and reason, the
root-relative path of the file that holds the hook or server, and the hook
event or server name, never the command, its arguments or a URL. This module
checks that shape and copies it into the stored finding; a finding that does
not match is dropped and leaves the detector incomplete instead of silently
complete.

Plugin findings are dashboard warnings. They never block or ask.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final

from .workspace_rule_findings import (
    MAX_RULE_FINDINGS,
    WORKSPACE_SOURCE_KIND,
    RuleScan,
    project_rule_findings,
    with_rule_coverage,
)

PLUGIN_MANIFEST_DETECTOR: Final = "plugin_manifest_v1"
PLUGIN_MANIFEST_SOURCE_KIND: Final = WORKSPACE_SOURCE_KIND
PLUGINS_RESULT_SCHEMA: Final = "guard.workspace-plugins.v1"
MAX_PLUGIN_MANIFEST_FINDINGS: Final = MAX_RULE_FINDINGS

_RULE_IDS: Final = {
    "hook": re.compile(r"hook\.config\.[a-z0-9.-]{1,120}"),
    "mcp_server": re.compile(r"mcp\.config\.[a-z0-9.-]{1,120}"),
}
_NAME_FIELDS: Final = {"hook": "event", "mcp_server": "server"}
_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_MANIFEST_DIRECTORIES: Final = frozenset({".claude-plugin", ".codex-plugin"})
_MAX_PATH_CHARS: Final = 4096


def project_plugin_manifest_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native plugin result."""

    return project_rule_findings(_SCAN, result)


def with_plugin_manifest_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the agent plugin detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that
    could not read every plugin file, or a malformed reply, leaves it
    incomplete. Both make the run partial. A worktree without plugins has no
    inputs.
    """

    return with_rule_coverage(_SCAN, coverage, result)


def _plugin_fields(item: Mapping[str, object]) -> dict[str, object] | None:
    kind = item.get("kind")
    rule_id = item.get("rule_id")
    name = item.get("name")
    if (
        not isinstance(kind, str)
        or kind not in _RULE_IDS
        or not isinstance(rule_id, str)
        or not _RULE_IDS[kind].fullmatch(rule_id)
        or not _is_plugin_file(item.get("path"))
        or not isinstance(name, str)
        or not _NAME.fullmatch(name)
    ):
        return None
    return {"component": kind, _NAME_FIELDS[kind]: name}


def _is_plugin_file(value: object) -> bool:
    """A root-relative manifest or plugin hook or MCP file the native check keeps."""

    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_PATH_CHARS or not value.isprintable() or "\\" in value:
        return False
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    name = parts[-1]
    directory = parts[-2] if len(parts) > 1 else None
    return (
        name == "gemini-extension.json"
        or (name == "plugin.json" and directory in _MANIFEST_DIRECTORIES)
        or (name == ".mcp.json" and directory is not None)
        or (directory == "hooks" and name.endswith(".json"))
    )


_SCAN: Final = RuleScan(
    detector=PLUGIN_MANIFEST_DETECTOR,
    result_schema=PLUGINS_RESULT_SCHEMA,
    summary_key="plugin_manifest",
    incomplete_reason="plugin_manifest_incomplete",
    counters=("plugins_scanned", "files_scanned", "commands_scanned", "servers_scanned"),
    inputs_counter="plugins_scanned",
    skip_kinds=("oversize", "not_text", "unparsed", "unread"),
    finding_fields=_plugin_fields,
)


__all__ = [
    "MAX_PLUGIN_MANIFEST_FINDINGS",
    "PLUGIN_MANIFEST_DETECTOR",
    "PLUGIN_MANIFEST_SOURCE_KIND",
    "project_plugin_manifest_findings",
    "with_plugin_manifest_coverage",
]
