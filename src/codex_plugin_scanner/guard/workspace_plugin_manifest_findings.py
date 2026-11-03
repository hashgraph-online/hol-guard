"""Project the native agent plugin check into workspace findings and coverage.

The native snapshot finds every Claude Code or Codex plugin manifest and
Gemini CLI extension in the worktree, reads the hooks and MCP servers each one
ships and runs them through the shared hook and MCP launch rules. It decides
each finding's stable ``finding_id``, the rule's severity and whether the
check was complete. A finding carries only the rule's fixed title and reason,
the root-relative path of the file that holds the hook or server, and the hook
event or server name, never the command, its arguments or a URL. The native
``workspace_rule_findings`` kind checks that shape and copies it into the
stored finding; a finding that does not match is dropped and leaves the
detector incomplete instead of silently complete.

Plugin findings are dashboard warnings. They never block or ask.
"""

from __future__ import annotations

from typing import Final

from .workspace_rule_findings import project_rule_findings, with_rule_coverage

PLUGIN_MANIFEST_DETECTOR: Final = "plugin_manifest_v1"


def project_plugin_manifest_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native plugin result."""

    return project_rule_findings(PLUGIN_MANIFEST_DETECTOR, result)


def with_plugin_manifest_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the agent plugin detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that
    could not read every plugin file, or a malformed reply, leaves it
    incomplete. Both make the run partial. A worktree without plugins has no
    inputs.
    """

    return with_rule_coverage(PLUGIN_MANIFEST_DETECTOR, coverage, result)


__all__ = [
    "PLUGIN_MANIFEST_DETECTOR",
    "project_plugin_manifest_findings",
    "with_plugin_manifest_coverage",
]
