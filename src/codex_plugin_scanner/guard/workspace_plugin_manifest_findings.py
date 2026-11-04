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

PLUGIN_MANIFEST_DETECTOR: Final = "plugin_manifest_v1"


__all__ = [
    "PLUGIN_MANIFEST_DETECTOR",
]
