"""Project the native project hook check into workspace findings and coverage.

The native snapshot reads the hook configuration files agents load from the
worktree root and runs every hook command through the shared launch screen. It
decides each finding's stable ``finding_id``, the rule's severity and whether
the check was complete. A finding carries only the rule's fixed title and
reason, the configuration file's root-relative path and the hook event, never
the command. The native ``workspace_rule_findings`` kind checks that shape and
copies it into the stored finding; a finding that does not match is dropped
and leaves the detector incomplete instead of silently complete.

Hook configuration findings are dashboard warnings. They never block or ask.
"""

from __future__ import annotations

from typing import Final

HOOK_CONFIG_DETECTOR: Final = "hook_config_v1"


__all__ = [
    "HOOK_CONFIG_DETECTOR",
]
