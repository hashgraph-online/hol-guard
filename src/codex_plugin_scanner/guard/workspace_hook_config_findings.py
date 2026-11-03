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

from .workspace_rule_findings import project_rule_findings, with_rule_coverage

HOOK_CONFIG_DETECTOR: Final = "hook_config_v1"


def project_hook_config_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native hook result."""

    return project_rule_findings(HOOK_CONFIG_DETECTOR, result)


def with_hook_config_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the hook configuration detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that
    could not read every configuration, or a malformed reply, leaves it
    incomplete. Both make the run partial. A worktree without hook
    configuration files has no inputs.
    """

    return with_rule_coverage(HOOK_CONFIG_DETECTOR, coverage, result)


__all__ = [
    "HOOK_CONFIG_DETECTOR",
    "project_hook_config_findings",
    "with_hook_config_coverage",
]
