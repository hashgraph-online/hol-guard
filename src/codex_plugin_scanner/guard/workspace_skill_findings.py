"""Project the native skill content scan into workspace findings and coverage.

The native snapshot runs the same skill content rules Guard applies at hook
time over every agent skill in the worktree, and decides the stable
``finding_id``, the rule's severity and whether the scan was complete. Each
finding carries only the rule's fixed title and reason and the skill's
root-relative path, never text from the skill. The native
``workspace_rule_findings`` kind checks that shape and copies it into the
stored finding; a finding that does not match is dropped and leaves the
detector incomplete instead of silently complete.

Skill findings are dashboard warnings. They never block or ask, so a skill a
developer wrote on purpose stays quiet until someone looks.
"""

from __future__ import annotations

from typing import Final

from .workspace_rule_findings import project_rule_findings, with_rule_coverage

SKILL_DETECTOR: Final = "skill_content_v1"


def project_skill_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native skill result."""

    return project_rule_findings(SKILL_DETECTOR, result)


def with_skill_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the skill detector to a run's coverage.

    A runtime without the scan leaves the detector not run; a scan that could
    not read every skill, or a malformed reply, leaves it incomplete. Both make
    the run partial. A worktree with no agent skills has no skill inputs.
    """

    return with_rule_coverage(SKILL_DETECTOR, coverage, result)


__all__ = [
    "SKILL_DETECTOR",
    "project_skill_findings",
    "with_skill_coverage",
]
