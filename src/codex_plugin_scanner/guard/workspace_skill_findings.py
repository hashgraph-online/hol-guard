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

SKILL_DETECTOR: Final = "skill_content_v1"


__all__ = [
    "SKILL_DETECTOR",
]
