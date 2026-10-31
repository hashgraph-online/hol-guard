"""Project the native skill content scan into workspace findings and coverage.

The native snapshot runs the same skill content rules Guard applies at hook
time over every agent skill in the worktree, and decides the stable
``finding_id``, the rule's severity and whether the scan was complete. Each
finding carries only the rule's fixed title and reason and the skill's
root-relative path, never text from the skill. This module checks that shape
and copies it into the stored finding; a finding that does not match is
dropped and leaves the detector incomplete instead of silently complete.

Skill findings are dashboard warnings. They never block or ask, so a skill a
developer wrote on purpose stays quiet until someone looks.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final

from .workspace_rule_findings import (
    MAX_RULE_FINDINGS,
    WORKSPACE_SOURCE_KIND,
    RuleScan,
    is_relative_path,
    project_rule_findings,
    with_rule_coverage,
)

SKILL_DETECTOR: Final = "skill_content_v1"
SKILL_SOURCE_KIND: Final = WORKSPACE_SOURCE_KIND
SKILLS_RESULT_SCHEMA: Final = "guard.workspace-skills.v1"
MAX_SKILL_FINDINGS: Final = MAX_RULE_FINDINGS

_RULE_ID = re.compile(r"skill\.[a-z0-9.-]{1,120}")
_SKILL_FILE: Final = "SKILL.md"


def project_skill_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native skill result."""

    return project_rule_findings(_SCAN, result)


def with_skill_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the skill detector to a run's coverage.

    A runtime without the scan leaves the detector not run; a scan that could
    not read every skill, or a malformed reply, leaves it incomplete. Both make
    the run partial. A worktree with no agent skills has no skill inputs.
    """

    return with_rule_coverage(_SCAN, coverage, result)


def _skill_fields(item: Mapping[str, object]) -> dict[str, object] | None:
    rule_id = item.get("rule_id")
    if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id) or not _is_skill_path(item.get("path")):
        return None
    return {}


def _is_skill_path(value: object) -> bool:
    """A normalized root-relative ``.../SKILL.md`` path, never one that leaves the root."""

    return is_relative_path(value) and "/" in value and value.rsplit("/", 1)[1] == _SKILL_FILE


_SCAN: Final = RuleScan(
    detector=SKILL_DETECTOR,
    result_schema=SKILLS_RESULT_SCHEMA,
    summary_key="skills",
    incomplete_reason="skills_incomplete",
    counters=("files_scanned", "bytes_scanned"),
    inputs_counter="files_scanned",
    skip_kinds=("oversize", "not_text", "unread", "linked"),
    finding_fields=_skill_fields,
)


__all__ = [
    "MAX_SKILL_FINDINGS",
    "SKILL_DETECTOR",
    "SKILL_SOURCE_KIND",
    "project_skill_findings",
    "with_skill_coverage",
]
