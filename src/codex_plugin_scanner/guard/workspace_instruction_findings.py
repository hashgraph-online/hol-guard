"""Project the native agent instruction file check into workspace findings and coverage.

The native snapshot reads the instruction files coding agents load from the
repository they work in: ``AGENTS.md``, ``CLAUDE.md`` and ``GEMINI.md`` at any
depth, Cursor rules in any ``.cursor/rules`` folder, and a few root files and
rule folders such as ``.github/copilot-instructions.md``. It flags an
instruction that turns off approvals or the sandbox, one that tells the agent
to disable or route around Guard, one that tells it to hide what it does, and
invisible Unicode controls. It decides each finding's stable ``finding_id``,
the rule's severity and whether the check was complete. A finding carries only
the rule's fixed title and reason and the file's root-relative path, never the
instruction text. This module checks that shape and copies it into the stored
finding; a finding that does not match is dropped and leaves the detector
incomplete instead of silently complete.

Instruction file findings are dashboard warnings. They never block or ask.
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

INSTRUCTION_DETECTOR: Final = "instruction_file_v1"
INSTRUCTION_SOURCE_KIND: Final = WORKSPACE_SOURCE_KIND
INSTRUCTIONS_RESULT_SCHEMA: Final = "guard.workspace-instructions.v1"
MAX_INSTRUCTION_FINDINGS: Final = MAX_RULE_FINDINGS

_RULE_IDS: Final = frozenset(
    {
        "instruction.approval-bypass",
        "instruction.guard-bypass",
        "instruction.hide-actions",
        "instruction.unicode-controls",
    }
)
# The files the native scan reads, compared without regard to case. Each
# folder is one non-empty segment without a backslash.
_FOLDERS: Final = r"(?:[^/\\\0]+/)*"
_INSTRUCTION_PATH: Final = re.compile(
    rf"{_FOLDERS}(?:agents|agents\.override|claude|claude\.local|gemini)\.md"
    r"|agent\.md|\.cursorrules|\.windsurfrules|\.clinerules|\.github/copilot-instructions\.md"
    rf"|{_FOLDERS}\.cursor/rules/{_FOLDERS}[^/\\\0]*\.mdc?"
    rf"|\.windsurf/rules/{_FOLDERS}[^/\\\0]+\.md"
    rf"|\.github/instructions/{_FOLDERS}[^/\\\0]+\.instructions\.md"
    rf"|\.kiro/steering/{_FOLDERS}[^/\\\0]+\.md|\.clinerules/{_FOLDERS}[^/\\\0]+\.md",
    re.IGNORECASE,
)
_MAX_PATH_BYTES: Final = 4096


def project_instruction_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native instruction file result."""

    return project_rule_findings(_SCAN, result)


def with_instruction_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the instruction file detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that
    could not read every instruction file, or a malformed reply, leaves it
    incomplete. Both make the run partial. A worktree without instruction
    files has no inputs.
    """

    return with_rule_coverage(_SCAN, coverage, result)


def _instruction_fields(item: Mapping[str, object]) -> dict[str, object] | None:
    rule_id = item.get("rule_id")
    path = item.get("path")
    if (
        not isinstance(rule_id, str)
        or rule_id not in _RULE_IDS
        or not is_relative_path(path)
        or len(path.encode("utf-8", "surrogatepass")) > _MAX_PATH_BYTES
        or not _INSTRUCTION_PATH.fullmatch(path)
    ):
        return None
    return {}


# A reply without its scan counts cannot show that nothing was found.
_SCAN: Final = RuleScan(
    detector=INSTRUCTION_DETECTOR,
    result_schema=INSTRUCTIONS_RESULT_SCHEMA,
    summary_key="instruction_file",
    incomplete_reason="instruction_file_incomplete",
    counters=("files_scanned",),
    inputs_counter="files_scanned",
    skip_kinds=("oversize", "not_text", "unread", "linked"),
    finding_fields=_instruction_fields,
    strict_counts=True,
)


__all__ = [
    "INSTRUCTION_DETECTOR",
    "INSTRUCTION_SOURCE_KIND",
    "MAX_INSTRUCTION_FINDINGS",
    "project_instruction_findings",
    "with_instruction_coverage",
]
