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
instruction text. The native ``workspace_rule_findings`` kind checks that
shape and copies it into the stored finding; a finding that does not match is
dropped and leaves the detector incomplete instead of silently complete.

Instruction file findings are dashboard warnings. They never block or ask.
"""

from __future__ import annotations

from typing import Final

from .workspace_rule_findings import project_rule_findings, with_rule_coverage

INSTRUCTION_DETECTOR: Final = "instruction_file_v1"


def project_instruction_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native instruction file result."""

    return project_rule_findings(INSTRUCTION_DETECTOR, result)


def with_instruction_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the instruction file detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that
    could not read every instruction file, or a malformed reply, leaves it
    incomplete. Both make the run partial. A worktree without instruction
    files has no inputs.
    """

    return with_rule_coverage(INSTRUCTION_DETECTOR, coverage, result)


__all__ = [
    "INSTRUCTION_DETECTOR",
    "project_instruction_findings",
    "with_instruction_coverage",
]
