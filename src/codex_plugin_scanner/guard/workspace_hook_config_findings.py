"""Project the native project hook check into workspace findings and coverage.

The native snapshot reads the hook configuration files agents load from the
worktree root and runs every hook command through the shared launch screen. It
decides each finding's stable ``finding_id``, the rule's severity and whether
the check was complete. A finding carries only the rule's fixed title and
reason, the configuration file's root-relative path and the hook event, never
the command. This module checks that shape and copies it into the stored
finding; a finding that does not match is dropped and leaves the detector
incomplete instead of silently complete.

Hook configuration findings are dashboard warnings. They never block or ask.
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

HOOK_CONFIG_DETECTOR: Final = "hook_config_v1"
HOOK_CONFIG_SOURCE_KIND: Final = WORKSPACE_SOURCE_KIND
HOOKS_RESULT_SCHEMA: Final = "guard.workspace-hooks.v1"
MAX_HOOK_CONFIG_FINDINGS: Final = MAX_RULE_FINDINGS

_RULE_ID = re.compile(r"hook\.config\.[a-z0-9.-]{1,120}")
_EVENT = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_HOOK_FILES: Final = frozenset(
    {
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".codex/config.toml",
        ".codex/hooks.json",
        ".cursor/hooks.json",
        ".devin/config.json",
        ".devin/config.local.json",
        ".devin/hooks.v1.json",
        ".gemini/settings.json",
    }
)
_COPILOT_HOOK_FILE = re.compile(r"\.github/hooks/[^/\\\0]{0,250}\.json")


def project_hook_config_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native hook result."""

    return project_rule_findings(_SCAN, result)


def with_hook_config_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the hook configuration detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that
    could not read every configuration, or a malformed reply, leaves it
    incomplete. Both make the run partial. A worktree without hook
    configuration files has no inputs.
    """

    return with_rule_coverage(_SCAN, coverage, result)


def _hook_fields(item: Mapping[str, object]) -> dict[str, object] | None:
    rule_id = item.get("rule_id")
    event = item.get("event")
    if (
        not isinstance(rule_id, str)
        or not _RULE_ID.fullmatch(rule_id)
        or not _is_hook_file(item.get("path"))
        or not isinstance(event, str)
        or not _EVENT.fullmatch(event)
    ):
        return None
    return {"event": event}


def _is_hook_file(value: object) -> bool:
    """One of the root-level hook configuration files the native check reads."""

    if not isinstance(value, str):
        return False
    return value in _HOOK_FILES or _COPILOT_HOOK_FILE.fullmatch(value) is not None


_SCAN: Final = RuleScan(
    detector=HOOK_CONFIG_DETECTOR,
    result_schema=HOOKS_RESULT_SCHEMA,
    summary_key="hook_config",
    incomplete_reason="hook_config_incomplete",
    counters=("files_scanned", "commands_scanned"),
    inputs_counter="files_scanned",
    skip_kinds=("oversize", "not_text", "unparsed", "unread", "linked"),
    finding_fields=_hook_fields,
)


__all__ = [
    "HOOK_CONFIG_DETECTOR",
    "HOOK_CONFIG_SOURCE_KIND",
    "MAX_HOOK_CONFIG_FINDINGS",
    "project_hook_config_findings",
    "with_hook_config_coverage",
]
