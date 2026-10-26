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

HOOK_CONFIG_DETECTOR: Final = "hook_config_v1"
HOOK_CONFIG_SOURCE_KIND: Final = "workspace_source"
HOOKS_RESULT_SCHEMA: Final = "guard.workspace-hooks.v1"
MAX_HOOK_CONFIG_FINDINGS: Final = 200

_FINDING_ID = re.compile(r"[0-9a-f]{32}")
_RULE_ID = re.compile(r"hook\.config\.[a-z0-9.-]{1,120}")
_REASON = re.compile(r"[a-z0-9_]{1,40}")
_EVENT = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_SEVERITIES: Final = frozenset({"critical", "high", "medium", "low", "info"})
_CONFIDENCES: Final = frozenset({"weak", "likely", "strong"})
_CATEGORY = re.compile(r"[a-z_]{1,32}")
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
_MAX_TEXT_CHARS: Final = 1024
_SKIP_KINDS: Final = ("oversize", "not_text", "unparsed", "unread", "linked")


def project_hook_config_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native hook result."""

    return _projection(result)[0]


def with_hook_config_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the hook configuration detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that
    could not read every configuration, or a malformed reply, leaves it
    incomplete. Both make the run partial. A worktree without hook
    configuration files has no inputs.
    """

    reasons = list(_list(coverage.get("reasons")))
    summary: dict[str, object] = {}
    if result is None:
        status = "not_run"
        reasons.append(f"detector_not_run:{HOOK_CONFIG_DETECTOR}")
    else:
        status, summary, truncation = _status(result)
        if status != "complete":
            reasons.append("hook_config_incomplete")
        if "max_findings" in truncation and "finding_cap" not in reasons:
            reasons.append("finding_cap")
        if status == "complete" and summary.get("files_scanned") == 0:
            status = "no_inputs"
    detectors = coverage.get("detectors")
    return {
        **coverage,
        "status": "partial" if reasons else "complete",
        "reasons": reasons,
        "detectors": {**(detectors if isinstance(detectors, Mapping) else {}), HOOK_CONFIG_DETECTOR: status},
        **({"hook_config": summary} if summary else {}),
    }


def _status(result: object) -> tuple[str, dict[str, object], list[str]]:
    if not isinstance(result, Mapping) or result.get("schema") != HOOKS_RESULT_SCHEMA:
        return "error", {}, ["unreadable_result"]
    status = result.get("status")
    # A reply without its findings list cannot show that nothing was found.
    if (
        not isinstance(status, str)
        or status not in {"complete", "incomplete"}
        or not isinstance(result.get("findings"), list)
    ):
        return "error", {}, ["unreadable_result"]
    reasons = _reasons(result.get("truncation_reasons"))
    if _projection(result)[1]:
        reasons = sorted({*reasons, "invalid_finding"})
    if status == "incomplete" and not reasons:
        reasons = ["incomplete"]
    skipped = result.get("skipped")
    summary: dict[str, object] = {
        "files_scanned": _count(result.get("files_scanned")),
        "commands_scanned": _count(result.get("commands_scanned")),
        "skipped": {kind: _count(skipped.get(kind)) if isinstance(skipped, Mapping) else 0 for kind in _SKIP_KINDS},
        "truncation_reasons": reasons,
    }
    return ("incomplete" if reasons else "complete"), summary, reasons


def _projection(result: object) -> tuple[list[dict[str, object]], int]:
    raw = result.get("findings") if isinstance(result, Mapping) else None
    if not isinstance(raw, list):
        return [], 0
    kept = raw[:MAX_HOOK_CONFIG_FINDINGS]
    findings = [finding for item in kept if (finding := _finding(item)) is not None]
    return findings, len(kept) - len(findings) + max(0, len(raw) - MAX_HOOK_CONFIG_FINDINGS)


def _finding(item: object) -> dict[str, object] | None:
    if not isinstance(item, Mapping):
        return None
    finding_id = item.get("finding_id")
    rule_id = item.get("rule_id")
    path = item.get("path")
    event = item.get("event")
    category = item.get("category")
    severity = item.get("severity")
    confidence = item.get("confidence")
    title = _text(item.get("title"))
    reason = _text(item.get("reason"))
    hint = item.get("false_positive_hint")
    if (
        not isinstance(finding_id, str)
        or not _FINDING_ID.fullmatch(finding_id)
        or not isinstance(rule_id, str)
        or not _RULE_ID.fullmatch(rule_id)
        or not _is_hook_file(path)
        or not isinstance(event, str)
        or not _EVENT.fullmatch(event)
        or not isinstance(category, str)
        or not _CATEGORY.fullmatch(category)
        or severity not in _SEVERITIES
        or confidence not in _CONFIDENCES
        or title is None
        or reason is None
        or (hint is not None and _text(hint) is None)
    ):
        return None
    return {
        "finding_id": finding_id,
        "source_kind": HOOK_CONFIG_SOURCE_KIND,
        "detector": HOOK_CONFIG_DETECTOR,
        "severity": severity,
        "decision": "warn",
        "ecosystem": None,
        "package_name": None,
        "package_version": None,
        "fix_version": None,
        "rule_ids": [rule_id],
        "advisory_ids": [],
        "path": path,
        "line": None,
        "event": event,
        "category": category,
        "confidence": confidence,
        "title": title,
        "reason": reason,
        "false_positive_hint": _text(hint),
        "validation_state": "unvalidated",
        "lifecycle_state": "open",
    }


def _is_hook_file(value: object) -> bool:
    """One of the root-level hook configuration files the native check reads."""

    if not isinstance(value, str):
        return False
    return value in _HOOK_FILES or _COPILOT_HOOK_FILE.fullmatch(value) is not None


def _text(value: object) -> str | None:
    """Fixed rule text: one bounded printable line."""

    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_TEXT_CHARS:
        return None
    return value if value.isprintable() else None


def _reasons(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str) and _REASON.fullmatch(item)})


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _list(value: object) -> list[object]:
    return list(value) if isinstance(value, (list, tuple)) else []


__all__ = [
    "HOOK_CONFIG_DETECTOR",
    "HOOK_CONFIG_SOURCE_KIND",
    "MAX_HOOK_CONFIG_FINDINGS",
    "project_hook_config_findings",
    "with_hook_config_coverage",
]
