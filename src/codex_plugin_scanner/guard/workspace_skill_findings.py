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

SKILL_DETECTOR: Final = "skill_content_v1"
SKILL_SOURCE_KIND: Final = "workspace_source"
SKILLS_RESULT_SCHEMA: Final = "guard.workspace-skills.v1"
MAX_SKILL_FINDINGS: Final = 200

_FINDING_ID = re.compile(r"[0-9a-f]{32}")
_RULE_ID = re.compile(r"skill\.[a-z0-9.-]{1,120}")
_REASON = re.compile(r"[a-z0-9_]{1,40}")
_SEVERITIES: Final = frozenset({"critical", "high", "medium", "low", "info"})
_CONFIDENCES: Final = frozenset({"weak", "likely", "strong"})
_CATEGORY = re.compile(r"[a-z_]{1,32}")
_SKILL_FILE: Final = "SKILL.md"
_MAX_PATH_CHARS: Final = 4096
_MAX_TEXT_CHARS: Final = 1024
_SKIP_KINDS: Final = ("oversize", "not_text", "unread", "linked")


def project_skill_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native skill result."""

    return _projection(result)[0]


def with_skill_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the skill detector to a run's coverage.

    A runtime without the scan leaves the detector not run; a scan that could
    not read every skill, or a malformed reply, leaves it incomplete. Both make
    the run partial. A worktree with no agent skills has no skill inputs.
    """

    reasons = list(_list(coverage.get("reasons")))
    summary: dict[str, object] = {}
    if result is None:
        status = "not_run"
        reasons.append(f"detector_not_run:{SKILL_DETECTOR}")
    else:
        status, summary, truncation = _status(result)
        if status != "complete":
            reasons.append("skills_incomplete")
        # A scan that stopped at its own cap lists only some findings.
        if "max_findings" in truncation and "finding_cap" not in reasons:
            reasons.append("finding_cap")
        if status == "complete" and summary.get("files_scanned") == 0:
            status = "no_inputs"
    detectors = coverage.get("detectors")
    return {
        **coverage,
        "status": "partial" if reasons else "complete",
        "reasons": reasons,
        "detectors": {**(detectors if isinstance(detectors, Mapping) else {}), SKILL_DETECTOR: status},
        **({"skills": summary} if summary else {}),
    }


def _status(result: object) -> tuple[str, dict[str, object], list[str]]:
    if not isinstance(result, Mapping) or result.get("schema") != SKILLS_RESULT_SCHEMA:
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
        "bytes_scanned": _count(result.get("bytes_scanned")),
        "skipped": {kind: _count(skipped.get(kind)) if isinstance(skipped, Mapping) else 0 for kind in _SKIP_KINDS},
        "truncation_reasons": reasons,
    }
    return ("incomplete" if reasons else "complete"), summary, reasons


def _projection(result: object) -> tuple[list[dict[str, object]], int]:
    raw = result.get("findings") if isinstance(result, Mapping) else None
    if not isinstance(raw, list):
        return [], 0
    findings = [finding for item in raw[:MAX_SKILL_FINDINGS] if (finding := _finding(item)) is not None]
    return findings, len(raw[:MAX_SKILL_FINDINGS]) - len(findings) + max(0, len(raw) - MAX_SKILL_FINDINGS)


def _finding(item: object) -> dict[str, object] | None:
    if not isinstance(item, Mapping):
        return None
    finding_id = item.get("finding_id")
    rule_id = item.get("rule_id")
    path = item.get("path")
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
        or not _is_skill_path(path)
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
        "source_kind": SKILL_SOURCE_KIND,
        "detector": SKILL_DETECTOR,
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
        "category": category,
        "confidence": confidence,
        "title": title,
        "reason": reason,
        "false_positive_hint": _text(hint),
        "validation_state": "unvalidated",
        "lifecycle_state": "open",
    }


def _is_skill_path(value: object) -> bool:
    """A normalized root-relative ``.../SKILL.md`` path, never one that leaves the root."""

    if not isinstance(value, str) or len(value) > _MAX_PATH_CHARS or "\0" in value or "\\" in value:
        return False
    parts = value.split("/")
    return (
        len(parts) >= 2
        and parts[-1] == _SKILL_FILE
        and all(part not in {"", ".", ".."} for part in parts)
        and not parts[0].endswith(":")
    )


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
    "MAX_SKILL_FINDINGS",
    "SKILL_DETECTOR",
    "SKILL_SOURCE_KIND",
    "project_skill_findings",
    "with_skill_coverage",
]
