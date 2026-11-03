"""Shared projection for the native workspace rule detectors.

The native snapshot runs several rule checks over a worktree: agent skills,
project hook configuration, MCP configuration, agent plugins and CI workflows.
Each replies in the same shape: a schema tag, a status, scan counts, skipped
counts, truncation reasons and a bounded list of findings. Every finding names a
stable ``finding_id``, a rule id, a root-relative path, a category, the rule's
severity and confidence and its fixed title and reason. A detector module
describes what differs with a :class:`RuleScan`; this module checks the shared
shape, copies it into the stored finding and records the detector's coverage.
A finding that does not match is dropped and leaves the detector incomplete
instead of silently complete.

Rule findings are dashboard warnings. They never block or ask.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, TypeGuard

WORKSPACE_SOURCE_KIND: Final = "workspace_source"
MAX_RULE_FINDINGS: Final = 200

_FINDING_ID = re.compile(r"[0-9a-f]{32}")
_REASON = re.compile(r"[a-z0-9_]{1,40}")
_SEVERITIES: Final = frozenset({"critical", "high", "medium", "low", "info"})
_CONFIDENCES: Final = frozenset({"weak", "likely", "strong"})
_CATEGORY = re.compile(r"[a-z_]{1,32}")
_MAX_PATH_CHARS: Final = 4096
_MAX_TEXT_CHARS: Final = 1024


@dataclass(frozen=True)
class RuleScan:
    """What one native rule detector's reply looks like."""

    detector: str
    result_schema: str
    # The coverage key that holds the scan summary.
    summary_key: str
    # The coverage reason a reply that is not complete adds.
    incomplete_reason: str
    counters: tuple[str, ...]
    # The counter that is zero when the worktree has nothing to check.
    inputs_counter: str
    skip_kinds: tuple[str, ...]
    # Checks the detector's own fields, including the rule id and path, and
    # returns the extra fields to store, or ``None`` for a malformed finding.
    finding_fields: Callable[[Mapping[str, object]], dict[str, object] | None]
    max_findings: int = MAX_RULE_FINDINGS
    # A strict reply must carry valid scan counts, its skipped counts and its
    # truncation reasons; otherwise a missing count reads as zero.
    strict_counts: bool = False


def project_rule_findings(scan: RuleScan, result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native rule result."""

    return _projection(scan, result)[0]


def with_rule_coverage(scan: RuleScan, coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add a rule detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that could
    not read every input, or a malformed reply, leaves it incomplete. Both make
    the run partial. A worktree with nothing to check has no inputs.
    """

    reasons = list(_list(coverage.get("reasons")))
    summary: dict[str, object] = {}
    if result is None:
        status = "not_run"
        reasons.append(f"detector_not_run:{scan.detector}")
    else:
        status, summary, truncation = _status(scan, result)
        if status != "complete":
            reasons.append(scan.incomplete_reason)
        # A scan that stopped at its own cap lists only some findings.
        if "max_findings" in truncation and "finding_cap" not in reasons:
            reasons.append("finding_cap")
        if status == "complete" and summary.get(scan.inputs_counter) == 0:
            status = "no_inputs"
    detectors = coverage.get("detectors")
    return {
        **coverage,
        "status": "partial" if reasons else "complete",
        "reasons": reasons,
        "detectors": {**(detectors if isinstance(detectors, Mapping) else {}), scan.detector: status},
        **({scan.summary_key: summary} if summary else {}),
    }


def is_relative_path(value: object) -> TypeGuard[str]:
    """A normalized root-relative path, never one that leaves the root."""

    if not isinstance(value, str) or len(value) > _MAX_PATH_CHARS or "\0" in value or "\\" in value:
        return False
    parts = value.split("/")
    return all(part not in {"", ".", ".."} for part in parts) and not parts[0].endswith(":")


def rule_text(value: object) -> str | None:
    """One bounded printable line."""

    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_TEXT_CHARS:
        return None
    return value if value.isprintable() else None


def _status(scan: RuleScan, result: object) -> tuple[str, dict[str, object], list[str]]:
    if not isinstance(result, Mapping) or result.get("schema") != scan.result_schema:
        return "error", {}, ["unreadable_result"]
    status = result.get("status")
    # A reply without its findings list cannot show that nothing was found.
    if (
        not isinstance(status, str)
        or status not in {"complete", "incomplete"}
        or not isinstance(result.get("findings"), list)
    ):
        return "error", {}, ["unreadable_result"]
    skipped = result.get("skipped")
    if scan.strict_counts and (
        not all(_is_count(result.get(counter)) for counter in scan.counters)
        or not isinstance(skipped, Mapping)
        or not isinstance(result.get("truncation_reasons"), list)
    ):
        return "error", {}, ["unreadable_result"]
    reasons = _reasons(result.get("truncation_reasons"))
    if _projection(scan, result)[1]:
        reasons = sorted({*reasons, "invalid_finding"})
    if status == "incomplete" and not reasons:
        reasons = ["incomplete"]
    summary: dict[str, object] = {
        **{counter: _count(result.get(counter)) for counter in scan.counters},
        "skipped": {kind: _count(skipped.get(kind)) if isinstance(skipped, Mapping) else 0 for kind in scan.skip_kinds},
        "truncation_reasons": reasons,
    }
    return ("incomplete" if reasons else "complete"), summary, reasons


def _projection(scan: RuleScan, result: object) -> tuple[list[dict[str, object]], int]:
    raw = result.get("findings") if isinstance(result, Mapping) else None
    if not isinstance(raw, list):
        return [], 0
    kept = raw[: scan.max_findings]
    findings = [finding for item in kept if (finding := _finding(scan, item)) is not None]
    return findings, len(kept) - len(findings) + max(0, len(raw) - scan.max_findings)


def _finding(scan: RuleScan, item: object) -> dict[str, object] | None:
    if not isinstance(item, Mapping):
        return None
    finding_id = item.get("finding_id")
    rule_id = item.get("rule_id")
    category = item.get("category")
    severity = item.get("severity")
    confidence = item.get("confidence")
    title = rule_text(item.get("title"))
    reason = rule_text(item.get("reason"))
    hint = item.get("false_positive_hint")
    extra = scan.finding_fields(item)
    if (
        extra is None
        or not isinstance(finding_id, str)
        or not _FINDING_ID.fullmatch(finding_id)
        or not isinstance(rule_id, str)
        or not isinstance(category, str)
        or not _CATEGORY.fullmatch(category)
        or not isinstance(severity, str)
        or severity not in _SEVERITIES
        or not isinstance(confidence, str)
        or confidence not in _CONFIDENCES
        or title is None
        or reason is None
        or (hint is not None and rule_text(hint) is None)
    ):
        return None
    return {
        "finding_id": finding_id,
        "source_kind": WORKSPACE_SOURCE_KIND,
        "detector": scan.detector,
        "severity": severity,
        "decision": "warn",
        "ecosystem": None,
        "package_name": None,
        "package_version": None,
        "fix_version": None,
        "rule_ids": [rule_id],
        "advisory_ids": [],
        "path": item.get("path"),
        "line": None,
        "category": category,
        "confidence": confidence,
        "title": title,
        "reason": reason,
        "false_positive_hint": rule_text(hint),
        "validation_state": "unvalidated",
        "lifecycle_state": "open",
        **extra,
    }


def _is_count(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _reasons(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str) and _REASON.fullmatch(item)})


def _count(value: object) -> int:
    return value if _is_count(value) else 0


def _list(value: object) -> list[object]:
    return list(value) if isinstance(value, (list, tuple)) else []


__all__ = [
    "MAX_RULE_FINDINGS",
    "WORKSPACE_SOURCE_KIND",
    "RuleScan",
    "is_relative_path",
    "project_rule_findings",
    "rule_text",
    "with_rule_coverage",
]
