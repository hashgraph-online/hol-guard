"""Shared projection for the native workspace rule detectors.

The native snapshot runs several rule checks over a worktree: agent skills,
project hook configuration, MCP configuration, agent plugins, CI workflows,
editor tasks and instruction files. Each replies in the same shape: a schema
tag, a status, scan counts, skipped counts, truncation reasons and a bounded
list of findings. The native ``workspace_rule_findings`` kind checks that
shape, copies each well-formed finding into the stored finding and records
each detector's coverage. A finding that does not match is dropped and leaves
the detector incomplete instead of silently complete.

Rule findings are dashboard warnings. They never block or ask.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast


def rule_findings(
    coverage: dict[str, object], results: Sequence[tuple[str, object]]
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """The well-formed findings of each ``(detector, result)`` and the coverage with each detector added.

    A ``None`` result is a runtime without the check, which leaves its
    detector not run.
    """

    batched = _checked(coverage, results)
    if batched is not None or len(results) < 2:
        return batched or _not_run(coverage, [detector for detector, _ in results])
    # One batch can fail where its parts would not, for example a reply over
    # the transport limit. Checking each detector alone keeps one oversized or
    # unreadable result from hiding the findings of the others.
    findings: list[dict[str, object]] = []
    for detector, result in results:
        checked = _checked(coverage, [(detector, result)])
        if checked is None:
            coverage = _not_run(coverage, [detector])[1]
            continue
        findings.extend(checked[0])
        coverage = checked[1]
    return findings, coverage


def _checked(
    coverage: dict[str, object], results: Sequence[tuple[str, object]]
) -> tuple[list[dict[str, object]], dict[str, object]] | None:
    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    request = {"coverage": coverage, "results": [[detector, result] for detector, result in results]}
    try:
        answer = native_runner_authority("workspace_rule_findings", request)
    except NativeRunnerAuthorityError:
        return None
    findings, merged = answer.get("findings"), answer.get("coverage")
    if isinstance(findings, list) and isinstance(merged, dict):
        return cast(list[dict[str, object]], findings), cast(dict[str, object], merged)
    return None


def _not_run(coverage: dict[str, object], detectors: list[str]) -> tuple[list[dict[str, object]], dict[str, object]]:
    """No findings, and each detector reported not run, which leaves the run partial.

    The findings are warnings that never block, so a runtime that cannot check
    the replies costs only these detectors.
    """

    reasons = coverage.get("reasons")
    reasons = [*(reasons if isinstance(reasons, list) else []), *(f"detector_not_run:{d}" for d in detectors)]
    previous = coverage.get("detectors")
    return [], {
        **coverage,
        "status": "partial" if reasons else "complete",
        "reasons": reasons,
        "detectors": {**(previous if isinstance(previous, dict) else {}), **dict.fromkeys(detectors, "not_run")},
    }


def project_rule_findings(detector: str, result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of one native rule result."""

    return rule_findings({}, [(detector, result)])[0]


def with_rule_coverage(detector: str, coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add one rule detector to a run's coverage."""

    return rule_findings(coverage, [(detector, result)])[1]


__all__ = ["project_rule_findings", "rule_findings", "with_rule_coverage"]
