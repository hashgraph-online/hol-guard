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

    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    request = {"coverage": coverage, "results": [[detector, result] for detector, result in results]}
    try:
        answer = native_runner_authority("workspace_rule_findings", request)
    except NativeRunnerAuthorityError:
        answer = {}
    findings, merged = answer.get("findings"), answer.get("coverage")
    if isinstance(findings, list) and isinstance(merged, dict):
        return cast(list[dict[str, object]], findings), cast(dict[str, object], merged)
    # The findings are warnings that never block, so a runtime that cannot
    # check the replies costs only these detectors: none of their findings are
    # stored and each is reported not run, which leaves the run partial.
    detectors = [detector for detector, _ in results]
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
