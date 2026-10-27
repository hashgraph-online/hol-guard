"""Keep an earlier finding listed until its detector checks the worktree again.

A partial run has at least one detector that did not finish: it was not run,
stopped at a limit, or could not read every file. Such a detector cannot show
that a risk an earlier run found has gone, so missing or partial data must not
quietly drop it. The finding stays in the new run with
``carried_from_run_id``, the run that last observed it, until the detector
completes again. A detector that completes, or finds nothing left to read,
settles every earlier finding of its own: one it no longer reports is gone.

The supply chain audit can read every dependency file and still miss some
advisory lookups. A package it no longer lists has left the worktree, so that
package's earlier finding is settled rather than carried.

Carried findings come after the run's own findings and stop at the same
count and byte bounds. A finding that does not fit adds the
``carried_finding_cap`` reason: the run's own findings are still whole, so it
is not the run-wide ``finding_cap``.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping
from typing import TYPE_CHECKING, Final

from .store_workspace_assessment_schema import FINDINGS_BYTE_BUDGET, MAX_FINDINGS

if TYPE_CHECKING:
    from .workspace_assessment_store import RunOutcome

RECHECKED: Final = frozenset({"complete", "no_inputs"})
CARRIED_FINDING_CAP: Final = "carried_finding_cap"
# The supply chain detector's findings and coverage name it differently.
_COVERAGE_KEYS: Final = {"supply_chain_local_v1": "supply_chain"}


def carry_unchecked_findings(outcome: RunOutcome, previous: Mapping[str, object] | None) -> RunOutcome:
    """``outcome`` with the earlier findings its unfinished detectors could not recheck.

    ``previous`` is the worktree's last completed or partial run. A detector
    the new run no longer names was retired, so its findings are not kept.
    """

    coverage = outcome.coverage or {}
    detectors = coverage.get("detectors")
    earlier = previous.get("findings") if previous is not None else None
    if outcome.state != "partial" or not isinstance(detectors, Mapping) or not isinstance(earlier, list):
        return outcome
    run_id = previous.get("run_id") if previous is not None else None
    findings = [dict(item) for item in outcome.findings]
    seen = {item.get("finding_id") for item in findings}
    used = sum(_size(item) for item in findings)
    carried = 0
    truncated = False
    for item in earlier:
        if not isinstance(item, Mapping) or item.get("finding_id") in seen or _package_gone(item, outcome):
            continue
        detector = item.get("detector")
        status = detectors.get(_COVERAGE_KEYS.get(detector, detector)) if isinstance(detector, str) else None
        if not isinstance(status, str) or status in RECHECKED:
            continue
        entry = {**item, "carried_from_run_id": item.get("carried_from_run_id") or run_id}
        size = _size(entry)
        if len(findings) >= MAX_FINDINGS or used + size > FINDINGS_BYTE_BUDGET:
            truncated = True
            continue
        findings.append(entry)
        seen.add(entry.get("finding_id"))
        used += size
        carried += 1
    if not carried and not truncated:
        return outcome
    reasons = coverage.get("reasons")
    reasons = [str(reason) for reason in reasons] if isinstance(reasons, list) else []
    if truncated and CARRIED_FINDING_CAP not in reasons:
        reasons.append(CARRIED_FINDING_CAP)
    return dataclasses.replace(
        outcome,
        coverage={**coverage, "reasons": reasons, "carried_findings": carried},
        findings=findings,
    )


def listed_packages(payload: Mapping[str, object]) -> frozenset[tuple[str, str, str]] | None:
    """The package coordinates a local audit read, as its findings name them.

    None when the audit stopped early or warned about a lockfile, since its
    package list may then be short.
    """

    evaluation = payload.get("evaluation")
    packages = evaluation.get("packages") if isinstance(evaluation, Mapping) else None
    stopped = payload.get("audit_status") == "incomplete" or payload.get("lockfile_warnings")
    if stopped or not isinstance(packages, list):
        return None
    return frozenset(
        (
            _text(package.get("ecosystem")) or "unknown",
            name,
            _text(package.get("resolvedVersion")) or _text(package.get("requestedVersion")) or "",
        )
        for package in packages
        if isinstance(package, Mapping) and (name := _text(package.get("name"))) is not None
    )


def _package_gone(item: Mapping[str, object], outcome: RunOutcome) -> bool:
    listed = outcome.listed_packages
    if listed is None or item.get("source_kind") != "supply_chain":
        return False
    coordinate = (item.get("ecosystem"), item.get("package_name"), item.get("package_version") or "")
    return coordinate not in listed


def _text(value: object) -> str | None:
    stripped = value.strip() if isinstance(value, str) else ""
    return stripped[:256] if stripped else None


def _size(item: Mapping[str, object]) -> int:
    return len(json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8")) + 1


__all__ = ["CARRIED_FINDING_CAP", "RECHECKED", "carry_unchecked_findings", "listed_packages"]
