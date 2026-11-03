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
package's earlier finding is settled rather than carried. A package the new
run reports again is settled too: its new finding replaces the earlier one.

A package finding keeps the finding id the worktree's last run gave it, even
when that run named the package under an older identity scheme, so the
finding's history and its Cloud key stay with the package. Earlier runs also
named a scoped package without its scope, as ``traverse`` for
``@babel/traverse``. Such a finding still belongs to the scoped package while
no other package the run reports would take the bare name. The resident
decides both the ids a run keeps and which earlier packages it settled.

Carried findings come after the run's own findings and stop at the same
count and byte bounds. A finding that does not fit adds the
``carried_finding_cap`` reason: the run's own findings are still whole, so it
is not the run-wide ``finding_cap``.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Final

from .native_package_audit_projection import native_package_identities
from .store_workspace_assessment_schema import FINDINGS_BYTE_BUDGET, MAX_FINDINGS

if TYPE_CHECKING:
    from .workspace_assessment_store import RunOutcome

RECHECKED: Final = frozenset({"complete", "no_inputs"})
CARRIED_FINDING_CAP: Final = "carried_finding_cap"
# The supply chain detector's findings and coverage name it differently.
_COVERAGE_KEYS: Final = {"supply_chain_local_v1": "supply_chain"}


def carry_unchecked_findings(
    outcome: RunOutcome, previous: Mapping[str, object] | None, settled: Sequence[bool] = ()
) -> RunOutcome:
    """``outcome`` with the earlier findings its unfinished detectors could not recheck.

    ``previous`` is the worktree's last completed or partial run. A detector
    the new run no longer names was retired, so its findings are not kept.
    ``settled`` marks, by position, the earlier package findings the new
    audit reports again or no longer lists.
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
    for index, item in enumerate(earlier):
        if not isinstance(item, Mapping) or item.get("finding_id") in seen or _settled(settled, index):
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


def keep_package_identities(
    outcome: RunOutcome, previous: Mapping[str, object] | None, *, store: Any | None = None
) -> tuple[RunOutcome, list[bool]]:
    """``outcome`` with each package finding under the id ``previous`` gave that package.

    Also returns, by position in ``previous``, the earlier package findings
    the new run settled, for :func:`carry_unchecked_findings`.
    """

    earlier = previous.get("findings") if previous is not None else None
    if not isinstance(earlier, list):
        return outcome, []
    reports_packages = any(item.get("source_kind") == "supply_chain" for item in outcome.findings)
    if not any(_is_package(item) for item in earlier) or (outcome.state != "partial" and not reports_packages):
        # Nothing to rename and nothing to carry, so the resident is not asked.
        return outcome, [False] * len(earlier)
    finding_ids, settled = native_package_identities(outcome.findings, earlier, outcome.listed_packages, store=store)
    findings = [
        item if item.get("finding_id") == finding_id else {**item, "finding_id": finding_id}
        for item, finding_id in zip(outcome.findings, finding_ids, strict=True)
    ]
    if findings == list(outcome.findings):
        return outcome, settled
    return dataclasses.replace(outcome, findings=findings), settled


def _is_package(item: object) -> bool:
    return isinstance(item, Mapping) and item.get("source_kind") == "supply_chain"


def _settled(settled: Sequence[bool], index: int) -> bool:
    return index < len(settled) and settled[index]


def _size(item: Mapping[str, object]) -> int:
    return len(json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8")) + 1


__all__ = ["CARRIED_FINDING_CAP", "RECHECKED", "carry_unchecked_findings", "keep_package_identities"]
