"""Which Guard decisions a case actually drove.

A case is written to exercise a particular decision, but the bytes that reach
Guard are the model's choice. When the shape a case exists to test is one the
model may spell a dozen ways, a green run can mean "Guard stayed correct" or it
can mean "the model avoided the shape this time", and the evidence reads the
same either way.

A case may therefore declare the reason codes it exists to reach. The codes are
read back out of that run's own ``guard_observations``, so a declaration is
satisfied only by a live Guard decision in the evidence; nothing here can mark a
path covered without one. A case that would otherwise pass without reaching a
declared code is reported as ``not-exercised`` — the outcome the driver already
retries and, unretried, never counts as a pass — rather than as a quiet pass.

Every case reports its observed codes whether or not it declares any, so a
qualification can state the decisions its run actually reached.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from typing import Any

from .catalog import Scenario

# The one decision that hands the call to an execution route which answers
# separately: the admission hook requires an owner, and the owner's own result
# carries the code. The judge validates a row's ``reason_code`` and nothing
# else, so ``execution_reason_code`` is read only on a row whose validated
# reason code is this one. On any other row it is a field no proof stands
# behind, and a declaration must never be satisfied by one.
_EXECUTION_ROUTE_REASON = "native_bash_owner_required"


def _row_paths(row: Mapping[str, Any]) -> Iterator[str]:
    """The reason codes one Guard row proves, the decision's own code first."""
    reason = row.get("reason_code")
    if not isinstance(reason, str) or not reason:
        return
    yield reason
    execution = row.get("execution_reason_code")
    if reason == _EXECUTION_ROUTE_REASON and isinstance(execution, str) and execution:
        yield execution


def observed_paths(case: Mapping[str, Any]) -> list[str]:
    """Every Guard reason code this case's own evidence recorded, sorted."""
    rows = case.get("guard_observations") or ()
    if not isinstance(rows, Iterable):
        return []
    codes = {code for row in rows if isinstance(row, Mapping) for code in _row_paths(row)}
    return sorted(codes)


def case_coverage(scenario: Scenario, case: Mapping[str, Any]) -> dict[str, list[str]]:
    """What this case was written to reach, what it reached, and the gap.

    Lists, not tuples: this record is published inside the assessment and the
    judge recomputes it from the evidence to compare against the published JSON.
    """
    observed = observed_paths(case)
    declared = list(scenario.decision_paths)
    return {
        "declared": declared,
        "observed": observed,
        "missing": [code for code in declared if code not in observed],
    }


def unexercised_reason(coverage: Mapping[str, list[str]]) -> str:
    """Why a case that otherwise passed did not exercise what it was written for."""
    return "the run never reached the decision this case declares: " + ", ".join(coverage["missing"])


def profile_coverage(scenarios: Iterable[Scenario], completed: Mapping[str, Any]) -> dict[str, Any]:
    """Declared decision paths across a run, which cases reached theirs, and
    every decision code the run's own evidence recorded.

    ``completed`` maps a scenario id to its finished case record. A case that
    never ran is neither exercised nor unexercised here: ``case_coverage`` in
    the runner already lists what never executed. Observed codes aggregate
    across every completed case, declaring or not, so the run states the
    decisions it actually reached rather than only the ones it was written to.
    """
    declared, exercised, unexercised = [], [], []
    observed: set[str] = set()
    for scenario in scenarios:
        row = completed.get(scenario.id)
        if isinstance(row, Mapping):
            paths = (row.get("assessment") or {}).get("decision_paths") or {}
            codes = paths.get("observed")
            if isinstance(codes, list):
                observed.update(codes)
        if not scenario.decision_paths:
            continue
        declared.append(scenario.id)
        if not isinstance(row, Mapping):
            continue
        missing = (row.get("assessment") or {}).get("decision_paths", {}).get("missing") or []
        (unexercised if missing else exercised).append(
            {"id": scenario.id, "missing": list(missing)} if missing else scenario.id
        )
    return {
        "declaring_cases": declared,
        "exercised_cases": exercised,
        "unexercised_cases": unexercised,
        "observed_decisions": sorted(observed),
    }
