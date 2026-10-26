"""Retry a gate case once when the native review did not answer in time.

The gates review each case at the real hook budget. On a loaded CI runner a
case that spawns git subprocess work can miss that budget, and the hook then
fail-closes without a policy answer. That outcome says nothing about the
policy under test, so the gate re-runs the same payload once at the same
budget and judges the second answer. A case that misses the budget twice
still fails, and no other reason is retried.

A missed budget surfaces under two reason codes. ``native_pre_tool_unavailable``
is the edge that never completed; ``native_review_deadline_exceeded`` is the
same miss caught one layer up, where the review was still running when the
deadline passed. Which of the two a loaded runner produces is a matter of
where the clock ran out, not of what the policy decided, so both are retried.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable

UNAVAILABLE_REASON = "native_pre_tool_unavailable"
REVIEW_DEADLINE_REASON = "native_review_deadline_exceeded"
# The hook reached its budget without a policy answer, however it was reported.
BUDGET_MISS_REASONS = frozenset({UNAVAILABLE_REASON, REVIEW_DEADLINE_REASON})


class NativeUnavailableRetryWarning(UserWarning):
    """A gate case was re-run after the native review missed its budget."""


def review_with_unavailable_retry(case_id: str, review: Callable[[], dict[str, object]]) -> dict[str, object]:
    result = review()
    if result.get("reason_code") not in BUDGET_MISS_REASONS:
        return result
    warnings.warn(
        f"{case_id}: native review unavailable at the hook budget; re-running once",
        NativeUnavailableRetryWarning,
        stacklevel=2,
    )
    retried = review()
    if retried.get("reason_code") in BUDGET_MISS_REASONS:
        warnings.warn(
            f"{case_id}: native review unavailable on both attempts; the case fails",
            NativeUnavailableRetryWarning,
            stacklevel=2,
        )
    return retried
