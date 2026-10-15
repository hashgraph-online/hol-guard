"""Retry a gate case once when the native review did not answer in time.

The gates review each case at the real hook budget. On a loaded CI runner a
case that spawns git subprocess work can miss that budget, and the hook then
fail-closes with ``native_pre_tool_unavailable``. That outcome says nothing
about the policy under test, so the gate re-runs the same payload once at the
same budget and judges the second answer. A case that is unavailable twice
still fails, and no other reason is retried.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable

UNAVAILABLE_REASON = "native_pre_tool_unavailable"


class NativeUnavailableRetryWarning(UserWarning):
    """A gate case was re-run after the native review missed its budget."""


def review_with_unavailable_retry(case_id: str, review: Callable[[], dict[str, object]]) -> dict[str, object]:
    result = review()
    if result.get("reason_code") != UNAVAILABLE_REASON:
        return result
    warnings.warn(
        f"{case_id}: native review unavailable at the hook budget; re-running once",
        NativeUnavailableRetryWarning,
        stacklevel=2,
    )
    retried = review()
    if retried.get("reason_code") == UNAVAILABLE_REASON:
        warnings.warn(
            f"{case_id}: native review unavailable on both attempts; the case fails",
            NativeUnavailableRetryWarning,
            stacklevel=2,
        )
    return retried
