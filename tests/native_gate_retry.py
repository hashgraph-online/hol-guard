"""Retry a gate case once when the native review did not answer in time.

The gates review each case at the real hook budget. On a loaded CI runner a
case that spawns git subprocess work can miss that budget, and the hook then
fail-closes without a policy answer. That outcome says nothing about the
policy under test, so the gate re-runs the same payload once at the same
budget and judges the second answer. A case that misses the budget twice
still fails, and no other reason is retried.

A missed budget surfaces under three reason codes. ``native_pre_tool_unavailable``
is the edge that never completed; ``native_review_deadline_exceeded`` is the
same miss caught one layer up, where the review was still running when the
deadline passed; ``native_command_extension_evaluation_timed_out`` is the miss
caught inside the command extension pass, which the runtime spells apart from
``native_command_extension_evaluation_failed`` precisely so a busy machine can
be told from a command Guard cannot model. Which of the three a loaded runner
produces is a matter of where the clock ran out, not of what the policy
decided, so all three are retried. The ``_failed`` spelling is a real
evaluation error and is never retried.

A Git read whose configuration probe ran out of time is held under the same
reason code as one whose checkout really runs a helper. The live hook sends
that hold on to the daemon's longer budget instead of showing it, so the gate
gives it the same single retry. A checkout that runs a helper is held on both
attempts and the case is judged on that second hold.
"""

from __future__ import annotations

import time
import warnings
from collections.abc import Callable
from typing import Any

from ci.gauntlet.approval_rows import approval_rows
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_failure_code

UNAVAILABLE_REASON = "native_pre_tool_unavailable"
REVIEW_DEADLINE_REASON = "native_review_deadline_exceeded"
EXTENSION_TIMEOUT_REASON = "native_command_extension_evaluation_timed_out"
# The hook reached its budget without a policy answer, however it was reported.
BUDGET_MISS_REASONS = frozenset({UNAVAILABLE_REASON, REVIEW_DEADLINE_REASON, EXTENSION_TIMEOUT_REASON})
# A Git read held because its configuration could not be settled, possibly in time.
GIT_CONTEXT_REASONS = frozenset({"native_git_execution_context_review", "native_git_helper_context_review"})
RETRIED_REASONS = BUDGET_MISS_REASONS | GIT_CONTEXT_REASONS


class NativeUnavailableRetryWarning(UserWarning):
    """A gate case was re-run after the native review missed its budget."""


def _timed(review: Callable[[], dict[str, object]]) -> tuple[dict[str, object], str]:
    started = time.monotonic()
    result = review()
    # The elapsed time and the client's failure code tell a missed budget from
    # a refusal when a case fails.
    return result, f"after {time.monotonic() - started:.2f}s, client failure {native_resident_client_failure_code()}"


def approval_snapshot(store: Any) -> dict[str, int]:
    """Every queued request id with the number of calls deduplicated onto it so far."""
    return {
        str(row.get("request_id")): int(row.get("dedupe_count") or 1)
        for row in store.list_approval_requests(status=None, limit=500)
    }


class RetryApprovals:
    """Judge a retried case on the rows its retry wrote, not the interrupted attempt's.

    A missed budget can still queue a review before the hook's clock runs out. That row
    answers the interrupted attempt, not the case: judging it fails a quiet case the retry
    allowed, and can rescue a block case the retry allowed. ``mark_retry`` records what the
    first attempt left behind, and ``rows`` then sets those aside. A row the retry
    deduplicated onto is the retry's own answer, so it stays and a real review is never
    hidden. Without a retry the baseline is unchanged, so an ordinary case judges every row
    it added.
    """

    def __init__(self, store: Any) -> None:
        self._store = store
        self.known = set(approval_snapshot(store))
        self._interrupted: dict[str, int] = {}
        self.set_aside = 0

    def mark_retry(self) -> None:
        self._interrupted = {
            request_id: count
            for request_id, count in approval_snapshot(self._store).items()
            if request_id not in self.known
        }

    def rows(self) -> list[dict[str, Any]]:
        if not self._interrupted:
            return approval_rows(self._store, self.known)
        current = approval_snapshot(self._store)
        stale = {
            request_id for request_id, count in self._interrupted.items() if current.get(request_id, count) == count
        }
        self.set_aside = len(stale)
        return approval_rows(self._store, self.known | stale)


def review_with_unavailable_retry(
    case_id: str,
    review: Callable[[], dict[str, object]],
    *,
    on_retry: Callable[[], None] | None = None,
) -> dict[str, object]:
    result, detail = _timed(review)
    reason = result.get("reason_code")
    if reason not in RETRIED_REASONS:
        return result
    missed = "a Git read held on its configuration" if reason in GIT_CONTEXT_REASONS else "native review unavailable"
    warnings.warn(
        f"{case_id}: {missed} at the hook budget ({detail}); re-running once",
        NativeUnavailableRetryWarning,
        stacklevel=2,
    )
    if on_retry is not None:
        # The caller judges approval rows, and the interrupted attempt may have queued one.
        on_retry()
    retried, detail = _timed(review)
    if retried.get("reason_code") in BUDGET_MISS_REASONS:
        warnings.warn(
            f"{case_id}: native review unavailable on both attempts ({detail}); the case fails",
            NativeUnavailableRetryWarning,
            stacklevel=2,
        )
    return retried
