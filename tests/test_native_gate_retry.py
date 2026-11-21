from __future__ import annotations

import time

import pytest

from tests.native_gate_retry import (
    DAEMON_BUDGET_SECONDS,
    EXTENSION_TIMEOUT_REASON,
    GIT_CONTEXT_REASONS,
    REVIEW_DEADLINE_REASON,
    UNAVAILABLE_REASON,
    NativeUnavailableRetryWarning,
    RetryApprovals,
    review_with_unavailable_retry,
)

_UNAVAILABLE = {"decision": "deny", "reason_code": UNAVAILABLE_REASON}
_DEADLINE = {"decision": "deny", "reason_code": REVIEW_DEADLINE_REASON}
_EXTENSION_TIMEOUT = {"decision": "deny", "reason_code": EXTENSION_TIMEOUT_REASON}
_ALLOW = {"decision": "allow", "reason_code": "native_allow"}


def _scripted(*results: dict[str, object], deadlines: list[float | None] | None = None):
    calls: list[int] = []

    def review(deadline: float | None) -> dict[str, object]:
        calls.append(1)
        if deadlines is not None:
            deadlines.append(deadline)
        return results[len(calls) - 1]

    return review, calls


def test_answered_review_runs_once() -> None:
    review, calls = _scripted(_ALLOW)
    assert review_with_unavailable_retry("case", review) == _ALLOW
    assert len(calls) == 1


def test_other_denials_are_not_retried() -> None:
    denied = {"decision": "deny", "reason_code": "native_destructive_shell_command"}
    review, calls = _scripted(denied)
    assert review_with_unavailable_retry("case", review) == denied
    assert len(calls) == 1


@pytest.mark.parametrize("reason", sorted(GIT_CONTEXT_REASONS))
def test_a_git_context_hold_is_retried_once(reason: str) -> None:
    held = {"decision": "deny", "reason_code": reason}
    review, calls = _scripted(held, _ALLOW)
    with pytest.warns(NativeUnavailableRetryWarning, match="held on its configuration"):
        assert review_with_unavailable_retry("case", review) == _ALLOW
    assert len(calls) == 2


@pytest.mark.parametrize("reason", sorted(GIT_CONTEXT_REASONS))
def test_a_git_context_hold_is_retried_at_the_daemon_budget(reason: str) -> None:
    # The live hook hands this hold to the daemon with the bridge's longer budget, so
    # retrying it at the hook budget a loaded runner just missed would fail it again.
    deadlines: list[float | None] = []
    review, _ = _scripted({"decision": "deny", "reason_code": reason}, _ALLOW, deadlines=deadlines)
    started = time.monotonic()
    with pytest.warns(NativeUnavailableRetryWarning):
        review_with_unavailable_retry("case", review)
    first, retry = deadlines
    assert first is None
    assert retry is not None
    assert retry - started >= DAEMON_BUDGET_SECONDS - 0.5


def test_a_missed_budget_is_retried_at_the_hook_budget() -> None:
    deadlines: list[float | None] = []
    review, _ = _scripted(_UNAVAILABLE, _ALLOW, deadlines=deadlines)
    with pytest.warns(NativeUnavailableRetryWarning):
        review_with_unavailable_retry("case", review)
    assert deadlines == [None, None]


@pytest.mark.parametrize("reason", sorted(GIT_CONTEXT_REASONS))
def test_a_git_context_hold_on_both_attempts_is_the_answer(reason: str) -> None:
    held = {"decision": "deny", "reason_code": reason}
    review, calls = _scripted(held, held)
    with pytest.warns(NativeUnavailableRetryWarning, match="re-running once"):
        assert review_with_unavailable_retry("case", review) == held
    assert len(calls) == 2


def test_unavailable_then_answered_uses_the_second_result() -> None:
    review, calls = _scripted(_UNAVAILABLE, _ALLOW)
    with pytest.warns(NativeUnavailableRetryWarning, match="re-running once"):
        assert review_with_unavailable_retry("case", review) == _ALLOW
    assert len(calls) == 2


def test_unavailable_twice_stays_unavailable() -> None:
    review, calls = _scripted(_UNAVAILABLE, _UNAVAILABLE)
    with pytest.warns(NativeUnavailableRetryWarning, match="both attempts"):
        assert review_with_unavailable_retry("case", review)["reason_code"] == UNAVAILABLE_REASON
    assert len(calls) == 2


def test_review_deadline_is_retried_like_an_unavailable_edge() -> None:
    review, calls = _scripted(_DEADLINE, _ALLOW)
    with pytest.warns(NativeUnavailableRetryWarning, match="re-running once"):
        assert review_with_unavailable_retry("case", review) == _ALLOW
    assert len(calls) == 2


def test_review_deadline_twice_still_fails_the_case() -> None:
    review, calls = _scripted(_DEADLINE, _DEADLINE)
    with pytest.warns(NativeUnavailableRetryWarning, match="both attempts"):
        assert review_with_unavailable_retry("case", review)["reason_code"] == REVIEW_DEADLINE_REASON
    assert len(calls) == 2


def test_a_budget_miss_may_be_reported_either_way_across_the_two_attempts() -> None:
    review, calls = _scripted(_UNAVAILABLE, _DEADLINE)
    with pytest.warns(NativeUnavailableRetryWarning, match="both attempts"):
        assert review_with_unavailable_retry("case", review)["reason_code"] == REVIEW_DEADLINE_REASON
    assert len(calls) == 2


def test_an_extension_evaluation_timeout_is_retried() -> None:
    # The command extension pass spells a missed clock apart from a real
    # evaluation error for exactly this reason: on a loaded runner it says
    # nothing about the policy under test.
    review, calls = _scripted(_EXTENSION_TIMEOUT, _ALLOW)
    with pytest.warns(NativeUnavailableRetryWarning, match="re-running once"):
        assert review_with_unavailable_retry("case", review) == _ALLOW
    assert len(calls) == 2


def test_an_extension_evaluation_timeout_twice_still_fails_the_case() -> None:
    review, calls = _scripted(_EXTENSION_TIMEOUT, _EXTENSION_TIMEOUT)
    with pytest.warns(NativeUnavailableRetryWarning, match="both attempts"):
        assert review_with_unavailable_retry("case", review)["reason_code"] == EXTENSION_TIMEOUT_REASON
    assert len(calls) == 2


def test_an_extension_evaluation_failure_is_not_retried() -> None:
    # `_failed` is a command Guard could not model, not a busy machine. Judging
    # a second answer there would hide a real evaluation error.
    failed = {"decision": "deny", "reason_code": "native_command_extension_evaluation_failed"}
    review, calls = _scripted(failed)
    assert review_with_unavailable_retry("case", review) == failed
    assert len(calls) == 1


def test_on_retry_runs_once_before_the_second_attempt() -> None:
    seen: list[int] = []
    review, calls = _scripted(_UNAVAILABLE, _ALLOW)

    def record() -> None:
        seen.append(len(calls))

    with pytest.warns(NativeUnavailableRetryWarning):
        review_with_unavailable_retry("case", review, on_retry=record)
    assert seen == [1]


def test_on_retry_stays_silent_when_the_first_answer_is_a_policy_answer() -> None:
    seen: list[int] = []
    review, _ = _scripted(_ALLOW)
    review_with_unavailable_retry("case", review, on_retry=lambda: seen.append(1))
    assert seen == []


def test_on_retry_runs_once_even_when_both_attempts_miss_the_budget() -> None:
    seen: list[int] = []
    review, _ = _scripted(_UNAVAILABLE, _DEADLINE)
    with pytest.warns(NativeUnavailableRetryWarning):
        review_with_unavailable_retry("case", review, on_retry=lambda: seen.append(1))
    assert seen == [1]


class _Store:
    """Just the queue read ``RetryApprovals`` makes, over rows a test scripts."""

    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows

    def list_approval_requests(self, status: object = None, limit: int = 0) -> list[dict[str, object]]:
        return list(self.rows)


def _row(request_id: str, dedupe_count: int = 1) -> dict[str, object]:
    return {"request_id": request_id, "dedupe_count": dedupe_count}


@pytest.fixture
def judged_ids(monkeypatch: pytest.MonkeyPatch) -> list[set[str]]:
    """Record the baseline ``RetryApprovals`` hands the row reader, instead of redacting rows."""
    recorded: list[set[str]] = []

    def fake(store: object, known_ids: set[str]) -> list[dict[str, object]]:
        recorded.append(set(known_ids))
        return [row for row in store.rows if str(row["request_id"]) not in known_ids]  # type: ignore[attr-defined]

    monkeypatch.setattr("tests.native_gate_retry.approval_rows", fake)
    return recorded


def test_a_case_that_never_retried_judges_every_row_it_added(judged_ids: list[set[str]]) -> None:
    store = _Store([_row("old")])
    approvals = RetryApprovals(store)
    store.rows.append(_row("added"))
    assert [row["request_id"] for row in approvals.rows()] == ["added"]
    assert judged_ids == [{"old"}]
    assert approvals.set_aside == 0


def test_a_row_the_interrupted_attempt_queued_is_not_judged(judged_ids: list[set[str]]) -> None:
    store = _Store([_row("old")])
    approvals = RetryApprovals(store)
    # The missed budget queued a review before the hook's clock ran out.
    store.rows.append(_row("interrupted"))
    approvals.mark_retry()
    store.rows.append(_row("retried"))
    assert [row["request_id"] for row in approvals.rows()] == ["retried"]
    assert judged_ids == [{"old", "interrupted"}]
    assert approvals.set_aside == 1


def test_a_row_the_retry_deduplicated_onto_is_still_judged(judged_ids: list[set[str]]) -> None:
    store = _Store([_row("old")])
    approvals = RetryApprovals(store)
    store.rows.append(_row("shared"))
    approvals.mark_retry()
    # The retry reached the same review, so the store counted it onto the same row.
    store.rows[-1] = _row("shared", dedupe_count=2)
    assert [row["request_id"] for row in approvals.rows()] == ["shared"]
    assert judged_ids == [{"old"}]
    assert approvals.set_aside == 0
