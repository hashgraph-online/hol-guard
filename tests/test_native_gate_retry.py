from __future__ import annotations

import pytest

from tests.native_gate_retry import (
    EXTENSION_TIMEOUT_REASON,
    REVIEW_DEADLINE_REASON,
    UNAVAILABLE_REASON,
    NativeUnavailableRetryWarning,
    review_with_unavailable_retry,
)

_UNAVAILABLE = {"decision": "deny", "reason_code": UNAVAILABLE_REASON}
_DEADLINE = {"decision": "deny", "reason_code": REVIEW_DEADLINE_REASON}
_EXTENSION_TIMEOUT = {"decision": "deny", "reason_code": EXTENSION_TIMEOUT_REASON}
_ALLOW = {"decision": "allow", "reason_code": "native_allow"}


def _scripted(*results: dict[str, object]):
    calls: list[int] = []

    def review() -> dict[str, object]:
        calls.append(1)
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
