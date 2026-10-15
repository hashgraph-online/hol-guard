from __future__ import annotations

import pytest

from tests.native_gate_retry import (
    UNAVAILABLE_REASON,
    NativeUnavailableRetryWarning,
    review_with_unavailable_retry,
)

_UNAVAILABLE = {"decision": "deny", "reason_code": UNAVAILABLE_REASON}
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
