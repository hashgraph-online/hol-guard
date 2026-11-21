"""A queue read survives one dropped resident round trip; a write never repeats."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from codex_plugin_scanner.guard.native_approval_scope import UNAVAILABLE as SCOPE_UNAVAILABLE
from codex_plugin_scanner.guard.native_approval_scope import ApprovalScopeUnavailableError
from codex_plugin_scanner.guard.native_guard_store import _unavailable
from codex_plugin_scanner.guard.store_approval_queries import StoreApprovalQueriesMixin


class _Store(StoreApprovalQueriesMixin):
    def __init__(self, answers: list[object]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    def _native_store_call(self, method: str, args: Mapping[str, object]) -> object:
        self.calls.append(method)
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def test_a_read_retries_one_dropped_round_trip() -> None:
    store = _Store([_unavailable("native_guard_store_unavailable"), 3])
    assert store._native_approval_read("count_approval_requests", {}) == 3
    assert store.calls == ["count_approval_requests", "count_approval_requests"]


def test_a_read_that_drops_twice_reads_as_unavailable() -> None:
    store = _Store([_unavailable("native_guard_store_unavailable")] * 2)
    with pytest.raises(ApprovalScopeUnavailableError):
        store._native_approval_read("list_approval_request_page", {})
    assert len(store.calls) == 2


def test_a_write_is_never_retried() -> None:
    store = _Store([_unavailable("native_guard_store_unavailable"), None])
    with pytest.raises(ApprovalScopeUnavailableError):
        store._native_approval_read("resolve_approval_request", {})
    assert store.calls == ["resolve_approval_request"]


def test_an_answered_refusal_is_not_retried() -> None:
    store = _Store([_unavailable("native_guard_store_response_invalid"), 3])
    with pytest.raises(ApprovalScopeUnavailableError):
        store._native_approval_read("count_approval_requests", {})
    assert store.calls == ["count_approval_requests"]


def test_a_scope_refusal_on_the_retry_reads_as_unavailable() -> None:
    store = _Store([_unavailable("native_guard_store_unavailable"), ValueError(SCOPE_UNAVAILABLE)])
    with pytest.raises(ApprovalScopeUnavailableError):
        store._native_approval_read("count_approval_requests", {})
    assert len(store.calls) == 2
