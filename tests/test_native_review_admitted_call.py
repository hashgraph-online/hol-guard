"""The approval witness is written only for a call let through on an approval."""

from __future__ import annotations

import sqlite3

from codex_plugin_scanner.guard.hook_review.hook_native_review_binding import admit_accepted_call

PAYLOAD = {"tool_call_id": "call-1", "tool_name": "bash", "tool_input": {"command": "ls -la"}}


class _Store:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[dict[str, object]] = []
        self._error = error

    def record_native_admitted_call(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        return True


def test_accepted_allow_records_the_exact_call() -> None:
    store = _Store()
    response = {"decision": "allow", "approval_reuse_status": "accepted"}
    assert admit_accepted_call(store, harness="omp", payload=PAYLOAD, response=response) is response
    assert len(store.calls) == 1
    assert store.calls[0]["harness"] == "omp"
    assert store.calls[0]["payload"] == PAYLOAD
    assert isinstance(store.calls[0]["now"], str)


def test_anything_but_an_accepted_allow_records_nothing() -> None:
    store = _Store()
    for response in (None, {"decision": "deny"}, {"decision": "allow", "approval_reuse_status": "pending"}):
        assert admit_accepted_call(store, harness="omp", payload=PAYLOAD, response=response) is response
    assert store.calls == []


def test_a_failed_write_keeps_the_approved_answer() -> None:
    response = {"decision": "allow", "approval_reuse_status": "accepted"}
    for error in (OSError("busy"), RuntimeError("native"), sqlite3.OperationalError("locked")):
        store = _Store(error)
        assert admit_accepted_call(store, harness="omp", payload=PAYLOAD, response=response) is response
    assert admit_accepted_call(object(), harness="omp", payload=PAYLOAD, response=response) is response
