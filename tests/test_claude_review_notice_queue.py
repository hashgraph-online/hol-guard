"""The daemon queues a paused native review, and its Claude notice, in one resident store call."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_review_approval
from codex_plugin_scanner.guard.native_guard_store import GUARD_STORE_MAX_REQUEST_BYTES, NativeGuardStoreUnavailable
from codex_plugin_scanner.guard.native_hook_adapter import native_review_query
from codex_plugin_scanner.guard.store_approval_facade import StoreApprovalsMixin

_QUERY = {"envelope": {"harness": "claude-code"}, "request_id": "req-1"}


class _Request:
    def to_dict(self) -> dict[str, object]:
        return {"request_id": "req-1"}


class _Store(StoreApprovalsMixin):
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _native_store_call(self, method: str, args: dict[str, Any]) -> str:
        self.calls.append((method, dict(args)))
        return "req-1"


class _KeyedStore:
    def __init__(self, material: object) -> None:
        self.material = material
        self.created: list[bool] = []

    def _policy_integrity_secret_material(self, *, create: bool) -> object:
        self.created.append(create)
        if isinstance(self.material, Exception):
            raise self.material
        return self.material


class _RowStore(StoreApprovalsMixin):
    """A resident reply to a queue write that asks for the stored row back."""

    def __init__(self, reply: object) -> None:
        self.reply = reply
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.reads: list[str] = []

    def _native_store_call(self, method: str, args: dict[str, Any]) -> object:
        self.calls.append((method, dict(args)))
        return self.reply

    def get_approval_request(self, request_id: str, *, derive_scope: bool = True) -> dict[str, object]:
        self.reads.append(request_id)
        return {"request_id": request_id, "read": "separately"}


def test_a_claude_review_queues_with_its_notice_in_one_store_write() -> None:
    store = _RowStore({"request_id": "req-1", "row": {"request_id": "req-1"}})
    key = {"integrity_key_b64": "a2V5", "integrity_key_id": "kid"}
    hint = {"budget_ms": 500}
    assert store.queue_native_review(_QUERY, "now", hint=hint, claude_key=key) == {"request_id": "req-1"}
    # The key rides in the top-level args the request digest leaves out; the
    # resident builds the notice's facts from the query itself.
    ((method, args),) = store.calls
    assert method == "queue_native_review"
    args.pop("cwd")
    assert args == {
        "review": _QUERY,
        "hint": hint,
        "now": "now",
        "silent": False,
        "claude_notice": True,
        "integrity_key_b64": "a2V5",
        "integrity_key_id": "kid",
        "return_row": True,
    }


def test_other_reviews_keep_the_plain_queue_write() -> None:
    store = _Store()
    store.add_approval_request(_Request(), "now")  # type: ignore[arg-type]
    assert store.calls == [
        ("add_approval_request", {"request": {"request_id": "req-1"}, "now": "now", "prompt_shown": None})
    ]


def test_the_notice_key_is_read_for_the_store_call() -> None:
    store = _KeyedStore((b"\x09" * 32, "bound-key"))
    assert hook_native_review_approval._claude_notice_key(store, None) == {
        "integrity_key_b64": "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk",
        "integrity_key_id": "bound-key",
    }
    assert store.created == [True]


def test_a_review_without_an_integrity_key_queues_without_a_notice() -> None:
    for store in (_KeyedStore((None, None)), _KeyedStore(OSError("locked")), object()):
        assert hook_native_review_approval._claude_notice_key(store, None) is None


def test_a_spent_hook_deadline_skips_the_notice_key_read() -> None:
    store = _KeyedStore((b"\x09" * 32, "bound-key"))
    assert hook_native_review_approval._claude_notice_key(store, time.monotonic()) is None
    assert store.created == []


def test_a_review_is_queued_and_read_back_in_one_store_call() -> None:
    row = {"request_id": "req-1", "harness": "codex"}
    store = _RowStore({"request_id": "req-1", "row": row})
    assert store.queue_native_review(_QUERY, "now") == row
    assert store.reads == []
    ((method, args),) = store.calls
    assert method == "queue_native_review"
    assert (args["claude_notice"], args["return_row"]) == (False, True)
    assert "integrity_key_b64" not in args
    assert "cwd" in args


def test_a_silent_review_reads_back_in_its_daemon_write() -> None:
    store = _RowStore({"request_id": "req-1", "event_error": None, "row": {"request_id": "req-1"}})
    assert store.queue_native_review(_QUERY, "now", silent=True) == {"request_id": "req-1"}
    ((method, args),) = store.calls
    assert method == "queue_native_review"
    assert (args["silent"], args["return_row"]) == (True, True)
    assert store.reads == []


def test_the_hook_response_rendered_with_the_row_rides_on_it() -> None:
    respond = {"paused_review": {"reason": None}}
    store = _RowStore({"request_id": "req-1", "row": {"request_id": "req-1"}, "response": {"decision": "ask"}})
    assert store.queue_native_review(_QUERY, "now", respond=respond) == {
        "request_id": "req-1",
        "hook_response": {"decision": "ask"},
    }
    ((_method, args),) = store.calls
    assert args["respond"] == respond


def test_a_call_that_asks_for_no_response_sends_no_respond() -> None:
    store = _RowStore({"request_id": "req-1", "row": {"request_id": "req-1"}})
    assert store.queue_native_review(_QUERY, "now") == {"request_id": "req-1"}
    ((_method, args),) = store.calls
    assert "respond" not in args


def test_a_row_the_write_did_not_read_back_is_read_separately() -> None:
    store = _RowStore({"request_id": "req-1", "row_error": "native_guard_store_invalid"})
    assert store.queue_native_review(_QUERY, "now") == {"request_id": "req-1", "read": "separately"}
    assert store.reads == ["req-1"]


class _UnreadableRowStore(_RowStore):
    def get_approval_request(self, request_id: str, *, derive_scope: bool = True) -> dict[str, object]:
        self.reads.append(request_id)
        raise ValueError("approval scope unavailable")


def test_a_failed_read_back_never_queues_the_review_again() -> None:
    # The write committed; a failed separate read answers no row rather than
    # an error a caller could take for a failed write.
    store = _UnreadableRowStore({"request_id": "req-1", "row_error": "native_guard_store_invalid"})
    key = {"integrity_key_b64": "a2V5", "integrity_key_id": "kid"}
    assert store.queue_native_review(_QUERY, "now", claude_key=key) is None
    assert [method for method, _ in store.calls] == ["queue_native_review"]
    assert store.reads == ["req-1"]


def test_an_unseeded_codex_live_wait_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    wait = {"process": {"pid": 1, "startToken": "t"}, "timeout_seconds": 120, "workspace": None}
    store = _RowStore({"request_id": "req-1", "live_wait": "native_guard_store_invalid", "row": {}})
    with caplog.at_level(logging.WARNING):
        store.queue_native_review(_QUERY, "now", codex_live_wait=wait)
    assert "Codex live wait not resumable for req-1" in caplog.text
    assert store.calls[0][1]["codex_live_wait_facts"] == wait
    # A seeded wait, and a bridge that is no longer waiting, are expected.
    for live_wait in ("seeded", "not_live"):
        store = _RowStore({"request_id": "req-1", "live_wait": live_wait, "row": {}})
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            store.queue_native_review(_QUERY, "now", codex_live_wait=wait)
        assert "Codex live wait" not in caplog.text, live_wait


def test_a_queue_write_without_a_request_id_is_refused() -> None:
    from codex_plugin_scanner.guard.native_signal_projection import NativeSignalProjectionUnavailableError

    for reply in (None, "", "req-1", {"row": {}}):
        store = _RowStore(reply)
        with pytest.raises(NativeSignalProjectionUnavailableError):
            store.queue_native_review(_QUERY, "now")


class _RefusingStore:
    """A store whose queue call the resident refuses."""

    def queue_native_review(self, *_args: object, **_kwargs: object) -> dict[str, object]:
        error = NativeGuardStoreUnavailable("Guard store native runtime unavailable: rm -rf private-build")
        error.reason = "native_guard_store_review_request_refused"
        raise error


def test_a_refused_queue_is_logged_by_its_reason_code_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger=hook_native_review_approval.__name__):
        queued = hook_native_review_approval.queue_native_pre_tool_review(
            _RefusingStore(),
            harness="codex",
            payload={"tool_name": "Bash", "tool_input": {"command": "rm -rf private-build"}},
            native_result={"decision": "review", "reason": "Deletes files."},
            native_receipt=None,
            workspace=tmp_path,
            guard_home=tmp_path / "guard",
            exact_token=None,
            review_binding="binding-1",
            approval_center_url="http://127.0.0.1:4781",
            policy_binding_verified=True,
        )
    assert queued is None
    assert "native_guard_store_review_request_refused" in caplog.text
    assert "private-build" not in caplog.text


def test_a_review_query_leaves_room_for_the_store_call_around_it(tmp_path: Path) -> None:
    # A pass-through blob just under the adapter's own cap would push the store
    # call over its cap once the queue arguments wrap it; the query drops it.
    blob = "x" * (GUARD_STORE_MAX_REQUEST_BYTES - 16 * 1024)
    query = native_review_query(
        "codex",
        {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": blob},
        {"result": {"decision": "review"}, "request_id": "req-1"},
        workspace=tmp_path,
        home_dir=tmp_path,
    )
    assert len(json.dumps(query).encode("utf-8")) < GUARD_STORE_MAX_REQUEST_BYTES - 32 * 1024
