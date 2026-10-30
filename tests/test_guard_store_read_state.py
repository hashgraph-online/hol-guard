"""Read marks travel in batches and pages that each fit one native store message."""

from __future__ import annotations

from collections.abc import Mapping

from codex_plugin_scanner.guard import store_read_state
from codex_plugin_scanner.guard.store_read_state import StoreReadStateMixin


class _FakeStore(StoreReadStateMixin):
    def __init__(self, pages: list[dict[str, object]] | None = None) -> None:
        self.pages = pages or []
        self.calls: list[tuple[str, dict[str, object]]] = []

    def _native_store_call(self, method: str, args: Mapping[str, object]) -> object:
        self.calls.append((method, dict(args)))
        return self.pages.pop(0) if method == "get_read_state" else None


def test_marks_go_in_batches_that_each_fit_one_message(monkeypatch) -> None:
    monkeypatch.setattr(store_read_state, "_BATCH_BYTES", 20)
    store = _FakeStore()
    store.mark_requests_read(["aaaa", "bbbb", "cccc", "dddd"])
    batches = [args["request_ids"] for _method, args in store.calls]
    assert batches == [["aaaa", "bbbb"], ["cccc", "dddd"]]
    assert len({args["now"] for _method, args in store.calls}) == 1


def test_no_marks_sends_nothing() -> None:
    store = _FakeStore()
    store.mark_requests_read([])
    assert store.calls == []


def test_a_read_follows_the_cursor_and_orders_marks_newest_first() -> None:
    store = _FakeStore(
        [
            {"marks": [["a", "t1"], ["b", "t3"]], "after": 2},
            {"marks": [["c", "t2"], ["d", "t1"]], "after": None},
        ]
    )
    assert store.get_read_state() == ["b", "c", "a", "d"]
    assert [args["after"] for _method, args in store.calls] == [None, 2]
