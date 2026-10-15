"""Advisory cache calls stay under the resident frame limits."""

from __future__ import annotations

import json

from codex_plugin_scanner.guard.store_advisory_cache import StoreAdvisoryCacheMixin, _advisory_batches


class _PagedStore(StoreAdvisoryCacheMixin):
    def __init__(self, rows: list[dict[str, object]], page_size: int) -> None:
        self.rows = rows
        self.page_size = page_size
        self.calls: list[dict[str, object]] = []

    def _native_store_call(self, method: str, args: dict[str, object]) -> object:
        self.calls.append(args)
        if method == "cache_advisories":
            return len(args["payloads"])
        after = args["after"]
        start = 0 if after is None else int(after["rowid"]) + 1
        end = len(self.rows) if args["limit"] is None else start + int(args["limit"])
        page = self.rows[start : min(end, start + self.page_size)]
        more = start + len(page) < min(end, len(self.rows))
        next_cursor = {"updated_at": "t", "rowid": start + len(page) - 1} if more else None
        return {"rows": page, "more": more, "next": next_cursor}


def _row(index: int) -> dict[str, object]:
    return {"publisher_key": f"k{index}", "payload_json": json.dumps({"n": index}), "updated_at": "t"}


def test_batches_keep_every_payload_in_order_under_the_budget() -> None:
    payloads = [json.dumps({"body": "x" * 300}) for _ in range(10)]
    batches = _advisory_batches(payloads, budget=1000)
    assert [payload for batch in batches for payload in batch] == payloads
    assert len(batches) > 1
    assert all(sum(len(json.dumps(payload)) for payload in batch) <= 1000 for batch in batches)
    assert _advisory_batches(["y" * 5000], budget=1000) == [["y" * 5000]]
    assert _advisory_batches([]) == [[]]


def test_cache_sums_counts_across_batches() -> None:
    store = _PagedStore([], page_size=1)
    assert store.cache_advisories([{"id": str(index), "body": "x" * 400_000} for index in range(6)], "now") == 6
    assert len(store.calls) > 1


def test_list_follows_pages_until_the_limit_or_the_end() -> None:
    store = _PagedStore([_row(index) for index in range(5)], page_size=2)
    assert [item["n"] for item in store.list_cached_advisories(limit=None)] == [0, 1, 2, 3, 4]
    assert [call["after"] for call in store.calls] == [
        None,
        {"updated_at": "t", "rowid": 1},
        {"updated_at": "t", "rowid": 3},
    ]
    store.calls.clear()
    assert [item["n"] for item in store.list_cached_advisories(limit=3)] == [0, 1, 2]
    assert store.calls == [{"limit": 3, "after": None}, {"limit": 1, "after": {"updated_at": "t", "rowid": 1}}]
    assert store.list_cached_advisories(limit=0) == []
