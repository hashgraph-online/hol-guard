"""The local event log is read through the native store."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.store import GuardStore


def _log(store: GuardStore, rows: list[tuple[str, str, str]]) -> None:
    with sqlite3.connect(store.path) as connection:
        connection.executemany(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
            rows,
        )


def test_events_read_newest_first_with_their_stored_key_order(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    _log(
        store,
        [
            ("alpha", '{"z": 1, "a": 2}', "2026-11-22T00:00:00Z"),
            ("beta", "[1]", "2026-11-22T00:00:01Z"),
            ("alpha", '{"sequence": 3}', "2026-11-22T00:00:02Z"),
        ],
    )

    events = store.list_events()

    assert [event["event_name"] for event in events] == ["alpha", "beta", "alpha"]
    assert events[1]["payload"] == {}
    assert list(cast("dict[str, object]", events[2]["payload"])) == ["z", "a"]
    assert [event["payload"] for event in store.list_events(limit=1, event_name="alpha")] == [{"sequence": 3}]
    assert store.list_events(limit=0) == []


def test_a_log_larger_than_one_reply_is_read_across_pages(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    note = "x" * 200_000
    _log(store, [("alpha", json.dumps({"index": index, "note": note}), f"t{index:03d}") for index in range(30)])

    events = store.list_events(limit=1000)

    assert [cast("dict[str, object]", event["payload"])["index"] for event in events] == list(range(29, -1, -1))
    assert len(store.list_events(limit=12)) == 12
    assert len(store.list_events(limit=-1)) == 30


def test_events_after_an_id_can_be_limited_to_named_events(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    _log(
        store,
        [
            ("alpha", '{"k": 1}', "t1"),
            ("beta", '{"k": 2}', "t2"),
            ("gamma", '"text"', "t3"),
        ],
    )

    named = store.list_events_after(1, event_names=("beta", "gamma"))

    assert [event["event_name"] for event in named] == ["beta", "gamma"]
    assert named[0]["payload"] == {"k": 2}
    assert named[1]["payload"] == {}
    assert len(store.list_events_after(0, limit=2)) == 2


@pytest.mark.parametrize(
    "answer",
    [
        [],
        {"items": []},
        {"items": {}, "more": False},
        {"items": [], "more": 0},
        {"items": [{"event_id": 1}], "more": False},
        {
            "items": [{"event_id": True, "event_name": "a", "occurred_at": "t", "payload_json": "{}"}],
            "more": False,
        },
        {
            "items": [{"event_id": 1, "event_name": "a", "occurred_at": "t", "payload_json": {}}],
            "more": False,
        },
        {"items": [], "more": True},
    ],
)
def test_a_malformed_page_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    store = GuardStore(tmp_path)

    def native(method: str, _args: object, **_kwargs: Any) -> object:
        assert method == "list_events"
        return answer

    monkeypatch.setattr(store, "_native_store_call", native)

    with pytest.raises(RuntimeError, match="native list_events returned no answer"):
        store.list_events()


def test_the_next_page_starts_after_the_last_event_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    pages = iter(
        [
            {
                "items": [{"event_id": 9, "event_name": "a", "occurred_at": "t9", "payload_json": "{}"}],
                "more": True,
            },
            {
                "items": [{"event_id": 4, "event_name": "a", "occurred_at": "t4", "payload_json": "{}"}],
                "more": False,
            },
        ]
    )
    calls: list[object] = []

    def native(_method: str, args: dict[str, object], **_kwargs: Any) -> object:
        calls.append(dict(args))
        return next(pages)

    monkeypatch.setattr(store, "_native_store_call", native)

    assert [event["event_id"] for event in store.list_events(limit=5, event_name="a")] == [9, 4]
    assert calls == [
        {"limit": 5, "event_name": "a"},
        {"limit": 4, "event_name": "a", "before": {"occurred_at": "t9", "event_id": 9}},
    ]


def test_events_after_an_id_are_read_oldest_first_across_pages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    pages = iter(
        [
            {
                "items": [{"event_id": 3, "event_name": "a", "occurred_at": "t3", "payload_json": '{"k": 3}'}],
                "more": True,
            },
            {
                "items": [{"event_id": 8, "event_name": "a", "occurred_at": "t8", "payload_json": "[]"}],
                "more": False,
            },
        ]
    )
    calls: list[object] = []

    def native(method: str, args: dict[str, object], **_kwargs: Any) -> object:
        assert method == "list_events"
        calls.append(dict(args))
        return next(pages)

    monkeypatch.setattr(store, "_native_store_call", native)

    events = store.list_events_after(2, limit=5, event_names=("a",))

    assert [event["payload"] for event in events] == [{"k": 3}, {}]
    assert calls == [
        {"after_event_id": 2, "event_names": ["a"], "limit": 5},
        {"after_event_id": 3, "event_names": ["a"], "limit": 4},
    ]


def test_a_payload_too_large_for_one_reply_reads_as_empty(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    oversized = json.dumps({"note": '"' * 700_000})
    _log(
        store,
        [
            ("alpha", '{"k": 1}', "t1"),
            ("alpha", oversized, "t2"),
            ("alpha", '{"k": 3}', "t3"),
        ],
    )

    assert [event["payload"] for event in store.list_events()] == [{"k": 3}, {}, {"k": 1}]
    assert [event["payload"] for event in store.list_events_after(0)] == [{"k": 1}, {}, {"k": 3}]
