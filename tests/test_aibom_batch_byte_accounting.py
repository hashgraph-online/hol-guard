"""Exact wire boundaries, custom serializers, and bounded serialization work."""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard import aibom_cli, aibom_sync


@pytest.mark.parametrize("text", ["", "plain", "☃", "😀", 'quote" slash\\ tab\t', "\x00\n", "é漢字"])
def test_default_byte_accounting_obeys_exact_utf8_wire_boundary(text: str) -> None:
    events: list[dict[str, object]] = [
        {"id": index, "value": text, "nested": {"metadata": [None, True, False, 1.25, {"雪": text}]}}
        for index in range(3)
    ]
    body_limit = len(aibom_cli._inventory_events_request_body(events[:2]))

    batches, oversized = aibom_cli._batch_inventory_events(events, max_body_bytes=body_limit)

    assert batches == [events[:2], events[2:]]
    assert not oversized
    assert len(aibom_cli._inventory_events_request_body(batches[0])) == body_limit
    assert [event for batch in batches for event in batch] == events
    assert batches[0][0] is events[0]
    for batch in batches:
        body = aibom_cli._inventory_events_request_body(batch)
        assert body == json.dumps({"events": batch}).encode("utf-8")
        assert len(body) <= body_limit

    batches, oversized = aibom_cli._batch_inventory_events(events, max_body_bytes=body_limit - 1)
    assert batches == [[event] for event in events]
    assert not oversized


def test_oversized_middle_snapshot_does_not_reset_valid_batch_or_provenance() -> None:
    events: list[dict[str, object]] = [
        {"id": 0, "metadata": {"provenance": "client_unverified"}},
        {"id": 1, "content": "x" * 2048},
        {"id": 2, "metadata": {"provenance": "client_unverified"}},
    ]
    valid = [events[0], events[2]]
    limit = len(aibom_cli._inventory_events_request_body(valid))

    batches, oversized = aibom_cli._batch_inventory_events(events, max_body_bytes=limit)

    assert batches == [valid]
    assert oversized == [events[1]]
    assert oversized[0] is events[1]
    assert json.loads(aibom_cli._inventory_events_request_body(batches[0]))["events"] == valid


def test_custom_request_serializer_retains_its_own_envelope_and_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    def custom(events: list[dict[str, object]]) -> bytes:
        # Different field, separators, encoding, and count-dependent padding.
        return ("prefix" * len(events)).encode() + json.dumps(
            {"rows": events}, ensure_ascii=False, separators=(",", ":")
        ).encode()

    events: list[dict[str, object]] = [{"id": index, "雪": "é😀"} for index in range(5)]
    limit = len(custom(events[:2]))
    monkeypatch.setattr(aibom_cli, "_inventory_events_request_body", custom)

    batches, oversized = aibom_cli._batch_inventory_events(events, max_body_bytes=limit)

    assert batches == [events[:2], events[2:4], events[4:]]
    assert not oversized
    assert all(len(custom(batch)) <= limit for batch in batches)


def test_batch_planning_serializes_each_snapshot_once(monkeypatch: pytest.MonkeyPatch) -> None:
    original = json.dumps
    serialized_event_ids: list[int] = []

    def counted(value: object, *args: object, **kwargs: object) -> str:
        if isinstance(value, dict) and isinstance(value.get("events"), list):
            serialized_event_ids.extend(event["id"] for event in value["events"])
        return original(value, *args, **kwargs)  # type: ignore[arg-type]

    events: list[dict[str, object]] = [{"id": index, "summary": "x" * 1024} for index in range(30)]
    monkeypatch.setattr(aibom_sync.json, "dumps", counted)

    batches, oversized = aibom_cli._batch_inventory_events(events)

    assert len(batches) == 10
    assert not oversized
    assert serialized_event_ids == list(range(30))


def test_empty_batch_does_not_invoke_replaced_serializer(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(_events: list[dict[str, object]]) -> bytes:
        raise AssertionError("empty input must not serialize")

    monkeypatch.setattr(aibom_cli, "_inventory_events_request_body", unexpected)
    assert aibom_cli._batch_inventory_events([]) == ([], [])
