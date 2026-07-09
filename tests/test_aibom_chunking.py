"""Tests for AIBOM inventory event chunking.

Large snapshots (e.g. Hermes with 486 items) exceed Cloudflare's 100s
origin timeout when sent as a single event.  _chunk_inventory_events
splits them into multiple smaller events.
"""

from __future__ import annotations

from codex_plugin_scanner.guard.aibom_cli import _chunk_inventory_events


def _make_event(snapshot_id: str, items: list[dict]) -> dict:
    """Build a minimal inventory snapshot event for testing."""
    return {
        "eventId": f"evt-{snapshot_id}",
        "eventType": "agent.inventory_snapshot",
        "idempotencyKey": snapshot_id,
        "occurredAt": "2026-07-09T18:00:00Z",
        "source": "edge",
        "workspaceId": "ws-test",
        "deviceId": None,
        "payload": {
            "snapshot": {
                "snapshotId": snapshot_id,
                "agentId": "hermes:local",
                "agentType": "hermes",
                "generatedAt": "2026-07-09T18:00:00Z",
                "items": items,
                "findings": [],
                "drift": [],
                "dockerProofs": [],
                "sources": [],
                "redactionReport": {"rawSecretsIncluded": False, "redactedFields": []},
            }
        },
    }


def _make_item(item_id: str) -> dict:
    return {
        "itemId": item_id,
        "itemKind": "skill",
        "displayName": item_id,
        "contentHash": f"hash-{item_id}",
        "sourceFingerprint": f"fp-{item_id}",
        "riskLevel": "unknown",
        "securityScore": 100,
        "driftState": "current",
        "metadata": {},
        "capabilityCategories": [],
        "scannerSources": [],
    }


class TestChunkInventoryEvents:
    """_chunk_inventory_events splits large events into item-level chunks."""

    def test_small_event_not_chunked(self):
        """An event with fewer items than the threshold stays as one event."""
        items = [_make_item(f"item-{i}") for i in range(10)]
        event = _make_event("snap-1", items)
        result = _chunk_inventory_events([event], max_items=100)
        assert len(result) == 1
        assert result[0]["idempotencyKey"] == "snap-1"

    def test_exact_threshold_not_chunked(self):
        """An event with exactly max_items items is not chunked."""
        items = [_make_item(f"item-{i}") for i in range(100)]
        event = _make_event("snap-1", items)
        result = _chunk_inventory_events([event], max_items=100)
        assert len(result) == 1

    def test_large_event_chunked(self):
        """An event with 486 items and max_items=100 produces 5 chunks."""
        items = [_make_item(f"item-{i}") for i in range(486)]
        event = _make_event("hermes:snapshot:test", items)
        result = _chunk_inventory_events([event], max_items=100)
        assert len(result) == 5  # ceil(486/100) = 5
        # Each chunk has at most 100 items
        for chunk in result:
            chunk_items = chunk["payload"]["snapshot"]["items"]
            assert len(chunk_items) <= 100
        # Last chunk has the remainder
        last_items = result[-1]["payload"]["snapshot"]["items"]
        assert len(last_items) == 86  # 486 - 400

    def test_chunked_events_have_unique_ids(self):
        """Each chunk gets a unique event_id and snapshot_id."""
        items = [_make_item(f"item-{i}") for i in range(250)]
        event = _make_event("snap-1", items)
        result = _chunk_inventory_events([event], max_items=100)
        assert len(result) == 3
        event_ids = {c["eventId"] for c in result}
        snapshot_ids = {c["idempotencyKey"] for c in result}
        assert len(event_ids) == 3
        assert len(snapshot_ids) == 3

    def test_chunked_snapshot_ids_have_suffix(self):
        """Chunked snapshot IDs include a -chunk-N-of-M suffix."""
        items = [_make_item(f"item-{i}") for i in range(250)]
        event = _make_event("hermes:snapshot:abc", items)
        result = _chunk_inventory_events([event], max_items=100)
        assert len(result) == 3
        assert result[0]["payload"]["snapshot"]["snapshotId"] == "hermes:snapshot:abc-chunk-1-of-3"
        assert result[1]["payload"]["snapshot"]["snapshotId"] == "hermes:snapshot:abc-chunk-2-of-3"
        assert result[2]["payload"]["snapshot"]["snapshotId"] == "hermes:snapshot:abc-chunk-3-of-3"

    def test_chunked_events_preserve_non_items_fields(self):
        """Chunked events keep findings, drift, sources, redactionReport."""
        items = [_make_item(f"item-{i}") for i in range(150)]
        event = _make_event("snap-1", items)
        event["payload"]["snapshot"]["findings"] = [{"findingId": "f1"}]
        event["payload"]["snapshot"]["sources"] = [{"sourceId": "s1"}]
        result = _chunk_inventory_events([event], max_items=100)
        assert len(result) == 2
        for chunk in result:
            snap = chunk["payload"]["snapshot"]
            assert snap["findings"] == [{"findingId": "f1"}]
            assert snap["sources"] == [{"sourceId": "s1"}]
            assert snap["agentId"] == "hermes:local"

    def test_mixed_events(self):
        """A mix of small and large events chunk correctly."""
        small = _make_event("small", [_make_item("a")])
        large = _make_event("large", [_make_item(f"i-{i}") for i in range(200)])
        result = _chunk_inventory_events([small, large], max_items=100)
        assert len(result) == 3  # 1 small + 2 large chunks

    def test_no_items_passes_through(self):
        """An event with empty items list passes through unchanged."""
        event = _make_event("empty", [])
        result = _chunk_inventory_events([event], max_items=100)
        assert len(result) == 1
        assert result[0]["payload"]["snapshot"]["items"] == []

    def test_all_items_preserved_across_chunks(self):
        """No items are lost during chunking."""
        original_items = [_make_item(f"item-{i}") for i in range(486)]
        event = _make_event("snap-1", original_items)
        result = _chunk_inventory_events([event], max_items=100)
        chunked_items = []
        for chunk in result:
            chunked_items.extend(chunk["payload"]["snapshot"]["items"])
        assert len(chunked_items) == 486
        original_ids = {item["itemId"] for item in original_items}
        chunked_ids = {item["itemId"] for item in chunked_items}
        assert original_ids == chunked_ids
