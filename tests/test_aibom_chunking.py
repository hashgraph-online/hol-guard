"""Tests for atomic AIBOM inventory request batching."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.aibom_cli import (
    _AIBOM_MAX_REQUEST_BODY_BYTES,
    _batch_inventory_events,
    _inventory_events_request_body,
)


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


class TestBatchInventoryEvents:
    def test_486_item_snapshot_remains_atomic(self) -> None:
        items = [_make_item(f"item-{i}") for i in range(486)]
        event = _make_event("hermes:snapshot:test", items)

        batches = _batch_inventory_events([event])

        assert batches == [[event]]
        snapshot = batches[0][0]["payload"]["snapshot"]
        assert snapshot["snapshotId"] == "hermes:snapshot:test"
        assert len(snapshot["items"]) == 486

    def test_small_events_share_count_bounded_batch(self) -> None:
        events = [_make_event(f"snap-{index}", [_make_item(str(index))]) for index in range(4)]

        batches = _batch_inventory_events(events, max_batch_size=3)

        assert batches == [events[:3], events[3:]]

    def test_request_limit_splits_between_snapshots(self) -> None:
        first = _make_event("first", [_make_item("a")])
        second = _make_event("second", [_make_item("b")])
        single_body_limit = max(
            len(_inventory_events_request_body([first])),
            len(_inventory_events_request_body([second])),
        )

        batches = _batch_inventory_events(
            [first, second],
            max_body_bytes=single_body_limit,
        )

        assert batches == [[first], [second]]
        assert first["idempotencyKey"] == "first"
        assert second["idempotencyKey"] == "second"

    def test_default_request_limit_accepts_just_under_and_rejects_over(self) -> None:
        event = _make_event("boundary", [_make_item("boundary")])
        base_size = len(_inventory_events_request_body([event]))
        event["payload"]["snapshot"]["redactionReport"]["padding"] = "x" * (
            _AIBOM_MAX_REQUEST_BODY_BYTES - base_size - 64
        )
        under_limit_size = len(_inventory_events_request_body([event]))

        batches = _batch_inventory_events([event])

        assert _AIBOM_MAX_REQUEST_BODY_BYTES - 100 < under_limit_size <= _AIBOM_MAX_REQUEST_BODY_BYTES
        assert all(len(_inventory_events_request_body(batch)) <= _AIBOM_MAX_REQUEST_BODY_BYTES for batch in batches)

        event["payload"]["snapshot"]["redactionReport"]["padding"] += "x" * 101
        with pytest.raises(ValueError, match="snapshot exceeds"):
            _batch_inventory_events([event])

    def test_oversized_snapshot_fails_instead_of_splitting(self) -> None:
        event = _make_event("oversized", [_make_item("large")])
        body_size = len(_inventory_events_request_body([event]))

        with pytest.raises(ValueError, match="snapshot exceeds"):
            _batch_inventory_events([event], max_body_bytes=body_size - 1)

        assert event["payload"]["snapshot"]["snapshotId"] == "oversized"
        assert len(event["payload"]["snapshot"]["items"]) == 1

    def test_non_item_snapshot_fields_remain_on_atomic_event(self) -> None:
        event = _make_event("snap-1", [_make_item("item-1")])
        snapshot = event["payload"]["snapshot"]
        snapshot["findings"] = [{"findingId": "finding-1"}]
        snapshot["sources"] = [{"sourceId": "source-1"}]

        batches = _batch_inventory_events([event])

        assert batches[0][0]["payload"]["snapshot"] == snapshot

    @pytest.mark.parametrize("max_batch_size,max_body_bytes", [(0, 100), (1, 0)])
    def test_invalid_limits_are_rejected(self, max_batch_size: int, max_body_bytes: int) -> None:
        with pytest.raises(ValueError, match="limits must be positive"):
            _batch_inventory_events(
                [],
                max_batch_size=max_batch_size,
                max_body_bytes=max_body_bytes,
            )
