"""HGP-170: outbox batching cannot starve eligible reviews."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.cloud_review_batching import (
    CloudReviewBatchLimits,
    CloudReviewEventTooLargeError,
    select_review_event_batch,
)
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request


def test_oldest_eligible_event_is_selected_first(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    for index in range(5):
        add_review_request(store, review_request(f"req-{index}"))
    now = "2099-01-01T00:00:00+00:00"
    oldest = store.list_ready_review_events(now=now, limit=2, newest_first=False)
    assert oldest
    assert oldest[0]["sequence"] == min(row["sequence"] for row in oldest)


def test_oversized_event_is_quarantined_with_reason() -> None:
    limits = CloudReviewBatchLimits(events=10, bytes=80)
    with pytest.raises(CloudReviewEventTooLargeError):
        select_review_event_batch(
            [{"eventId": "huge", "localStreamSequence": 1, "padding": "x" * 5000}],
            limits,
        )


def test_valid_prefix_continues_after_byte_cap() -> None:
    events = [{"eventId": f"e-{index}", "localStreamSequence": index + 1, "padding": "n"} for index in range(20)]
    selected = select_review_event_batch(events, CloudReviewBatchLimits(events=5, bytes=10_000))
    assert 1 <= len(selected) <= 5
    assert selected[0]["eventId"] == "e-0"
