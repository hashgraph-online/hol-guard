"""Proposed control for rejecting mutable progress metadata before optional upload."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from tests.test_receipt_sync_authority import CURSOR, _candidate, _ready, _reply
from tests.test_receipt_upload_preparation import _body, _preparation, _request, _selected, _serialize


@pytest.mark.parametrize("kind", ["list", "dict"])
def test_mutable_backfill_metadata_cannot_escape_into_sent_progress(tmp_path: Path, kind: str) -> None:
    store, _ = _ready(tmp_path)
    rows = _selected(store)
    rows[0]["__command_detail_backfill"] = [] if kind == "list" else {}

    def serialize(batch: Sequence[Mapping[str, object]], level: str) -> list[dict[str, object]]:
        marker = batch[0]["__command_detail_backfill"]
        if isinstance(marker, list):
            marker.append("synthetic mutation")
        elif isinstance(marker, dict):
            marker["changed"] = True
        return _serialize(store, batch, level)

    preparation = _preparation(store, rows, serialize=serialize)
    request = _request()
    preparation.prepare(request)
    assert _body(request)["receipts"] == []
    assert preparation.sent_batch == ()
    assert preparation.attempt is not None and preparation.attempt.rows_sent == 0
    assert not preparation.attempt.optional_allowed
    result = preparation.complete(_reply(), candidate=_candidate(2))
    assert result is not None and not result.progress_committed
    assert store.get_sync_payload(CURSOR) is None
