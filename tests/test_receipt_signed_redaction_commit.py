"""A verified signed default remains consistent through the final receipt commit."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config as config_module
from tests.test_receipt_signed_redaction_default import _ready_store, _signed_level
from tests.test_receipt_sync_authority import CURSOR, NOW, _candidate, _reply
from tests.test_receipt_upload_preparation import _body, _preparation, _request, _selected


@pytest.mark.parametrize("signed_level", ["none", "partial"])
@pytest.mark.parametrize(
    "change", ["remove-default", "keep-explicit", "strengthen-local", "clear-source", "change-cursor"]
)
def test_signed_privacy_setting_is_rechecked_at_actual_receipt_commit(
    tmp_path: Path, signed_level: str, change: str
) -> None:
    store = _ready_store(tmp_path, local=signed_level)
    _signed_level(store, signed_level)
    rows = _selected(store)
    preparation = _preparation(store, rows, redaction_level=signed_level)
    request = _request()
    preparation.prepare(request)

    assert [row["receiptId"] for row in _body(request)["receipts"]] == [row["receipt_id"] for row in rows]
    assert preparation.attempt is not None
    assert preparation.attempt.optional_allowed and preparation.attempt.rows_sent == 2
    assert preparation.attempt.redaction_level == signed_level
    assert preparation.attempt.capture.preference_state.confirmed
    assert preparation.attempt.sent_revision == 1
    assert store.get_sync_payload(CURSOR) is None
    config_path = store.guard_home / "config.toml"
    if change == "remove-default":
        config_path.write_text("sync = true\ntelemetry = true\n", encoding="utf-8")
        assert config_module.load_guard_config(store.guard_home).receipt_redaction_level == "full"
    elif change == "strengthen-local":
        config_path.write_text('sync = true\ntelemetry = true\nreceipt_redaction_level = "full"\n', encoding="utf-8")
    elif change == "clear-source":
        store.clear_oauth_local_credentials()
    elif change == "change-cursor":
        store.set_sync_payload(CURSOR, {"last_rowid": 41, "synced_at": NOW}, NOW)

    candidate = _candidate(max(row["receipt_rowid"] for row in rows))
    result = preparation.complete(_reply(redaction="none"), candidate=candidate)

    if change == "clear-source":
        assert result is None
        assert store.get_sync_payload(CURSOR) is None
        return
    assert result is not None and result.preference_accepted and result.receipt_acknowledged
    if change in {"remove-default", "keep-explicit"}:
        assert result.progress_committed
        assert store.get_sync_payload(CURSOR) == {"last_rowid": candidate.cursor_rowid, "synced_at": NOW}
    else:
        assert not result.progress_committed
        expected = {"last_rowid": 41, "synced_at": NOW} if change == "change-cursor" else None
        assert store.get_sync_payload(CURSOR) == expected
