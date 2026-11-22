"""The native store reads the Guard Cloud status rows in one snapshot."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_cloud_status_rows import CloudStatusRows

_NOW = "2026-09-28T00:10:00+00:00"


def test_an_empty_store_reads_empty_rows(tmp_path: Path) -> None:
    assert GuardStore(tmp_path).cloud_status_rows() == CloudStatusRows()


def test_stored_rows_come_back_and_rows_that_are_not_objects_read_as_empty(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload("alert_preferences", {"watchlistEnabled": True}, _NOW)
    store.set_sync_payload("runtime_session_summary", {"runtime_device_id": "device-1"}, _NOW)
    store.set_sync_payload("guard_events_v1_summary", {"accepted": 3}, _NOW)
    store.set_sync_payload("sync_summary", ["not", "an", "object"], _NOW)

    rows = store.cloud_status_rows()

    assert rows.alert_preferences == {"watchlistEnabled": True}
    assert rows.runtime_session_summary == {"runtime_device_id": "device-1"}
    assert rows.guard_events_v1_summary == {"accepted": 3}
    assert rows.sync_summary == {}


@pytest.mark.parametrize(
    ("key", "row", "expired"),
    [
        ("policy_bundle_last_error", {"reason": "auth_expired"}, True),
        ("headless_app_sync_summary", {"status": "auth_expired"}, True),
        ("guard_cloud_review_sync_state", {"state": "auth_expired"}, True),
        ("policy_bundle_last_error", {"reason": "network"}, False),
        ("headless_app_sync_summary", {"state": "auth_expired"}, False),
        ("sync_summary", {"status": "auth_expired"}, False),
    ],
)
def test_the_sign_in_rows_decide_whether_the_sign_in_expired(
    tmp_path: Path, key: str, row: dict[str, Any], expired: bool
) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(key, row, _NOW)
    assert store.cloud_status_rows().cloud_auth_expired is expired


def test_the_last_sync_time_falls_back_to_the_receipt_cursor(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload("receipt_sync_cursor", {"synced_at": "cursor-time"}, _NOW)
    assert store.cloud_status_rows().last_sync_at == "cursor-time"
    store.set_sync_payload("sync_summary", {"synced_at": "summary-time"}, _NOW)
    assert store.cloud_status_rows().last_sync_at == "summary-time"


def test_the_latest_cloud_sync_prefers_the_headless_app_summary(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload("sync_summary", {"synced_at": "receipts"}, _NOW)
    assert store.cloud_status_rows().latest_cloud_sync == {"synced_at": "receipts"}
    store.set_sync_payload("headless_app_sync_summary", {"status": "ok"}, _NOW)
    assert store.cloud_status_rows().latest_cloud_sync == {"status": "ok"}


def test_an_unreadable_answer_is_refused() -> None:
    with pytest.raises(RuntimeError, match="no answer"):
        CloudStatusRows.from_native({"rows": None})
