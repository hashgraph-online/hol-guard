"""The native store owns the rows behind the local Cloud Review settings page."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-09-28T00:10:00+00:00"
_BINDING = {"workspace_id": "ws-1", "oauth_source": "default"}


def test_an_empty_store_reads_an_idle_view(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    assert store.cloud_review_settings_state(binding=_BINDING) == {
        "sync": {},
        "sync_reconnect_required": False,
        "recovery_error": None,
    }


@pytest.mark.parametrize(
    ("row", "required"),
    [
        ({"state": "error", "last_error_code": "cloud_auth_expired"}, True),
        ({"state": "error", "last_error_code": "cloud_unreachable"}, False),
        ({"state": "error", "last_error_code": None, "last_error": "HTTP Error 401: Unauthorized"}, False),
        ({"state": "error", "last_error": "HTTP Error 401: Unauthorized"}, True),
        ({"state": "idle", "last_error_code": "cloud_connect_required"}, False),
    ],
)
def test_the_sync_row_decides_whether_sign_in_is_needed(tmp_path: Path, row: dict[str, object], required: bool) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload("guard_cloud_review_sync_state", row, _NOW)
    state = store.cloud_review_settings_state(binding=None)
    assert state["sync"] == row
    assert state["sync_reconnect_required"] is required


def test_the_recovery_error_counts_only_for_its_binding(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.record_cloud_review_recovery(binding=_BINDING, error="worker_refresh_failed", now=_NOW)

    assert store.get_sync_payload("guard_cloud_review_settings_recovery") == {
        "binding": _BINDING,
        "error": "worker_refresh_failed",
    }
    assert store.cloud_review_settings_state(binding=_BINDING)["recovery_error"] == "worker_refresh_failed"
    other = {**_BINDING, "workspace_id": "ws-2"}
    assert store.cloud_review_settings_state(binding=other)["recovery_error"] is None

    store.record_cloud_review_recovery(binding=_BINDING, error=None, now=_NOW)
    assert store.cloud_review_settings_state(binding=_BINDING)["recovery_error"] is None


def test_a_malformed_recovery_is_refused_without_a_write(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    with pytest.raises(ValueError, match="invalid_error"):
        store.record_cloud_review_recovery(binding=_BINDING, error="", now=_NOW)
    assert store.get_sync_payload("guard_cloud_review_settings_recovery") is None
