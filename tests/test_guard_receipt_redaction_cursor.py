from __future__ import annotations

from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.runtime.runner import (
    _RELAXED_RECEIPT_REDACTION_RESYNC_MARKER,
    _ensure_relaxed_receipt_redaction_resync,
    _persist_cloud_receipt_redaction_level,
)
from codex_plugin_scanner.guard.store import GuardStore


def test_cloud_receipt_redaction_relaxation_resets_receipt_cursor_before_storing_level(tmp_path) -> None:
    store = GuardStore(tmp_path)
    writes: list[tuple[str, dict[str, object], str]] = []
    original_set_sync_payload = store.set_sync_payload

    def record_set_sync_payload(state_key: str, payload: dict[str, object], now: str) -> None:
        writes.append((state_key, payload, now))
        original_set_sync_payload(state_key, payload, now)

    store.set_sync_payload = record_set_sync_payload  # type: ignore[method-assign]
    original_set_sync_payload(
        "receipt_sync_cursor",
        {"last_rowid": 17, "synced_at": "2026-04-15T00:00:00Z"},
        "2026-04-15T00:00:00Z",
    )

    _persist_cloud_receipt_redaction_level(
        store,
        level="none",
        synced_at="2026-04-15T00:01:00Z",
    )

    assert [write[0] for write in writes] == [
        "receipt_sync_cursor",
        "cloud_receipt_redaction_level",
        _RELAXED_RECEIPT_REDACTION_RESYNC_MARKER,
    ]
    assert store.get_sync_payload("cloud_receipt_redaction_level") == {
        "level": "none",
        "updated_at": "2026-04-15T00:01:00Z",
    }
    assert store.get_sync_payload(_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER) == {
        "level": "none",
        "updated_at": "2026-04-15T00:01:00Z",
    }
    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 0,
        "synced_at": "2026-04-15T00:01:00Z",
        "reason": "cloud_receipt_redaction_level_relaxed",
        "receipt_redaction_level": "none",
    }


def test_cloud_receipt_redaction_tightening_keeps_receipt_cursor(tmp_path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(
        "cloud_receipt_redaction_level",
        {"level": "none", "updated_at": "2026-04-15T00:00:00Z"},
        "2026-04-15T00:00:00Z",
    )
    store.set_sync_payload(
        "receipt_sync_cursor",
        {"last_rowid": 17, "synced_at": "2026-04-15T00:00:00Z"},
        "2026-04-15T00:00:00Z",
    )

    _persist_cloud_receipt_redaction_level(
        store,
        level="full",
        synced_at="2026-04-15T00:01:00Z",
    )

    assert store.get_sync_payload("cloud_receipt_redaction_level") == {
        "level": "full",
        "updated_at": "2026-04-15T00:01:00Z",
    }
    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 17,
        "synced_at": "2026-04-15T00:00:00Z",
    }


def test_existing_relaxed_receipt_redaction_resets_cursor_once(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard.db")
    store.set_sync_payload(
        "cloud_receipt_redaction_level",
        {"level": "none", "updated_at": "2026-04-15T00:00:00Z"},
        "2026-04-15T00:00:00Z",
    )
    store.set_sync_payload(
        "receipt_sync_cursor",
        {"last_rowid": 42, "synced_at": "2026-04-15T00:00:00Z"},
        "2026-04-15T00:00:00Z",
    )

    _ensure_relaxed_receipt_redaction_resync(
        store,
        level="none",
        synced_at="2026-04-15T00:01:00Z",
    )

    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 0,
        "synced_at": "2026-04-15T00:01:00Z",
        "reason": "cloud_receipt_redaction_level_relaxed_existing",
        "receipt_redaction_level": "none",
    }
    assert store.get_sync_payload(_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER) == {
        "level": "none",
        "updated_at": "2026-04-15T00:01:00Z",
    }

    _ensure_relaxed_receipt_redaction_resync(
        store,
        level="none",
        synced_at="2026-04-15T00:02:00Z",
    )

    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 0,
        "synced_at": "2026-04-15T00:01:00Z",
        "reason": "cloud_receipt_redaction_level_relaxed_existing",
        "receipt_redaction_level": "none",
    }


def test_first_cloud_redaction_level_matches_relaxed_local_config_without_cursor_reset(tmp_path) -> None:
    store = GuardStore(tmp_path)
    update_guard_settings(tmp_path, {"receipt_redaction_level": "none"})
    store.set_sync_payload(
        "receipt_sync_cursor",
        {"last_rowid": 17, "synced_at": "2026-04-15T00:00:00Z"},
        "2026-04-15T00:00:00Z",
    )

    _persist_cloud_receipt_redaction_level(
        store,
        level="none",
        synced_at="2026-04-15T00:01:00Z",
    )

    assert store.get_sync_payload("cloud_receipt_redaction_level") == {
        "level": "none",
        "updated_at": "2026-04-15T00:01:00Z",
    }
    assert store.get_sync_payload("receipt_sync_cursor") == {
        "last_rowid": 17,
        "synced_at": "2026-04-15T00:00:00Z",
    }
