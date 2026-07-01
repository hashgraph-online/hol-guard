from __future__ import annotations

from datetime import datetime, timezone

from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.runner import (
    _RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER,
    _RELAXED_RECEIPT_REDACTION_RESYNC_MARKER,
    _ensure_relaxed_receipt_redaction_resync,
    _persist_cloud_receipt_redaction_level,
    _receipt_sync_cursor_rowids_from_batch,
    _receipt_sync_rows_with_command_detail_backfill,
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


def test_command_detail_backfill_rows_do_not_advance_receipt_cursor() -> None:
    rowids = _receipt_sync_cursor_rowids_from_batch(
        [
            {"receipt_id": "cursor-1", "receipt_rowid": 101},
            {"receipt_id": "backfill-1", "receipt_rowid": 5000},
            {"receipt_id": "cursor-2", "receipt_rowid": 102},
        ],
        cursor_receipt_ids={"cursor-1", "cursor-2"},
    )

    assert rowids == [101, 102]


def test_relaxed_redaction_sync_adds_recent_blocked_command_detail_backfill(tmp_path) -> None:
    store = GuardStore(tmp_path)
    store.add_receipt(
        GuardReceipt(
            receipt_id="guard-receipt-backfill",
            timestamp=datetime.now(timezone.utc).isoformat(),
            harness="codex",
            artifact_id="codex:tool-action:backfill",
            artifact_hash="hash-backfill",
            policy_decision="block",
            capabilities_summary="tool action request",
            changed_capabilities=(),
            provenance_summary="",
            user_override=None,
            artifact_name="bash",
            source_scope="project",
            diff_summary=None,
            approval_source=None,
            approval_request_id=None,
            scanner_evidence=(),
            browser_intent=None,
        ),
        action_envelope=GuardActionEnvelope(
            schema_version=1,
            action_id="action-backfill",
            harness="codex",
            event_name="PreToolUse",
            action_type="shell_command",
            workspace=None,
            workspace_hash="workspace",
            tool_name="bash",
            command="cd repo && npx vitest run example.test.ts --reporter=verbose",
            prompt_excerpt=None,
            prompt_text=None,
            target_paths=(),
            network_hosts=(),
            mcp_server=None,
            mcp_tool=None,
            package_manager=None,
            package_name=None,
            package_intent_kind=None,
            package_targets=(),
            pre_execution_result="block",
            script_name=None,
            raw_payload_redacted={},
        ),
    )

    rows, marker = _receipt_sync_rows_with_command_detail_backfill(
        store,
        receipts=[],
        redaction_level="partial",
        synced_at="2026-04-15T00:01:00Z",
    )

    assert [row["receipt_id"] for row in rows] == ["guard-receipt-backfill"]
    assert marker == {
        "level": "partial",
        "updated_at": "2026-04-15T00:01:00Z",
        "days": 7,
        "limit": 5000,
        "receipts": 1,
    }


def test_relaxed_redaction_command_detail_backfill_marker_prevents_repeat(tmp_path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(
        _RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER,
        {"level": "partial", "updated_at": "2026-04-15T00:01:00Z"},
        "2026-04-15T00:01:00Z",
    )

    rows, marker = _receipt_sync_rows_with_command_detail_backfill(
        store,
        receipts=[],
        redaction_level="partial",
        synced_at="2026-04-15T00:02:00Z",
    )

    assert rows == []
    assert marker is None


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
