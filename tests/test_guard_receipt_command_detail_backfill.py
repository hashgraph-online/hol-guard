from __future__ import annotations

import base64
from datetime import datetime, timezone

from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.runtime import runner as guard_runner
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.runner import (
    _cloud_sync_receipt_payload,
    _receipt_sync_rows_with_command_detail_backfill,
)
from codex_plugin_scanner.guard.store import GuardStore


def _decode_transport_command(envelope: dict[str, object]) -> str | None:
    encoded = envelope.get("commandEncoded")
    if isinstance(encoded, str):
        padded = encoded + "=" * (-len(encoded) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    command = envelope.get("command")
    return command if isinstance(command, str) else None


def _store_command_receipt(
    store: GuardStore,
    *,
    receipt_id: str,
    policy_decision: str = "block",
) -> None:
    store.add_receipt(
        GuardReceipt(
            receipt_id=receipt_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            harness="codex",
            artifact_id=f"codex:tool-action:{receipt_id}",
            artifact_hash=f"hash-{receipt_id}",
            policy_decision=policy_decision,
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
            action_id=f"action-{receipt_id}",
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
        ),
    )


def test_command_detail_backfill_ignores_legacy_v1_completion_marker(tmp_path) -> None:
    store = GuardStore(tmp_path)
    _store_command_receipt(store, receipt_id="guard-receipt-backfill-v2")
    store.set_sync_payload(
        "cloud_receipt_command_detail_backfill_v1",
        {"level": "none", "updated_at": "2026-04-15T00:01:00Z", "complete": True},
        "2026-04-15T00:01:00Z",
    )

    rows, marker = _receipt_sync_rows_with_command_detail_backfill(
        store,
        receipts=[],
        redaction_level="none",
        synced_at="2026-04-15T00:02:00Z",
    )

    assert [row["receipt_id"] for row in rows] == ["guard-receipt-backfill-v2"]
    assert marker is not None
    assert marker["complete"] is True


def test_command_detail_backfill_replays_sandbox_required_receipts(tmp_path) -> None:
    store = GuardStore(tmp_path)
    _store_command_receipt(
        store,
        receipt_id="guard-receipt-sandbox-required",
        policy_decision="sandbox-required",
    )

    rows, marker = _receipt_sync_rows_with_command_detail_backfill(
        store,
        receipts=[],
        redaction_level="none",
        synced_at="2026-04-15T00:02:00Z",
    )

    assert [row["receipt_id"] for row in rows] == ["guard-receipt-sandbox-required"]
    assert marker is not None


def test_redaction_disabled_backfill_payload_keeps_review_command_detail(tmp_path) -> None:
    store = GuardStore(tmp_path)
    _store_command_receipt(store, receipt_id="guard-receipt-command-payload")
    receipt = store.get_receipt("guard-receipt-command-payload")
    assert receipt is not None

    payload = _cloud_sync_receipt_payload(
        receipt,
        device_id="device",
        device_name="Developer Mac",
        redaction_level="none",
    )

    envelope = payload["envelopeRedacted"]
    assert isinstance(envelope, dict)
    assert envelope["commandTransport"] == "base64url-v1"
    assert _decode_transport_command(envelope) == "cd repo && npx vitest run example.test.ts --reporter=verbose"


def test_command_detail_backfill_pages_historical_receipts(monkeypatch, tmp_path) -> None:
    store = GuardStore(tmp_path)
    for index in range(3):
        _store_command_receipt(
            store,
            receipt_id=f"guard-receipt-page-{index}",
        )

    monkeypatch.setattr(guard_runner, "_RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT", 2)

    first_rows, first_marker = _receipt_sync_rows_with_command_detail_backfill(
        store,
        receipts=[],
        redaction_level="none",
        synced_at="2026-07-02T00:00:00+00:00",
    )

    assert [row["receipt_id"] for row in first_rows] == ["guard-receipt-page-1", "guard-receipt-page-2"]
    assert first_marker is not None
    assert first_marker["queried"] == 2
    assert first_marker["receipts"] == 2
    assert first_marker["complete"] is False
    store.set_sync_payload("cloud_receipt_command_detail_backfill_v2", first_marker, "2026-07-02T00:00:00+00:00")

    second_rows, second_marker = _receipt_sync_rows_with_command_detail_backfill(
        store,
        receipts=[],
        redaction_level="none",
        synced_at="2026-07-02T00:01:00+00:00",
    )

    assert [row["receipt_id"] for row in second_rows] == ["guard-receipt-page-0"]
    assert second_marker is not None
    assert second_marker["queried"] == 1
    assert second_marker["receipts"] == 1
    assert second_marker["complete"] is True
