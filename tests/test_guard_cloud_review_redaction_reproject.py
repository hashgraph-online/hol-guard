"""HGP-173: redaction changes reproject pending Cloud Review requests."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.review_event_integrity import review_event_payload_digest
from codex_plugin_scanner.guard.runtime.cloud_review_event_projection import (
    build_cloud_review_event,
    project_cloud_review_event,
)
from codex_plugin_scanner.guard.runtime.runner import _persist_cloud_receipt_redaction_level
from codex_plugin_scanner.guard.store import GuardStore

_SECRET = "tokensecret123"
_NOW = "2026-09-17T12:00:00+00:00"


def _request() -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id="redact-pending",
        harness="codex",
        artifact_id="codex:project:redact-pending",
        artifact_name="Secret command",
        artifact_hash="hash-redact",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("shell_command",),
        source_scope="project",
        config_path="/workspace/config.toml",
        review_command="hol-guard approvals approve redact-pending",
        approval_url="http://127.0.0.1/requests/redact-pending",
        raw_command_text=f'curl -H "Bearer {_SECRET}" https://api.example.com/deploy',
        action_envelope_json={
            "action_type": "shell_command",
            "command": f'curl -H "Bearer {_SECRET}" https://api.example.com/deploy',
        },
        trigger_summary="Deploy",
        last_seen_at=_NOW,
    )


def _binding(store: GuardStore) -> dict[str, str]:
    store.set_sync_payload(
        "oauth_local_credentials",
        {"grant_id": "grant-1", "workspace_id": "workspace-1", "machine_id": "machine-1"},
        _NOW,
    )
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    return {
        "oauth_subject_hash": binding["oauth_subject_hash"],
        "workspace_id": binding["workspace_id"],
        "machine_id": binding["machine_id"],
        "machine_installation_id": binding["machine_installation_id"],
    }


def test_tightened_redaction_reprojects_pending_request_without_secret(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _binding(store)
    store.add_approval_request(_request(), _NOW)
    none_event = build_cloud_review_event(
        store.get_approval_request("redact-pending") or {},
        oauth=None,
        redaction_level="none",
        store=store,
        event_sequence=1,
    )
    assert none_event is not None
    assert _SECRET not in json.dumps(none_event)
    assert "curl" in str(none_event.get("rawCommand") or "")

    _persist_cloud_receipt_redaction_level(store, level="full", synced_at=_NOW)
    rows = store.list_ready_review_events(now=_NOW, limit=8, **binding)
    assert rows
    projected = project_cloud_review_event(
        store,
        outbox_row=rows[0],
        delivery_binding=binding,
        redaction_level="full",
        oauth=None,
    )
    assert projected is not None
    _sequence, event = projected
    dumped = json.dumps(event)
    assert _SECRET not in dumped
    assert event["rawCommand"] is None
    payload = json.loads(str(event["eventPayloadJson"]))
    snapshot = payload.get("requestSnapshot")
    assert isinstance(snapshot, dict)
    assert snapshot.get("raw_command_text") in {None, ""}
    assert _SECRET not in json.dumps(snapshot)


def test_user_facing_projection_errors_never_include_secret(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _binding(store)
    store.add_approval_request(_request(), _NOW)
    mismatched = {**binding, "workspace_id": "other-workspace"}
    rows = store.list_ready_review_events(now=_NOW, limit=8, **binding)
    assert rows
    result = project_cloud_review_event(
        store,
        outbox_row=rows[0],
        delivery_binding=mismatched,
        redaction_level="none",
        oauth=None,
    )
    assert result is None
    dumped = json.dumps(store.review_event_outbox_status(now=_NOW, **binding))
    assert _SECRET not in dumped


@pytest.mark.parametrize("level", ["none", "full"])
def test_projection_drops_private_snapshot_fields_and_hashes_transmitted_bytes(tmp_path: Path, level: str) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _binding(store)
    opaque_secret = "opaque-credential-b2e7"
    request = replace(
        _request(),
        scanner_evidence=({"apiKey": opaque_secret, "metadata": {"password": opaque_secret}},),
        decision_v2_json={"debug": {"Authorization": opaque_secret}},
        action_envelope_json={
            "action_type": "shell_command",
            "command": "echo test",
            "raw_payload_redacted": {"apiKey": opaque_secret, "nested": {"password": opaque_secret}},
        },
    )
    store.add_approval_request(request, _NOW)
    row = store.list_ready_review_events(now=_NOW, limit=1, **binding)[0]
    original_json = row["payload_json"]
    original_hash = row["payload_hash"]
    result = project_cloud_review_event(
        store, outbox_row=row, delivery_binding=binding, redaction_level=level, oauth=None
    )
    assert result is not None
    event = result[1]
    assert opaque_secret not in json.dumps(event)
    projected = json.loads(event["eventPayloadJson"])
    snapshot = projected["requestSnapshot"]
    assert "scanner_evidence_json" not in snapshot
    assert "decision_v2_json" not in snapshot
    assert "config_path" not in snapshot
    assert snapshot["oauth_source"] == "default"
    assert snapshot["request_id"] == event["localRequestId"]
    assert snapshot["harness"] == event["harnessId"]
    assert snapshot["policy_action"] == event["policyAction"]
    assert snapshot["recommended_scope"] == event["recommendedScope"]
    assert event["payloadHash"] == review_event_payload_digest(
        event["eventPayloadJson"],
        oauth_source="default",
        **binding,
    )
    stored = store.list_ready_review_events(now=_NOW, limit=1, **binding)[0]
    assert stored["payload_json"] == original_json
    assert stored["payload_hash"] == original_hash
    assert (
        project_cloud_review_event(
            store, outbox_row=stored, delivery_binding=binding, redaction_level=level, oauth=None
        )[1]["payloadHash"]
        == event["payloadHash"]
    )


def test_tightened_redaction_appends_fresh_snapshot_identity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _binding(store)
    _persist_cloud_receipt_redaction_level(store, level="none", synced_at=_NOW)
    store.add_approval_request(_request(), _NOW)
    before = store.list_ready_review_events(now=_NOW, limit=8, **binding)
    _persist_cloud_receipt_redaction_level(store, level="full", synced_at=_NOW)
    after = store.list_ready_review_events(now=_NOW, limit=8, **binding)
    assert len(after) == len(before) + 1
    assert after[-1]["event_type"] == "review.request.snapshot_requeued"
    assert after[-1]["event_id"] not in {row["event_id"] for row in before}
    assert after[-1]["request_sequence"] > before[-1]["request_sequence"]
    assert after[-1]["stream_sequence"] > before[-1]["stream_sequence"]
