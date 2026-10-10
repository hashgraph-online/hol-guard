from __future__ import annotations

import copy
import hashlib
import json
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.memory_decision_event import MEMORY_DECISION_EVENT_CONTRACT_VERSION
from codex_plugin_scanner.guard.memory_decision_outbox import enqueue_memory_decision_event
from codex_plugin_scanner.guard.receipts.manager import build_receipt
from codex_plugin_scanner.guard.store import GuardStore


def _approval_request(
    *,
    request_id: str = "req-1",
    review_command: str = "npm install lodash",
    raw_command: str | None = "npm install lodash",
    artifact_id: str | None = "npm:lodash",
    artifact_name: str | None = "lodash",
    artifact_type: str | None = "package",
    harness: str = "codex",
) -> dict[str, object]:
    return {
        "request_id": request_id,
        "review_command": review_command,
        "raw_command_text": raw_command,
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "artifact_type": artifact_type,
        "harness": harness,
        "risk_summary": "Supply-chain install",
        "risk_signals": ["network_install", "filesystem_write"],
        "queue_group_id": "queue-1",
        "action_identity": "action-1",
    }


def _store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


def _seed_workspace(store: GuardStore) -> str:
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="demo-token",
        dpop_private_key_pem=None,  # type: ignore[arg-type]
        dpop_public_jwk=None,  # type: ignore[arg-type]
        dpop_public_jwk_thumbprint=None,  # type: ignore[arg-type]
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-07-07T00:00:00Z",
    )
    receipt = build_receipt(
        harness="codex",
        artifact_id="shell-command",
        artifact_hash="sha256:artifact",
        policy_decision="allow",
        capabilities_summary="shell",
        changed_capabilities=[],
        provenance_summary="local approval",
        artifact_name="Shell command",
        source_scope="project",
        approval_request_id="req-1",
        raw_command_text="npm install lodash",
    )
    store.add_receipt(receipt)
    return receipt.receipt_id


def _memory_events(store: GuardStore) -> list[dict[str, object]]:
    return [
        event
        for event in store.list_guard_events_v1(uploaded=False, limit=20)
        if event["event_type"] == "approval.memory_decision"
    ]


class TestMemoryDecisionOutboxEnqueue:
    def test_enqueue_writes_event_to_outbox(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        source_receipt_id = _seed_workspace(store)
        enqueued = enqueue_memory_decision_event(
            store,
            request=_approval_request(),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        assert enqueued is True
        events = _memory_events(store)
        assert len(events) == 1
        assert events[0]["event_type"] == "approval.memory_decision"
        payload = events[0]["payload"]
        assert isinstance(payload, dict)
        assert payload["eventType"] == "approval.memory_decision"
        assert payload["payload"]["decision_action"] == "approved"
        assert payload["payload"]["contractVersion"] == MEMORY_DECISION_EVENT_CONTRACT_VERSION
        assert payload["payload"]["device_id"] is not None
        assert payload["payload"]["machine_id"] is not None
        assert payload["payload"]["machine_installation_id"] is None
        assert payload["payload"]["source_receipt_id"] == source_receipt_id

    def test_enqueue_includes_project_identity_from_guard_operation(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        store.upsert_guard_session(
            session_id="session-1",
            harness="codex",
            surface="cli",
            status="active",
            client_name="codex",
            client_title=None,
            client_version=None,
            workspace=str(tmp_path),
            capabilities=[],
            now="2026-07-07T00:00:00Z",
        )
        store.upsert_guard_operation(
            operation_id="operation-1",
            session_id="session-1",
            harness="codex",
            operation_type="tool_call",
            status="waiting",
            approval_request_ids=["req-1"],
            resume_token=None,
            metadata={"project_id": "project-1", "workspace_path": str(tmp_path)},
            now="2026-07-07T00:00:00Z",
        )

        enqueued = enqueue_memory_decision_event(
            store,
            request=_approval_request(request_id="req-1"),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )

        assert enqueued is True
        payload = _memory_events(store)[0]["payload"]
        assert isinstance(payload, dict)
        assert payload["payload"]["project_id"] == "project-1"

    def test_enqueue_is_idempotent_by_request_action_time(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        for _ in range(3):
            enqueue_memory_decision_event(
                store,
                request=_approval_request(),
                action="allow",
                scope="harness",
                resolved_at="2026-07-07T00:00:00Z",
            )
        assert len(_memory_events(store)) == 1

    def test_block_and_allow_on_same_request_use_distinct_receipts(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        for action in ("allow", "block"):
            enqueue_memory_decision_event(
                store,
                request=_approval_request(),
                action=action,
                scope="harness",
                resolved_at="2026-07-07T00:00:00Z",
            )
        events = _memory_events(store)
        assert len(events) == 2
        source_receipt_ids = {
            event["payload"]["payload"]["source_receipt_id"] for event in events if isinstance(event["payload"], dict)
        }
        assert len(source_receipt_ids) == 2
        assert all(store.get_receipt(receipt_id) is not None for receipt_id in source_receipt_ids)

    def test_uses_first_matching_receipt_when_retries_share_a_request(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        first_receipt_id = _seed_workspace(store)
        retry_receipt = build_receipt(
            harness="codex",
            artifact_id="shell-command-retry",
            artifact_hash="sha256:retry",
            policy_decision="allow",
            capabilities_summary="shell",
            changed_capabilities=[],
            provenance_summary="retry",
            artifact_name="Shell command retry",
            source_scope="project",
            approval_request_id="req-1",
            raw_command_text="npm install other-package",
        )
        store.add_receipt(retry_receipt)

        assert enqueue_memory_decision_event(
            store,
            request=_approval_request(),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        payload = _memory_events(store)[0]["payload"]
        assert isinstance(payload, dict)
        assert payload["payload"]["source_receipt_id"] == first_receipt_id

    def test_enqueue_without_pattern_signal_keeps_receipt_lineage(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        request = _approval_request(
            request_id="req-no-signal",
            review_command="",
            raw_command=None,
            artifact_id=None,
            artifact_name=None,
        )
        assert enqueue_memory_decision_event(
            store,
            request=request,
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        payload = _memory_events(store)[0]["payload"]
        assert isinstance(payload, dict)
        assert payload["payload"]["memory_pattern_fingerprint"] is None
        assert store.get_receipt(payload["payload"]["source_receipt_id"]) is not None

    def test_enqueue_rejects_empty_request_id(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        request = _approval_request(request_id="")
        assert not enqueue_memory_decision_event(
            store,
            request=request,
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        assert _memory_events(store) == []

    def test_enqueue_creates_receipt_without_cloud_pairing(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        assert enqueue_memory_decision_event(
            store,
            request=_approval_request(),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        payload = _memory_events(store)[0]["payload"]
        assert isinstance(payload, dict)
        source_receipt_id = payload["payload"]["source_receipt_id"]
        assert store.get_receipt(source_receipt_id) is not None


def test_backlog_send_removes_source_when_current_native_disclosure_authority_is_unavailable(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime.runner import _receipt_disclosure_before_send

    store = _store(tmp_path)
    row = {
        "receipt_id": "old-workspace-memory",
        "approval_request_id": "old-native-request",
        "approval_source": "memory_decision",
        "source_scope": "workspace",
        "raw_command_text": "private original command",
    }
    request = urllib.request.Request(
        "http://127.0.0.1:4321/api/guard/receipts/sync",
        data=json.dumps(
            {
                "receipts": [
                    {
                        "receiptId": row["receipt_id"],
                        "envelopeRedacted": {"policyMemorySource": {"commandText": row["raw_command_text"]}},
                        "envelope_redacted": {"policyMemorySource": {"commandText": row["raw_command_text"]}},
                        "metadata": {"policyMemorySource": {"commandText": row["raw_command_text"]}},
                        "policyMemorySource": {"commandText": row["raw_command_text"]},
                    }
                ],
            }
        ).encode(),
        headers={"Authorization": "DPoP old-token"},
    )
    prepare = _receipt_disclosure_before_send(store, [row], "none")
    prepare(request)
    sent = json.loads(request.data)["receipts"][0]
    assert "policyMemorySource" not in sent
    for field in ("envelopeRedacted", "envelope_redacted", "metadata"):
        assert "policyMemorySource" not in sent[field]
    prepare(request)
    assert json.loads(request.data)["receipts"][0] == sent


def test_ordinary_allow_once_is_not_a_reusable_source_even_when_full_receipt_upload_is_enabled(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.memory_decision_outbox import policy_memory_source_for_receipt

    source = policy_memory_source_for_receipt(
        _store(tmp_path),
        {
            "approval_request_id": "ordinary",
            "approval_source": "local_approval",
            "source_scope": "once",
            "raw_command_text": "private original command",
        },
        redaction_level="none",
        access_token="current-token",
    )
    assert source is None


@pytest.mark.parametrize("revocation", ["consent", "token", "origin", "snapshot", "command", "resolution"])
def test_reusable_source_is_removed_on_retry_after_authority_changes(tmp_path, monkeypatch, revocation):
    from codex_plugin_scanner.guard import memory_decision_outbox as outbox
    from codex_plugin_scanner.guard.runtime import native_cloud_review_v4
    from codex_plugin_scanner.guard.runtime.native_cloud_review_origin import (
        NATIVE_CLOUD_REVIEW_ORIGIN_FIELD,
        NATIVE_CLOUD_REVIEW_ORIGIN_QUEUE_PREFIX,
    )
    from codex_plugin_scanner.guard.runtime.runner import _receipt_disclosure_before_send
    from tests.test_native_cloud_review_origin_projection import _source

    origin, native_receipt, _ = _source()
    command = "  printf 'private original action'  "
    origin["command_sha256"] = hashlib.sha256(command.encode()).hexdigest()
    binding = {"machine_id": "machine-1", "workspace_id": "workspace-1", "consent_revision": 3, "revocation_epoch": 1}
    envelope = {
        NATIVE_CLOUD_REVIEW_ORIGIN_FIELD: origin,
        "nativeApprovalChallenge": origin["challenge"],
        "native_origin_receipt": native_receipt,
        outbox.NATIVE_MEMORY_SOURCE_BINDING_FIELD: copy.deepcopy(binding),
    }
    saved = {
        "request_id": origin["request_id"],
        "request_kind": "reviewable_pause",
        "watch_only_observation": False,
        "queue_group_id": NATIVE_CLOUD_REVIEW_ORIGIN_QUEUE_PREFIX + origin["request_id"],
        "harness": native_receipt["harness"],
        "artifact_id": "shell-command",
        "raw_command_text": command,
        "status": "resolved",
        "resolution_action": "allow",
        "resolution_scope": "workspace",
        "action_envelope_json": json.dumps(envelope),
    }
    snapshot = copy.deepcopy(saved)
    credentials = {"token_type": "DPoP", "access_token": "current-token"}
    store = SimpleNamespace(
        guard_home=tmp_path,
        get_oauth_local_credentials=lambda **kwargs: credentials,
        get_approval_request=lambda request_id: saved,
        list_review_event_snapshots=lambda request_id: [snapshot],
    )
    monkeypatch.setattr(outbox, "native_memory_source_binding", lambda store: binding)
    current_origin = copy.deepcopy(origin)
    monkeypatch.setattr(native_cloud_review_v4, "get_native_approval_origin", lambda *args: current_origin)
    receipt = {
        "receipt_id": "source-receipt",
        "approval_request_id": origin["request_id"],
        "approval_source": "memory_decision",
        "source_scope": "workspace",
        "artifact_id": saved["artifact_id"],
        "harness": saved["harness"],
        "raw_command_text": command,
    }
    request = urllib.request.Request(
        "http://127.0.0.1:4321/api/guard/receipts/sync",
        data=json.dumps({"receipts": [{"receiptId": receipt["receipt_id"]}]}).encode(),
        headers={"Authorization": "DPoP current-token"},
    )
    prepare = _receipt_disclosure_before_send(store, [receipt], "none")
    prepare(request)
    disclosed = json.loads(request.data)["receipts"][0]["envelopeRedacted"]["policyMemorySource"]
    assert disclosed["commandText"] == command
    if revocation == "consent":
        binding["revocation_epoch"] = 2
    elif revocation == "token":
        credentials["access_token"] = "replacement-token"
    elif revocation == "origin":
        current_origin.pop("command_sha256")
    elif revocation == "snapshot":
        snapshot["action_envelope_json"] = json.dumps({**envelope, outbox.NATIVE_MEMORY_SOURCE_BINDING_FIELD: {}})
    elif revocation == "command":
        saved["raw_command_text"] = command.strip()
    else:
        saved["resolution_scope"] = "once"
    prepare(request)
    assert "policyMemorySource" not in json.loads(request.data)["receipts"][0]["envelopeRedacted"]
