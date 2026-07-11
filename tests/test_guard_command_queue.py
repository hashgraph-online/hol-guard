from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import store as guard_store_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.daemon import client as daemon_client_module
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon.command_queue_worker import (
    CommandQueueWorker,
    start_command_queue_worker,
)
from codex_plugin_scanner.guard.review_contracts import (
    GuardReviewContractError,
    build_local_review_request_claim,
    guard_review_oauth_metadata,
    payload_hash_for_decision_memory_bundle,
    payload_hash_for_remote_approval_envelope,
    validate_remote_approval_request_binding,
    validated_remote_approval_envelope,
)
from codex_plugin_scanner.guard.runtime import (
    command_executors,
    command_queue,
    local_request_snapshots,
)
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.schemas.guard_event_v1 import GuardEventV1
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_review_signing_helpers import (
    REVIEW_SIGNING_KEY_ID,
    review_trusted_keyring_payload,
    review_verification_keys,
    sign_review_payload,
)


@pytest.fixture(autouse=True)
def _default_store_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux", raising=False)


class FakeStore:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.payloads: dict[str, dict[str, object] | list[object]] = {
            "policy_bundle_keyring": review_trusted_keyring_payload(),
        }

    def get_sync_payload(self, key: str) -> dict[str, object] | list[object] | None:
        return self.payloads.get(key)

    def set_sync_payload(self, key: str, payload: dict[str, object] | list[object], now: str) -> None:
        self.payloads[key] = payload

    def get_cloud_sync_profile(self) -> dict[str, str]:
        return {
            "auth_mode": "oauth",
            "sync_url": "https://hol.test/api/guard/receipts/sync",
            "workspace_id": "workspace-1",
        }

    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object]:
        return {
            "grant_id": "grant-1",
            "machine_id": "machine-1",
            "runtime_id": "runtime-1",
            "workspace_id": "workspace-1",
        }

    def get_or_create_installation_id(self) -> str:
        return "22222222-2222-4222-8222-222222222222"

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object]:
        return {
            "operation_id": request_id,
            "metadata": {"workspace_path": "/workspace/repo"},
        }

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        del request_id
        return None

    def claim_remote_once_receipt(
        self,
        receipt_id: str,
        *,
        request_id: str,
        claimed_at: str,
    ) -> bool:
        del receipt_id, request_id, claimed_at
        return True

    def release_remote_once_receipt(self, receipt_id: str) -> None:
        del receipt_id

    def list_policy_decisions(self, harness: str | None = None) -> list[dict[str, object]]:
        del harness
        return []

    def replace_remote_policies(
        self,
        decisions,
        generated_at: str,
        *,
        remote_write_authorized: bool = False,
    ) -> None:
        del decisions, generated_at, remote_write_authorized

    def list_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        limit: int | None = 50,
        cursor: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, object]]:
        del status, harness, limit, cursor, search
        return []


def _approval_request_row(
    request_id: str,
    *,
    artifact_id: str = "plugin:hol/deploy",
    artifact_hash: str = "b" * 64,
    harness: str = "cursor",
    policy_action: str = "require-reapproval",
    recommended_scope: str = "artifact",
) -> dict[str, object]:
    return {
        "request_id": request_id,
        "status": "pending",
        "harness": harness,
        "artifact_id": artifact_id,
        "artifact_hash": artifact_hash,
        "policy_action": policy_action,
        "recommended_scope": recommended_scope,
        "created_at": "2026-05-14T11:58:00.000Z",
        "last_seen_at": "2026-05-14T11:59:00.000Z",
        "queue_group_id": "queue-group-1",
        "action_envelope_json": {
            "action_type": "shell_command",
            "command": "cat /workspace/repo/.npmrc",
            "tool_name": "Bash",
        },
    }


def _signed_remote_approval(
    store: FakeStore,
    request_row: dict[str, object],
    *,
    decision: str = "allow_once",
    receipt_id: str = "cloud-receipt-1",
    issued_at: datetime | None = None,
    include_key_id: bool = True,
    scope: str | None = None,
) -> dict[str, object]:
    oauth = guard_review_oauth_metadata(store)
    claim = build_local_review_request_claim(
        request_row=request_row,
        oauth=oauth,
        store=store,
    )
    issued_at = issued_at or datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = issued_at + timedelta(minutes=5)
    envelope = {
        "actionEnvelopeHash": claim["actionEnvelopeHash"],
        "approvalId": claim["approvalId"],
        "capabilityCategory": claim["capabilityCategory"],
        "contractVersion": "guard.remote-approval.v1",
        "decision": decision,
        "decisionId": receipt_id,
        "deviceId": claim["deviceId"],
        "expiresAt": expires_at.isoformat(),
        "harnessId": claim["harnessId"],
        "issuedAt": issued_at.isoformat(),
        "localRequestId": claim["localRequestId"],
        "machineId": claim["machineId"],
        "machineInstallationId": claim["machineInstallationId"],
        "nonce": f"{claim['nonce']}:{receipt_id}",
        "policyVersion": claim["policyVersion"],
        "projectIdentity": claim["projectIdentity"],
        "receiptId": receipt_id,
        "reviewerRole": "workspace-owner",
        "reviewerUserId": "user-1",
        "riskCategory": claim["riskCategory"],
        "runtimeGrantId": claim["runtimeGrantId"],
        "scope": scope if scope is not None else str(request_row.get("recommended_scope") or "artifact"),
        "sourceClaimHash": claim["claimHash"],
        "stepUpChallengeId": None,
        "workspaceId": claim["workspaceId"],
        "verificationKeys": review_verification_keys(),
        "signatureAlgorithm": "rsa-pss-sha256",
    }
    if include_key_id:
        envelope["keyId"] = REVIEW_SIGNING_KEY_ID
    envelope["payloadHash"] = payload_hash_for_remote_approval_envelope(envelope)
    envelope["signature"] = sign_review_payload(envelope)
    return envelope


def _signed_decision_memory_bundle(
    store: FakeStore,
    *,
    rule_scope: str = "workspace",
    action: str = "allow",
    rule_id: str = "review-memory:receipt-1",
    policy_version: str = "policy-version-2",
) -> dict[str, object]:
    oauth = guard_review_oauth_metadata(store)
    issued_at = datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = issued_at + timedelta(days=30)
    bundle = {
        "blastRadius": {
            "artifactCount": 1,
            "machineCount": 1,
            "workspaceCount": 1,
        },
        "bundleVersion": rule_id,
        "contractVersion": "guard.decision-memory-bundle.v1",
        "expiresAt": expires_at.isoformat(),
        "issuedAt": issued_at.isoformat(),
        "issuerKeyId": REVIEW_SIGNING_KEY_ID,
        "memoryRules": [
            {
                "action": action,
                "approvalId": "approval-1",
                "artifactHash": "b" * 64,
                "artifactId": "plugin:hol/deploy",
                "capabilityCategory": "tool-call",
                "expiresAt": expires_at.isoformat(),
                "harnessId": "cursor",
                "projectIdentity": "project:/workspace/repo",
                "reason": "Approved in cloud.",
                "recommendedScope": "artifact",
                "riskCategory": "medium",
                "ruleId": rule_id,
                "scope": rule_scope,
                "sourceReceiptIds": ["receipt-1"],
                "target": {
                    "machineIds": [oauth.installation_id],
                    "workspaceIds": [oauth.workspace_id],
                },
            }
        ],
        "policyVersion": policy_version,
        "revocations": [],
        "scope": "workspace",
        "scopeEvidence": {
            "approvalIds": ["approval-1"],
            "sourceReceiptHashes": ["c" * 64],
            "sourceReceiptIds": ["receipt-1"],
        },
        "verificationKeys": review_verification_keys(),
        "signatureAlgorithm": "rsa-pss-sha256",
        "workspaceId": oauth.workspace_id,
    }
    payload_hash = payload_hash_for_decision_memory_bundle(bundle)
    bundle["bundleHash"] = payload_hash
    bundle["payloadHash"] = payload_hash
    bundle["signature"] = sign_review_payload(bundle)
    return bundle


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path,
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )


def _oauth_store(tmp_path: Path) -> GuardStore:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        supply_chain_entitlement_expires_at="2026-07-01T00:00:00+00:00",
        supply_chain_firewall=True,
        supply_chain_plan_id="team",
        now="2026-06-13T00:00:00+00:00",
    )
    return store


def test_remote_approval_rejects_queue_admission_after_expiry(tmp_path: Path) -> None:
    store = FakeStore(tmp_path / "guard-home")
    request_row = _approval_request_row("request-expired")
    envelope = _signed_remote_approval(
        store,
        request_row,
        issued_at=datetime(2026, 6, 12, tzinfo=timezone.utc),
    )

    with pytest.raises(GuardReviewContractError, match="remote_approval_expired"):
        validated_remote_approval_envelope(
            envelope,
            store=store,
            admitted_at="2026-06-12T00:06:00+00:00",
        )


def test_guard_review_oauth_metadata_prefers_explicit_device_id(tmp_path: Path) -> None:
    class DeviceStore(FakeStore):
        def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object]:
            del allow_primary
            return {
                "device_id": "device-9",
                "grant_id": "grant-1",
                "machine_id": "machine-1",
                "runtime_id": "runtime-1",
                "workspace_id": "workspace-1",
            }

    oauth = guard_review_oauth_metadata(DeviceStore(tmp_path / "guard-home"))

    assert oauth.device_id == "device-9"
    assert oauth.machine_id == "machine-1"


def test_local_request_snapshot_items_continues_without_oauth_metadata(tmp_path: Path) -> None:
    class MissingOauthStore(FakeStore):
        def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object]:
            del allow_primary
            return {}

        def list_approval_requests(
            self,
            *,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
            search: str | None = None,
        ) -> list[dict[str, object]]:
            del harness, limit, cursor, search
            if status == "pending":
                return [_approval_request_row("req-no-oauth")]
            return []

    snapshot = command_executors._local_request_snapshot_items(MissingOauthStore(tmp_path / "guard-home"))

    assert len(snapshot) == 1
    assert snapshot[0]["localRequestId"] == "req-no-oauth"
    assert snapshot[0]["claim"] is None


def test_local_request_snapshot_payload_includes_complete_pending_backlog(tmp_path: Path) -> None:
    class ManyPendingStore(FakeStore):
        def list_approval_requests(
            self,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
        ) -> list[dict[str, object]]:
            del harness, cursor
            if status == "pending":
                rows = [_approval_request_row(f"req-pending-{index}") for index in range(125)]
            elif status == "resolved":
                rows = [
                    {
                        **_approval_request_row(f"req-resolved-{index}"),
                        "status": "resolved",
                        "resolved_at": "2026-07-02T12:00:00+00:00",
                    }
                    for index in range(3)
                ]
            else:
                rows = []
            return rows if limit is None else rows[:limit]

    payload = command_executors._local_request_snapshot_payload(ManyPendingStore(tmp_path / "guard-home"))

    assert payload["pendingComplete"] is True
    assert payload["resolvedComplete"] is True
    assert payload["pendingCount"] == 125
    assert payload["resolvedCount"] == 3
    assert len(payload["requests"]) == 128
    assert {item["localRequestId"] for item in payload["requests"]} >= {
        "req-pending-0",
        "req-pending-124",
        "req-resolved-2",
    }


def test_local_request_snapshot_payload_includes_resolution_memory_fields(tmp_path: Path) -> None:
    class ResolvedDecisionStore(FakeStore):
        def list_approval_requests(
            self,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
        ) -> list[dict[str, object]]:
            del harness, cursor
            if status != "resolved":
                return []
            rows = [
                {
                    **_approval_request_row("req-resolved-memory"),
                    "resolution_action": "allow",
                    "resolution_scope": "project",
                    "resolved_at": "2026-07-02T12:00:00+00:00",
                    "status": "resolved",
                },
            ]
            return rows if limit is None else rows[:limit]

    payload = command_executors._local_request_snapshot_payload(ResolvedDecisionStore(tmp_path / "guard-home"))

    [request] = payload["requests"]
    assert request["localRequestId"] == "req-resolved-memory"
    assert request["requestPayload"]["resolution_action"] == "allow"
    assert request["requestPayload"]["resolution_scope"] == "project"


def test_local_request_snapshot_payload_marks_pending_incomplete_when_truncated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(command_executors, "LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT", 2)

    class TruncatedPendingStore(FakeStore):
        def list_approval_requests(
            self,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
        ) -> list[dict[str, object]]:
            del harness, cursor
            if status != "pending":
                return []
            rows = [_approval_request_row(f"req-pending-{index}") for index in range(3)]
            return rows if limit is None else rows[:limit]

    payload = command_executors._local_request_snapshot_payload(TruncatedPendingStore(tmp_path / "guard-home"))

    assert payload["pendingComplete"] is False
    assert payload["resolvedComplete"] is True
    assert payload["pendingCount"] == 2
    assert [item["localRequestId"] for item in payload["requests"]] == [
        "req-pending-0",
        "req-pending-1",
    ]


def test_local_request_snapshot_payload_keeps_pending_complete_when_resolved_truncated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StatusSplitStore(FakeStore):
        def list_approval_requests(
            self,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
        ) -> list[dict[str, object]]:
            del harness, cursor
            if status == "pending":
                rows = [_approval_request_row("req-pending-0")]
            elif status == "resolved":
                rows = [
                    {
                        **_approval_request_row("req-resolved-0"),
                        "status": "resolved",
                        "resolved_at": "2026-07-02T12:00:00+00:00",
                        "action_envelope_json": {
                            "action_type": "shell_command",
                            "command": "x" * 20_000,
                            "tool_name": "Bash",
                        },
                    }
                ]
            else:
                rows = []
            return rows if limit is None else rows[:limit]

    store = StatusSplitStore(tmp_path / "guard-home")
    pending_items, pending_complete = command_executors._local_request_snapshot_items_for_status(
        store,
        status="pending",
        limit=command_executors.LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT,
    )
    pending_only_bytes = len(
        json.dumps({"requests": pending_items}, separators=(",", ":"), sort_keys=True).encode(
            "utf-8",
        ),
    )
    monkeypatch.setattr(
        command_executors,
        "LOCAL_REQUEST_SNAPSHOT_MAX_BYTES",
        pending_only_bytes + 512,
    )

    payload = command_executors._local_request_snapshot_payload(store)

    assert pending_complete is True
    assert payload["pendingComplete"] is True
    assert payload["resolvedComplete"] is False
    assert [item["localRequestId"] for item in payload["requests"]] == ["req-pending-0"]


def test_local_request_snapshot_byte_cap_truncates_large_payloads() -> None:
    items = [{"localRequestId": f"req-large-{index}", "rawCommandText": "x" * 12_000} for index in range(400)]

    selected, complete = command_executors._local_request_snapshot_byte_capped_items(
        items,
        max_bytes=command_executors.LOCAL_REQUEST_SNAPSHOT_MAX_BYTES,
    )
    encoded = json.dumps({"requests": selected}, separators=(",", ":")).encode("utf-8")

    assert len(encoded) <= command_executors.LOCAL_REQUEST_SNAPSHOT_MAX_BYTES
    assert complete is False
    assert 0 < len(selected) < len(items)


def test_local_request_snapshot_byte_cap_compacts_oversized_first_item() -> None:
    items = [
        {
            "localRequestId": "req-oversized",
            "status": "pending",
            "harness": "cursor",
            "rawCommandText": "x" * (command_executors.LOCAL_REQUEST_SNAPSHOT_MAX_BYTES + 100_000),
            "actionEnvelope": {
                "command": "y" * (command_executors.LOCAL_REQUEST_SNAPSHOT_MAX_BYTES + 100_000),
            },
        },
        {"localRequestId": "req-next"},
    ]

    selected, complete = command_executors._local_request_snapshot_byte_capped_items(
        items,
        max_bytes=command_executors.LOCAL_REQUEST_SNAPSHOT_MAX_BYTES,
    )
    encoded = json.dumps({"requests": selected}, separators=(",", ":")).encode("utf-8")

    assert len(encoded) <= command_executors.LOCAL_REQUEST_SNAPSHOT_MAX_BYTES
    assert complete is False
    assert [item["localRequestId"] for item in selected] == ["req-oversized"]
    assert str(selected[0]["rawCommandText"]).endswith("...[truncated]")


def test_local_request_snapshot_operation_uses_complete_payload(tmp_path: Path) -> None:
    class ManyPendingStore(FakeStore):
        def list_approval_requests(
            self,
            *,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
            search: str | None = None,
        ) -> list[dict[str, object]]:
            del harness, cursor, search
            if status == "pending":
                rows = [_approval_request_row(f"req-pending-{index}") for index in range(125)]
                return rows if limit is None else rows[:limit]
            if status == "resolved":
                rows = [_approval_request_row("req-resolved")]
                return rows if limit is None else rows[:limit]
            return []

    result = command_executors.execute_guard_command_job(
        {"operation": "guard.localRequests.snapshot", "payload": {}},
        context=_context(tmp_path),
        store=ManyPendingStore(tmp_path / "guard-home"),
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    payload = result["data"]

    assert payload["pendingComplete"] is True
    assert payload["resolvedComplete"] is True
    assert payload["pendingCount"] == 125
    assert len(payload["requests"]) == 126
    assert payload["requests"][0]["localRequestId"] == "req-pending-0"
    assert payload["requests"][124]["localRequestId"] == "req-pending-124"
    assert payload["requests"][125]["localRequestId"] == "req-resolved"


def test_local_request_snapshot_items_continues_when_request_claim_is_invalid(tmp_path: Path) -> None:
    class MalformedRequestStore(FakeStore):
        def list_approval_requests(
            self,
            *,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
            search: str | None = None,
        ) -> list[dict[str, object]]:
            del harness, limit, cursor, search
            if status == "pending":
                row = _approval_request_row("req-malformed")
                row.pop("created_at", None)
                return [row]
            return []

    snapshot = command_executors._local_request_snapshot_items(MalformedRequestStore(tmp_path / "guard-home"))

    assert len(snapshot) == 1
    assert snapshot[0]["localRequestId"] == "req-malformed"
    assert snapshot[0]["claim"] is None


def test_local_request_snapshot_strips_command_when_redaction_is_full(tmp_path: Path) -> None:
    class RequestStore(FakeStore):
        def list_approval_requests(
            self,
            *,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
            search: str | None = None,
        ) -> list[dict[str, object]]:
            del harness, limit, cursor, search
            if status == "pending":
                row = _approval_request_row("req-full-redaction")
                row["raw_command_text"] = "sed -n '1,80p' .env"
                row["rawCommandText"] = "cat PRIVATE_KEY_FILE"
                row["commandText"] = "cat CREDENTIAL_FILE"
                row["raw_target_paths"] = ["secret-config.txt"]
                row["request_payload_json"] = {"command": "cat secret-config.txt"}
                return [row]
            return []

    store = RequestStore(tmp_path / "guard-home")
    store.payloads["cloud_receipt_redaction_level"] = {"level": "full"}

    snapshot = command_executors._local_request_snapshot_items(store)

    payload = snapshot[0]["requestPayload"]
    assert isinstance(payload, dict)
    envelope = payload["action_envelope_json"]
    assert isinstance(envelope, dict)
    assert payload["redaction_enabled"] is True
    assert payload["redactionEnabled"] is True
    assert payload["raw_command_text"] is None
    assert payload["command_text"] is None
    assert payload["rawCommandText"] is None
    assert payload["commandText"] is None
    assert payload["actionEnvelope"] == envelope
    assert payload["envelope_redacted"] == envelope
    assert payload["envelopeRedacted"] == envelope
    assert "raw_target_paths" not in payload
    assert "request_payload_json" not in payload
    assert "command" not in envelope
    assert envelope["operation"] == "run"
    assert envelope["target_class"] == "shell_command"
    assert envelope["targetClass"] == "shell_command"
    assert envelope["target_count"] == 0
    assert envelope["targetCount"] == 0


def test_local_request_snapshot_withholds_command_when_redaction_is_partial(tmp_path: Path) -> None:
    class RequestStore(FakeStore):
        def list_approval_requests(
            self,
            *,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
            search: str | None = None,
        ) -> list[dict[str, object]]:
            del harness, limit, cursor, search
            if status == "pending":
                row = _approval_request_row("req-partial-redaction")
                row["rawCommandText"] = "grep sk-test-token src/config.ts"
                row["action_envelope_json"] = {
                    "action_type": "shell_command",
                    "command": "cat PRIVATE_KEY_FILE",
                    "tool_name": "grep",
                    "target_paths": ["src/config.ts"],
                }
                return [row]
            return []

    store = RequestStore(tmp_path / "guard-home")
    store.payloads["cloud_receipt_redaction_level"] = {"level": "partial"}

    snapshot = command_executors._local_request_snapshot_items(store)

    payload = snapshot[0]["requestPayload"]
    assert isinstance(payload, dict)
    envelope = payload["action_envelope_json"]
    assert isinstance(envelope, dict)
    assert payload["redaction_enabled"] is True
    assert payload["redactionEnabled"] is True
    assert payload["raw_command_text"] is None
    assert payload["command_text"] is None
    assert payload["rawCommandText"] is None
    assert payload["commandText"] is None
    assert "command" not in envelope
    assert "target_paths" not in envelope
    assert envelope["operation"] == "run"
    assert envelope["target_class"] == "shell_command"
    assert envelope["target_count"] == 1
    assert payload["actionEnvelope"] == envelope
    assert payload["envelopeRedacted"] == envelope


def test_local_request_snapshot_syncs_raw_command_aliases_and_routing_when_redaction_disabled(
    tmp_path: Path,
) -> None:
    class RequestStore(FakeStore):
        def list_approval_requests(
            self,
            *,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
            search: str | None = None,
        ) -> list[dict[str, object]]:
            del harness, limit, cursor, search
            if status == "pending":
                row = _approval_request_row("req-no-redaction", harness="codex")
                row["raw_command_text"] = "rg TODO src/lib/file.ts"
                row["action_envelope_json"] = {
                    "action_type": "shell_command",
                    "command": "rg TODO src/lib/file.ts",
                    "tool_name": "Bash",
                    "target_paths": ["src/lib/file.ts"],
                }
                return [row]
            return []

    store = RequestStore(tmp_path / "guard-home")
    store.payloads["cloud_receipt_redaction_level"] = {"level": "none"}

    snapshot = command_executors._local_request_snapshot_items(store)

    item = snapshot[0]
    payload = item["requestPayload"]
    assert isinstance(payload, dict)
    assert item["workspace_id"] == "workspace-1"
    assert item["workspaceId"] == "workspace-1"
    assert item["machine_installation_id"] == "22222222-2222-4222-8222-222222222222"
    assert item["machineInstallationId"] == "22222222-2222-4222-8222-222222222222"
    assert item["grant_id"] == "grant-1"
    assert item["grantId"] == "grant-1"
    assert item["runtime_grant_id"] == "runtime-1"
    assert item["runtimeGrantId"] == "runtime-1"
    assert item["local_request_id"] == "req-no-redaction"
    assert item["localRequestId"] == "req-no-redaction"
    assert item["harness_id"] == "codex"
    assert item["harnessId"] == "codex"
    assert item["request_last_seen_at"] == "2026-05-14T11:59:00.000Z"
    assert item["requestLastSeenAt"] == "2026-05-14T11:59:00.000Z"
    assert payload["redaction_enabled"] is False
    assert payload["redactionEnabled"] is False
    assert payload["raw_command_text"] == "rg TODO src/lib/file.ts"
    assert payload["rawCommandText"] == "rg TODO src/lib/file.ts"
    assert payload["command_text"] == "rg TODO src/lib/file.ts"
    assert payload["commandText"] == "rg TODO src/lib/file.ts"
    assert payload["workspace_id"] == "workspace-1"
    assert payload["workspaceId"] == "workspace-1"
    envelope = payload["action_envelope_json"]
    assert isinstance(envelope, dict)
    assert payload["actionEnvelope"] == envelope
    assert envelope["command"] == "rg TODO src/lib/file.ts"
    assert envelope["target_paths"] == ["src/lib/file.ts"]
    assert envelope["targetPaths"] == ["src/lib/file.ts"]


@pytest.mark.parametrize(
    ("name", "envelope", "expected"),
    [
        (
            "mcp",
            {
                "action_type": "mcp_tool",
                "mcp_server": "filesystem",
                "mcp_tool": "read_file",
                "tool_name": "mcp__filesystem__read_file",
                "target_paths": ["README.md"],
                "raw_payload_redacted": {"tool_input": {"path": "README.md"}},
            },
            {"mcpServer": "filesystem", "mcpTool": "read_file", "targetResource": "README.md"},
        ),
        (
            "skill",
            {
                "action_type": "skill",
                "operation": "install",
                "skill_name": "guard-audit",
                "source_path": "skills/guard-audit",
                "requested_permission": "workspace-write",
            },
            {"skillName": "guard-audit", "sourcePath": "skills/guard-audit", "requestedPermission": "workspace-write"},
        ),
        (
            "file_read",
            {"action_type": "file_read", "target_paths": ["README.md"]},
            {"operation": "read", "path": "README.md", "accessMode": "read", "contentState": "metadata_only"},
        ),
        (
            "file_write",
            {"action_type": "file_write", "target_paths": ["src/app.ts"]},
            {"operation": "write", "path": "src/app.ts", "accessMode": "write", "contentState": "metadata_only"},
        ),
        (
            "browser",
            {"action_type": "browser_action", "operation": "click", "url": "https://example.test", "selector": "#run"},
            {"operation": "click", "url": "https://example.test", "selector": "#run"},
        ),
        (
            "package",
            {"action_type": "package_script", "package_manager": "npm", "package_name": "left-pad"},
            {"operation": "install", "packageManager": "npm", "packageName": "left-pad"},
        ),
        (
            "network",
            {"action_type": "network_request", "method": "POST", "url": "https://api.example.test/v1"},
            {"operation": "request", "method": "POST", "url": "https://api.example.test/v1"},
        ),
        (
            "unknown",
            {"action_type": "custom_tool", "tool_name": "CustomTool", "parameters": {"id": "123"}},
            {"actionType": "custom_tool", "toolName": "CustomTool", "parameters": {"id": "123"}},
        ),
    ],
)
def test_cloud_review_payload_action_envelope_aliases(
    name: str,
    envelope: dict[str, object],
    expected: dict[str, object],
) -> None:
    row = {
        **_approval_request_row(f"req-envelope-{name}"),
        "action_envelope_json": envelope,
    }

    payload = local_request_snapshots._cloud_safe_local_request_payload(row, redaction_level="none")

    action_envelope = payload["action_envelope_json"]
    assert isinstance(action_envelope, dict)
    assert payload["actionEnvelope"] == action_envelope
    assert payload["redaction_enabled"] is False
    assert payload["redactionEnabled"] is False
    assert action_envelope["action_type"] == envelope["action_type"]
    assert action_envelope["actionType"] == envelope["action_type"]
    for key, value in expected.items():
        assert action_envelope[key] == value


def test_cloud_review_payload_malformed_envelope_gets_safe_display_contract() -> None:
    row = {
        **_approval_request_row("req-malformed-envelope"),
        "action_envelope_json": "{not json",
    }

    payload = local_request_snapshots._cloud_safe_local_request_payload(row, redaction_level="full")

    envelope = payload["action_envelope_json"]
    assert isinstance(envelope, dict)
    assert payload["actionEnvelope"] == envelope
    assert payload["envelope_redacted"] == envelope
    assert payload["envelopeRedacted"] == envelope
    assert envelope["malformed"] is True
    assert envelope["action_type"] == "unknown"
    assert envelope["actionType"] == "unknown"
    assert envelope["operation"] == "parse_action_envelope"


def test_local_request_snapshot_syncs_display_fields_when_command_missing(tmp_path: Path) -> None:
    class RequestStore(FakeStore):
        def list_approval_requests(
            self,
            *,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
            search: str | None = None,
        ) -> list[dict[str, object]]:
            del harness, limit, cursor, search
            if status != "pending":
                return []
            row = _approval_request_row("req-display-fields")
            row["artifact_type"] = "tool_action_request"
            row["artifact_name"] = "grep credential-looking output"
            row["artifact_label"] = "grep credential-looking output"
            row["source_label"] = "Pi"
            row["trigger_summary"] = "Tool output contains credential-looking material."
            row["why_now"] = "Guard paused this output before delivery."
            row["risk_headline"] = "Credential-looking output reached the harness."
            row["risk_summary"] = "Guard stopped post-tool output before the harness saw it."
            row["raw_command_text"] = None
            row["action_envelope_json"] = None
            return [row]

    store = RequestStore(tmp_path / "guard-home")
    store.payloads["cloud_receipt_redaction_level"] = {"level": "full"}

    snapshot = command_executors._local_request_snapshot_items(store)

    payload = snapshot[0]["requestPayload"]
    assert isinstance(payload, dict)
    assert payload["artifact_name"] == "grep credential-looking output"
    assert payload["artifact_type"] == "tool_action_request"
    assert payload["artifact_label"] == "grep credential-looking output"
    assert payload["source_label"] == "Pi"
    assert payload["trigger_summary"] == "Tool output contains credential-looking material."
    assert payload["why_now"] == "Guard paused this output before delivery."
    assert payload["risk_headline"] == "Credential-looking output reached the harness."
    assert payload["risk_summary"] == "Guard stopped post-tool output before the harness saw it."
    assert payload["raw_command_text"] is None
    assert payload["command_text"] is None


def test_executor_rejects_remote_approval_without_trusted_keyring(tmp_path: Path) -> None:
    class RequestStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.request_row = _approval_request_row("request-untrusted")

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-untrusted" else None

    store = RequestStore(tmp_path / "guard-home")
    store.payloads["policy_bundle_keyring"] = {"contractVersion": "guard-policy-keyring.v1", "keys": []}

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "allow_once",
                "localRequestId": "request-untrusted",
                "remoteApproval": _signed_remote_approval(
                    store,
                    store.request_row,
                    receipt_id="receipt-untrusted",
                ),
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["failureCode"] == "unknown_signing_key"


def _block_local_daemon_client(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("Guard Cloud command execution must not use the local daemon client.")

    monkeypatch.setattr(daemon_client_module, "load_guard_surface_daemon_client", fail)
    for module in (daemon_client_module, daemon_manager_module):
        monkeypatch.setattr(module, "ensure_guard_daemon", fail)
        monkeypatch.setattr(module, "load_guard_daemon_url", fail)
        monkeypatch.setattr(module, "load_guard_daemon_auth_token", fail)


def test_command_queue_enabled_defaults_on(monkeypatch) -> None:
    monkeypatch.delenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, raising=False)

    assert command_queue.command_queue_enabled() is True


@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_command_queue_enabled_allows_explicit_opt_in(value: str, monkeypatch) -> None:
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, value)

    assert command_queue.command_queue_enabled() is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "disabled"])
def test_command_queue_enabled_allows_explicit_opt_out(value: str, monkeypatch) -> None:
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, value)

    assert command_queue.command_queue_enabled() is False


@pytest.mark.parametrize("value", ["garbage", "maybe"])
def test_command_queue_enabled_disables_unrecognized_explicit_values(value: str, monkeypatch) -> None:
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, value)

    assert command_queue.command_queue_enabled() is False


def test_poll_once_leases_heartbeats_executes_and_posts_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = FakeStore(tmp_path / "guard-home")
    calls: list[tuple[str, str, dict[str, object]]] = []

    def fake_auth_context(current_store: object) -> dict[str, object]:
        assert current_store is store
        return {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"}

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        calls.append((method, path, payload))
        if path == "/lease":
            return {
                "item": {
                    "id": "job-1",
                    "leaseId": "lease-1",
                    "operation": "guard.packageShims.status",
                }
            }
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_resolve_guard_sync_auth_context", fake_auth_context)
    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)
    monkeypatch.setattr(
        command_executors,
        "package_shim_status",
        lambda context: {"active_managers": ["npm"]},
    )

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert calls[0] == (
        "POST",
        "/lease",
        {
            "workspaceId": "workspace-1",
            "deviceId": "machine-1",
            "daemonVersion": command_queue.__version__,
            "capabilities": {
                "operations": list(command_executors.SUPPORTED_COMMAND_OPERATIONS),
                "schemaVersions": dict(command_executors.COMMAND_OPERATION_SCHEMA_VERSIONS),
            },
            "localRequestsSnapshot": {
                "requests": [],
                "pendingComplete": True,
                "resolvedComplete": True,
                "pendingLimit": command_executors.LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT,
                "resolvedLimit": command_executors.LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT,
                "pendingCount": 0,
                "resolvedCount": 0,
            },
            "maxJobs": 1,
            "waitMs": 25000,
        },
    )
    assert calls[1] == ("POST", "/job-1/heartbeat", {"leaseId": "lease-1"})
    assert calls[2] == ("POST", "/job-1/heartbeat", {"leaseId": "lease-1"})
    assert calls[3][0:2] == ("POST", "/job-1/result")
    assert calls[3][2]["status"] == "succeeded"
    assert calls[3][2]["leaseId"] == "lease-1"
    assert "machineInstallationId" not in calls[0][2]
    assert "machineInstallationId" not in calls[1][2]
    assert "machineInstallationId" not in calls[2][2]
    assert "machineInstallationId" not in calls[3][2]


def test_lease_payload_strips_local_snapshot_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _oauth_store(tmp_path)
    monkeypatch.setattr(
        command_queue,
        "_local_request_snapshot_payload",
        lambda _store: {
            "requests": [],
            "pendingComplete": True,
            "resolvedComplete": True,
            "pendingLimit": 125,
            "resolvedLimit": 25,
            "pendingCount": 0,
            "resolvedCount": 0,
            "maxBytes": 900000,
            "debugOnly": "drop-me",
        },
    )

    payload = command_queue._lease_payload(store)

    assert payload["localRequestsSnapshot"] == {
        "requests": [],
        "pendingComplete": True,
        "resolvedComplete": True,
        "pendingLimit": 125,
        "resolvedLimit": 25,
        "pendingCount": 0,
        "resolvedCount": 0,
    }


def test_executor_app_remove_never_uses_local_daemon_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _block_local_daemon_client(monkeypatch)

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.app.remove",
            "payload": {"harness": "codex", "surface": "cli"},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["waitingLocalConfirm"] is True
    assert result["data"] == {
        "confirm_command": "hol-guard apps disconnect codex --surface cli --confirm disconnect-codex",
        "confirmation_phrase": "disconnect-codex",
        "harness": "codex",
        "summary": ("Run the local disconnect command on this machine to confirm removing Guard protection for codex."),
        "surface": "cli",
    }


def test_poll_once_executes_app_connect_without_local_daemon_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FakeStore(tmp_path / "guard-home")
    calls: list[tuple[str, str, dict[str, object]]] = []
    _block_local_daemon_client(monkeypatch)
    monkeypatch.setattr(
        command_queue,
        "_resolve_guard_sync_auth_context",
        lambda current_store: {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"},
    )

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        calls.append((method, path, payload))
        if path == "/lease":
            return {
                "item": {
                    "id": "job-app-connect-1",
                    "leaseId": "lease-app-connect-1",
                    "operation": "guard.app.connect",
                    "payload": {"harness": "codex", "surface": "cli"},
                }
            }
        return {"ok": True}

    def fake_apply_managed_install(
        command: str,
        requested_harness: str | None,
        install_all: bool,
        context: HarnessContext,
        store: object,
        workspace: str | None,
        now: str,
        *,
        surface: str | None = None,
    ) -> dict[str, object]:
        del install_all, context, store, workspace
        assert command == "install"
        assert requested_harness == "codex"
        assert isinstance(now, str) and now
        return {"managed_install": {"harness": requested_harness}, "surface": surface}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)
    monkeypatch.setattr(command_executors, "apply_managed_install", fake_apply_managed_install)

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert calls[-1][0:2] == ("POST", "/job-app-connect-1/result")
    assert calls[-1][2]["status"] == "succeeded"
    result = calls[-1][2]["result"]
    assert isinstance(result, dict)
    assert result["data"] == {
        "managed_install": {"harness": "codex"},
        "surface": "cli",
    }


def test_poll_once_continues_when_local_request_snapshot_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class BrokenSnapshotStore(FakeStore):
        def list_approval_requests(
            self,
            *,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
            search: str | None = None,
        ) -> list[dict[str, object]]:
            del status, harness, limit, cursor, search
            raise OSError("approval store locked")

    store = BrokenSnapshotStore(tmp_path / "guard-home")
    calls: list[tuple[str, str, dict[str, object]]] = []
    monkeypatch.setattr(
        command_queue,
        "_resolve_guard_sync_auth_context",
        lambda current_store: {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"},
    )

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        calls.append((method, path, payload))
        if path == "/lease":
            return {
                "item": {
                    "id": "job-1",
                    "leaseId": "lease-1",
                    "operation": "guard.packageShims.status",
                }
            }
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)
    monkeypatch.setattr(
        command_executors,
        "package_shim_status",
        lambda context: {"active_managers": []},
    )

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert calls[0][0:2] == ("POST", "/lease")
    assert calls[0][2]["localRequestsSnapshot"] == {"requests": []}
    assert calls[-1][0:2] == ("POST", "/job-1/result")


def test_poll_once_persists_result_retry_when_result_upload_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = FakeStore(tmp_path / "guard-home")

    monkeypatch.setattr(
        command_queue,
        "_resolve_guard_sync_auth_context",
        lambda current_store: {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"},
    )
    monkeypatch.setattr(command_executors, "package_shim_status", lambda context: {"active_managers": []})

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        if path == "/lease":
            return {
                "item": {
                    "id": "job-2",
                    "leaseId": "lease-2",
                    "operation": "guard.packageShims.status",
                }
            }
        if path.endswith("/result"):
            raise OSError("upload failed")
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    try:
        command_queue.poll_command_queue_once(store, _context(tmp_path))
    except OSError:
        pass
    else:
        raise AssertionError("result upload should fail")

    state = store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY)
    assert isinstance(state, dict)
    assert state["state"] == "result_pending"
    assert isinstance(state["pending_result"], dict)


def test_poll_once_persists_result_when_result_upload_http_error(tmp_path: Path, monkeypatch) -> None:
    """Regression: HTTPError 500/429 on result upload must persist pending_result (PR #1308)."""
    store = FakeStore(tmp_path / "guard-home")

    monkeypatch.setattr(
        command_queue,
        "_resolve_guard_sync_auth_context",
        lambda current_store: {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"},
    )
    monkeypatch.setattr(command_executors, "package_shim_status", lambda context: {"active_managers": []})

    class FakeHTTPError(urllib.error.HTTPError):
        def __init__(self) -> None:
            super().__init__(
                "https://hol.test/api/guard/commands/job-3/result",
                500,
                "Internal Server Error",
                {},
                None,
            )

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        if path == "/lease":
            return {
                "item": {
                    "id": "job-3",
                    "leaseId": "lease-3",
                    "operation": "guard.packageShims.status",
                }
            }
        if path.endswith("/result"):
            raise FakeHTTPError()
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    with pytest.raises(urllib.error.HTTPError):
        command_queue.poll_command_queue_once(store, _context(tmp_path))

    state = store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY)
    assert isinstance(state, dict)
    assert state["state"] == "result_pending"
    pending = state["pending_result"]
    assert isinstance(pending, dict)
    assert pending["job"]["id"] == "job-3"
    assert "payload" in pending


def test_poll_once_clears_active_job_when_heartbeat_fails(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    monkeypatch.setattr(
        command_queue,
        "_resolve_guard_sync_auth_context",
        lambda current_store: {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"},
    )

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        if path == "/lease":
            return {
                "item": {
                    "id": "job-2",
                    "leaseId": "lease-2",
                    "operation": "guard.packageShims.status",
                }
            }
        if path.endswith("/heartbeat"):
            raise OSError("heartbeat failed")
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    try:
        command_queue.poll_command_queue_once(store, _context(tmp_path))
    except OSError:
        pass
    else:
        raise AssertionError("heartbeat should fail")

    state = store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY)
    assert isinstance(state, dict)
    assert state["state"] == "error"
    assert "active_job" not in state


def test_poll_once_posts_failed_result_when_execution_raises(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    result_payloads: list[dict[str, object]] = []
    monkeypatch.setattr(
        command_queue,
        "_resolve_guard_sync_auth_context",
        lambda current_store: {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"},
    )
    monkeypatch.setattr(
        command_executors,
        "package_shim_status",
        lambda context: (_ for _ in ()).throw(RuntimeError("shim status failed")),
    )

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        if path == "/lease":
            return {
                "item": {
                    "id": "job-5",
                    "leaseId": "lease-5",
                    "operation": "guard.packageShims.status",
                }
            }
        if path.endswith("/result"):
            result_payloads.append(payload)
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert result_payloads[0]["status"] == "failed"
    assert result_payloads[0]["failureCode"] == "execution_error"
    assert "shim status failed" in str(result_payloads[0]["failureMessage"])


def test_poll_once_posts_waiting_local_confirm_result_for_destructive_job(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = FakeStore(tmp_path / "guard-home")
    result_payloads: list[dict[str, object]] = []
    monkeypatch.setattr(
        command_queue,
        "_resolve_guard_sync_auth_context",
        lambda current_store: {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"},
    )

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        if path == "/lease":
            return {
                "item": {
                    "id": "job-6",
                    "leaseId": "lease-6",
                    "operation": "guard.packageShims.remove",
                    "payload": {"managers": ["npm"]},
                }
            }
        if path.endswith("/result"):
            result_payloads.append(payload)
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert result_payloads[0]["status"] == "waiting_local_confirm"
    assert result_payloads[0]["idempotencyKey"] == "job-6:lease-6:waiting_local_confirm"
    result = result_payloads[0]["result"]
    assert isinstance(result, dict)
    assert "waitingLocalConfirm" not in result
    data = result["data"]
    assert isinstance(data, dict)
    assert data["confirm_command"] == "hol-guard package-shims uninstall --manager npm"
    assert data["summary"] == (
        "Run the local package-shim uninstall command on this machine to confirm removal for npm."
    )


def test_result_payload_reuses_stable_success_idempotency_key() -> None:
    job = {"id": "job-duplicate-result", "leaseId": "lease-duplicate-result"}
    execution = {"data": {"ok": True}}

    first = command_queue._result_payload(job, execution)
    second = command_queue._result_payload(job, execution)

    assert first["status"] == "succeeded"
    assert first["idempotencyKey"] == "job-duplicate-result:lease-duplicate-result:succeeded"
    assert second["idempotencyKey"] == first["idempotencyKey"]


def test_poll_once_retries_pending_result_before_leasing(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    store.set_sync_payload(
        command_queue.COMMAND_QUEUE_STATE_KEY,
        {
            "state": "result_pending",
            "pending_result": {
                "job": {"id": "job-3", "leaseId": "lease-3"},
                "payload": {
                    "leaseId": "lease-3",
                    "idempotencyKey": "job-3:lease-3:succeeded",
                    "status": "succeeded",
                    "result": {"data": {}},
                },
            },
        },
        "2026-06-13T00:00:00+00:00",
    )
    calls: list[str] = []
    monkeypatch.setattr(
        command_queue,
        "_resolve_guard_sync_auth_context",
        lambda current_store: {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"},
    )

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        calls.append(path)
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert calls == ["/job-3/result"]
    assert status["pending_result"] is None


def test_poll_once_reuses_cached_access_token_across_oauth_polls(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = _oauth_store(tmp_path)
    observed_refresh_tokens: list[str] = []
    observed_access_tokens: list[str] = []

    def fake_refresh(
        *,
        token_endpoint: str,
        client_id: str,
        refresh_token: str,
        dpop_key_material,
    ) -> dict[str, object]:
        del token_endpoint, client_id, dpop_key_material
        observed_refresh_tokens.append(refresh_token)
        current_index = len(observed_refresh_tokens)
        return {
            "access_token": f"access-token-{current_index}",
            "access_token_expires_at": "2099-07-05T00:00:00+00:00",
            "refresh_token": f"refresh-token-{current_index + 1}",
            "package_firewall_entitlement": {
                "supply_chain_entitlement_expires_at": "2026-07-05T00:00:00+00:00",
                "supply_chain_firewall": True,
                "supply_chain_plan_id": "team",
            },
        }

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        del method, payload
        observed_access_tokens.append(str(auth_context["access_token"]))
        assert path == "/lease"
        return {"item": None}

    monkeypatch.setattr(guard_runner_module, "_refresh_guard_oauth_access_token", fake_refresh)
    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    first_status = command_queue.poll_command_queue_once(store, _context(tmp_path))
    second_status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert first_status["last_poll_was_empty"] is True
    assert second_status["last_poll_was_empty"] is True
    assert observed_refresh_tokens == ["refresh-token-1"]
    assert observed_access_tokens == ["access-token-1", "access-token-1"]
    credentials = store.get_oauth_local_credentials()
    assert credentials is not None
    assert credentials["refresh_token"] == "refresh-token-2"
    assert credentials["access_token"] == "access-token-1"
    assert credentials["access_token_expires_at"] == "2099-07-05T00:00:00+00:00"


def test_poll_once_clears_active_job_for_malformed_pending_result(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    store.set_sync_payload(
        command_queue.COMMAND_QUEUE_STATE_KEY,
        {
            "state": "result_pending",
            "active_job": {"id": "job-4", "leaseId": "lease-4"},
            "pending_result": {"job": "bad", "payload": {}},
        },
        "2026-06-13T00:00:00+00:00",
    )
    calls: list[str] = []
    monkeypatch.setattr(
        command_queue,
        "_resolve_guard_sync_auth_context",
        lambda current_store: {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"},
    )

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        calls.append(path)
        return {"item": None}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    command_queue.poll_command_queue_once(store, _context(tmp_path))

    state = store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY)
    assert isinstance(state, dict)
    assert "active_job" not in state
    assert "pending_result" not in state
    assert calls == ["/lease"]


def test_command_queue_loop_empty_long_poll_returns_positive_bounded_backoff(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Long-poll empty responses must use bounded positive backoff, not zero-delay.

    Verifies the fix for the immediate-empty long-poll spin bug: when long-poll
    is enabled and every poll returns empty, the loop must wait with a positive
    backoff that is non-decreasing (bounded exponential growth), not spin at 0s.
    """
    store = FakeStore(tmp_path / "guard-home")
    waits: list[float] = []

    class StopAfterThreeWaits:
        def is_set(self) -> bool:
            return False

        def wait(self, seconds: float) -> bool:
            waits.append(seconds)
            return len(waits) >= 3

    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, "1")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_LEASE_WAIT_MS_ENV, "25000")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_POLL_INTERVAL_ENV, "1")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ERROR_BACKOFF_ENV, "8")

    def fake_poll_once(current_store: object, context: HarnessContext) -> dict[str, object]:
        return {"last_poll_was_empty": True}

    monkeypatch.setattr(command_queue, "poll_command_queue_once", fake_poll_once)

    command_queue.command_queue_loop(
        store,
        _context(tmp_path),
        stop_event=StopAfterThreeWaits(),
    )

    # Each wait must be strictly positive (no zero-delay spin).
    assert all(w > 0 for w in waits), f"Long-poll empty responses caused zero-delay spin: {waits}"
    # Backoff must be non-decreasing (bounded exponential growth).
    assert waits == sorted(waits), f"Backoff must not decrease: {waits}"


def test_command_queue_loop_backs_off_after_empty_short_poll_when_wait_disabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = FakeStore(tmp_path / "guard-home")
    waits: list[float] = []

    class StopAfterThreeWaits:
        def is_set(self) -> bool:
            return False

        def wait(self, seconds: float) -> bool:
            waits.append(seconds)
            return len(waits) >= 3

    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, "1")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_LEASE_WAIT_MS_ENV, "0")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_POLL_INTERVAL_ENV, "1")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ERROR_BACKOFF_ENV, "8")

    def fake_poll_once(current_store: object, context: HarnessContext) -> dict[str, object]:
        return {"last_poll_was_empty": True}

    monkeypatch.setattr(command_queue, "poll_command_queue_once", fake_poll_once)

    command_queue.command_queue_loop(
        store,
        _context(tmp_path),
        stop_event=StopAfterThreeWaits(),
    )

    assert waits == [1, 2, 4]


def test_start_worker_replaces_stopped_alive_worker(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")

    class FakeThread:
        def __init__(self) -> None:
            self.started = False

        def is_alive(self) -> bool:
            return True

        def start(self) -> None:
            self.started = True

    class FakeEvent:
        def __init__(self, stopped: bool = False) -> None:
            self.stopped = stopped

        def is_set(self) -> bool:
            return self.stopped

    created_threads: list[FakeThread] = []

    def fake_thread(*args: object, **kwargs: object) -> FakeThread:
        thread = FakeThread()
        created_threads.append(thread)
        return thread

    monkeypatch.delenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, raising=False)
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.command_queue_worker.threading.Thread", fake_thread)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.command_queue_worker.threading.Event",
        lambda: FakeEvent(False),
    )
    existing = CommandQueueWorker(thread=FakeThread(), stop_event=FakeEvent(True))  # type: ignore[arg-type]

    worker = start_command_queue_worker(store, existing)  # type: ignore[arg-type]

    assert worker is not existing
    assert created_threads[0].started is True


def test_start_worker_respects_command_queue_opt_out(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, "0")

    assert start_command_queue_worker(store, None) is None  # type: ignore[arg-type]


def test_command_queue_loop_backs_off_after_errors(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    waits: list[float] = []

    class StopAfterThreeWaits:
        def is_set(self) -> bool:
            return False

        def wait(self, seconds: float) -> bool:
            waits.append(seconds)
            return len(waits) >= 3

    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, "1")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_POLL_INTERVAL_ENV, "1")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ERROR_BACKOFF_ENV, "8")
    monkeypatch.setattr(
        command_queue,
        "poll_command_queue_once",
        lambda current_store, context: (_ for _ in ()).throw(OSError("network down")),
    )

    command_queue.command_queue_loop(
        store,
        _context(tmp_path),
        stop_event=StopAfterThreeWaits(),
    )

    assert waits == [1, 2, 4]


def test_command_queue_loop_retries_revoked_oauth_auth_and_records_reconnect_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = _oauth_store(tmp_path)

    waits: list[float] = []

    class StopAfterThreeWaits:
        def is_set(self) -> bool:
            return False

        def wait(self, seconds: float) -> bool:
            waits.append(seconds)
            return len(waits) >= 3

    def fake_refresh(
        *,
        token_endpoint: str,
        client_id: str,
        refresh_token: str,
        dpop_key_material,
    ) -> dict[str, object]:
        del token_endpoint, client_id, refresh_token, dpop_key_material
        raise guard_runner_module.GuardSyncAuthorizationExpiredError(
            "Guard authorization expired. Run `hol-guard connect` to sign in again."
        )

    stop_event = StopAfterThreeWaits()
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, "1")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_POLL_INTERVAL_ENV, "1")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ERROR_BACKOFF_ENV, "8")
    monkeypatch.setattr(guard_runner_module, "_refresh_guard_oauth_access_token", fake_refresh)

    command_queue.command_queue_loop(store, _context(tmp_path), stop_event=stop_event)

    status = command_queue.command_queue_status(store)
    assert status["state"] == "auth_expired"
    assert "hol-guard connect" in str(status["last_error"])
    assert waits == [1, 2, 4]


def test_command_queue_retry_wait_clamps_zero_poll_interval_and_large_backoff_exponent() -> None:
    assert command_queue._retry_wait_seconds(0.0, 8.0, 1) == 0.1
    assert command_queue._retry_wait_seconds(1.0, 8.0, 10_000) == 8.0


def test_poll_once_keeps_auth_expired_state_when_auth_refresh_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = _oauth_store(tmp_path)
    existing_error = "Guard authorization expired. Run `hol-guard connect` to sign in again."
    store.set_sync_payload(
        command_queue.COMMAND_QUEUE_STATE_KEY,
        {
            "state": "auth_expired",
            "last_error": existing_error,
            "last_poll_at": "2026-06-23T10:00:00+00:00",
        },
        "2026-06-23T10:00:00+00:00",
    )

    def fake_auth_context(current_store, *, allow_primary_repair: bool = True, force_refresh: bool = False):
        del current_store, allow_primary_repair, force_refresh
        raise guard_runner_module.GuardSyncAuthorizationExpiredError(existing_error)

    monkeypatch.setattr(command_queue, "_resolve_guard_sync_auth_context", fake_auth_context)

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError, match="hol-guard connect"):
        command_queue.poll_command_queue_once(store, _context(tmp_path))

    status = command_queue.command_queue_status(store)
    assert status["state"] == "auth_expired"
    assert status["last_error"] == existing_error


def test_poll_once_repairs_oauth_storage_and_retries_before_leasing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = _oauth_store(tmp_path)
    resolve_calls = {"count": 0}

    def fake_auth_context(current_store, *, allow_primary_repair: bool = True, force_refresh: bool = False):
        del current_store, allow_primary_repair, force_refresh
        resolve_calls["count"] += 1
        if resolve_calls["count"] == 1:
            raise guard_runner_module.GuardSyncNotConfiguredError("Guard is not logged in.")
        return {
            "access_token": "access-token-1",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        }

    def fake_repair(current_store):
        del current_store
        return {
            "existing_sign_in_valid": True,
            "repaired_storage": True,
        }

    monkeypatch.setattr(command_queue, "_resolve_guard_sync_auth_context", fake_auth_context)
    monkeypatch.setattr(command_queue, "repair_guard_cloud_connect_storage", fake_repair)
    monkeypatch.setattr(command_queue, "_json_request", lambda *args, **kwargs: {})

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert resolve_calls["count"] == 2
    assert status["state"] == "idle"
    assert status["last_poll_was_empty"] is True


def test_commands_status_outputs_command_queue_state(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_sync_payload(
        command_queue.COMMAND_QUEUE_STATE_KEY,
        {"state": "idle", "last_poll_at": "2026-06-13T00:00:00+00:00"},
        "2026-06-13T00:00:00+00:00",
    )
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, "1")

    rc = main(["guard", "commands", "status", "--guard-home", str(guard_home), "--json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "idle"
    assert payload["enabled"] is True
    assert payload["supported_operations"] == list(command_executors.SUPPORTED_COMMAND_OPERATIONS)


def test_doctor_repair_clears_malformed_command_queue_state(tmp_path: Path, capsys) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_sync_payload(
        command_queue.COMMAND_QUEUE_STATE_KEY,
        {"state": "result_pending", "active_job": "bad", "pending_result": {"job": "bad"}},
        "2026-06-13T00:00:00+00:00",
    )

    rc = main(["guard", "doctor", "--guard-home", str(guard_home), "--repair", "--json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    repair = payload["command_queue"]["repair"]
    assert repair["repaired_count"] == 2
    assert sorted(repair["repaired"]) == ["active_job", "pending_result"]
    state = store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY)
    assert isinstance(state, dict)
    assert state["state"] == "idle"
    assert "active_job" not in state
    assert "pending_result" not in state


def test_executor_rejects_duplicate_package_managers(tmp_path: Path) -> None:
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.packageShims.install",
            "payload": {"managers": ["npm", "npm"]},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["failureCode"] == "duplicate_manager"


def test_executor_status_ignores_speculative_managers_field(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(command_executors, "package_shim_status", lambda context: {"active_managers": []})

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.packageShims.status",
            "payload": {"managers": ["not-a-manager"]},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["generatedAt"] == "2026-06-13T00:00:00+00:00"
    assert result["data"] == {"active_managers": []}


def test_executor_dispatches_app_connect(tmp_path: Path, monkeypatch) -> None:
    calls: list[tuple[str, str | None, str | None]] = []

    def fake_apply_managed_install(
        command: str,
        requested_harness: str | None,
        install_all: bool,
        context: HarnessContext,
        store: object,
        workspace: str | None,
        now: str,
        *,
        surface: str | None = None,
    ) -> dict[str, object]:
        assert install_all is False
        calls.append((command, requested_harness, surface))
        return {"managed_install": {"harness": requested_harness}, "surface": surface}

    monkeypatch.setattr(command_executors, "apply_managed_install", fake_apply_managed_install)

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.app.connect",
            "payload": {"harness": "codex", "surface": "cli"},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert calls == [("install", "codex", "cli")]
    assert result["generatedAt"] == "2026-06-13T00:00:00+00:00"
    assert isinstance(result["data"], dict)


def test_executor_returns_waiting_local_confirm_for_package_shim_remove(tmp_path: Path) -> None:
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.packageShims.remove",
            "payload": {"managers": ["npm"]},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["waitingLocalConfirm"] is True
    assert result["data"] == {
        "confirm_command": "hol-guard package-shims uninstall --manager npm",
        "managers": ["npm"],
        "summary": ("Run the local package-shim uninstall command on this machine to confirm removal for npm."),
    }


def test_executor_returns_waiting_local_confirm_for_package_shim_remove_all_managers(tmp_path: Path) -> None:
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.packageShims.remove",
            "payload": {},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["waitingLocalConfirm"] is True
    assert result["data"] == {
        "confirm_command": "hol-guard package-shims uninstall",
        "managers": [],
        "summary": "Run the local package-shim uninstall command on this machine to confirm removal.",
    }


def test_executor_returns_waiting_local_confirm_for_app_remove(tmp_path: Path, monkeypatch) -> None:
    def fake_apply_managed_install(
        command: str,
        requested_harness: str | None,
        install_all: bool,
        context: HarnessContext,
        store: object,
        workspace: str | None,
        now: str,
        *,
        surface: str | None = None,
    ) -> dict[str, object]:
        del command, requested_harness, install_all, context, store, workspace, now, surface
        raise AssertionError("app remove should not uninstall without local confirmation")

    monkeypatch.setattr(command_executors, "apply_managed_install", fake_apply_managed_install)

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.app.remove",
            "payload": {"harness": "codex", "surface": "cli"},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["waitingLocalConfirm"] is True
    assert result["data"] == {
        "confirm_command": "hol-guard apps disconnect codex --surface cli --confirm disconnect-codex",
        "confirmation_phrase": "disconnect-codex",
        "harness": "codex",
        "summary": ("Run the local disconnect command on this machine to confirm removing Guard protection for codex."),
        "surface": "cli",
    }


def test_executor_returns_waiting_local_confirm_for_app_remove_without_surface(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fake_apply_managed_install(
        command: str,
        requested_harness: str | None,
        install_all: bool,
        context: HarnessContext,
        store: object,
        workspace: str | None,
        now: str,
        *,
        surface: str | None = None,
    ) -> dict[str, object]:
        del command, requested_harness, install_all, context, store, workspace, now, surface
        raise AssertionError("app remove should not uninstall without local confirmation")

    monkeypatch.setattr(command_executors, "apply_managed_install", fake_apply_managed_install)

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.app.remove",
            "payload": {"harness": "codex"},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["waitingLocalConfirm"] is True
    assert result["data"] == {
        "confirm_command": "hol-guard apps disconnect codex --confirm disconnect-codex",
        "confirmation_phrase": "disconnect-codex",
        "harness": "codex",
        "summary": ("Run the local disconnect command on this machine to confirm removing Guard protection for codex."),
        "surface": None,
    }


def test_executor_resolves_expired_approval_from_preexisting_queue(tmp_path: Path) -> None:
    class ApprovalStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.resolved: list[dict[str, object]] = []
            self.claimed_receipts: list[dict[str, str]] = []
            self.guard_events: list[GuardEventV1] = []
            self.request_row = _approval_request_row("request-1")

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-1" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            self.claimed_receipts.append(
                {
                    "receipt_id": receipt_id,
                    "request_id": request_id,
                    "claimed_at": claimed_at,
                }
            )
            return True

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            self.resolved.append(
                {
                    "request_id": request_id,
                    "resolution_action": resolution_action,
                    "resolution_scope": resolution_scope,
                    "reason": reason,
                    "resolved_at": resolved_at,
                }
            )
            return {"resolved": True, "resolved_request": {"request_id": request_id}}

        def add_guard_event_v1(self, event: GuardEventV1) -> None:
            self.guard_events.append(event)

    store = ApprovalStore(tmp_path / "guard-home")
    remote_approval = _signed_remote_approval(
        store,
        store.request_row,
        include_key_id=False,
        issued_at=datetime(2026, 6, 12, tzinfo=timezone.utc),
    )
    result = command_executors.execute_guard_command_job(
        {
            "createdAt": "2026-06-11T00:02:00+00:00",
            "operation": "guard.approval.resolve",
            "targetMachineInstallationId": "portal-installation-routing-id",
            "payload": {
                "localRequestId": "request-1",
                "action": "allow_once",
                "targetMachineInstallationId": "portal-installation-routing-id",
                "remoteApproval": remote_approval,
                "scope": "artifact",
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["generatedAt"] == "2026-06-13T00:00:00+00:00"
    data = result["data"]
    assert data["status"] == "completed"
    assert data["daemonAckStatus"] == "resolved"
    assert data["remoteDecision"] == "allow"
    assert data["resolution"]["status"] == "resolved"
    assert "remoteApproval" not in data
    assert store.resolved == [
        {
            "request_id": "request-1",
            "resolution_action": "allow",
            "resolution_scope": "artifact",
            "reason": "Guard Cloud signed remote approval",
            "resolved_at": "2026-06-13T00:00:00+00:00",
        }
    ]
    assert store.claimed_receipts == [
        {
            "receipt_id": "cloud-receipt-1",
            "request_id": "request-1",
            "claimed_at": "2026-06-13T00:00:00+00:00",
        }
    ]
    assert store.guard_events
    event_payload = store.guard_events[0].payload
    assert event_payload["decision_source"] == "cloud_review"
    assert event_payload["decision_action"] == "approved"
    assert event_payload["project_id"] == "/workspace/repo"


def test_executor_blocks_local_approval_request(tmp_path: Path) -> None:
    class ApprovalStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.resolved: list[dict[str, object]] = []
            self.request_row = _approval_request_row("request-block-1")

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-block-1" else None

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            self.resolved.append(
                {
                    "request_id": request_id,
                    "resolution_action": resolution_action,
                    "resolution_scope": resolution_scope,
                    "reason": reason,
                    "resolved_at": resolved_at,
                }
            )
            return {"resolved": True, "resolved_request": {"request_id": request_id}}

    store = ApprovalStore(tmp_path / "guard-home")
    remote_approval = _signed_remote_approval(
        store,
        store.request_row,
        decision="block",
        receipt_id="cloud-receipt-block",
    )
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "localRequestId": "request-block-1",
                "action": "block",
                "remoteApproval": remote_approval,
                "scope": "artifact",
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    data = result["data"]
    assert data["status"] == "completed"
    assert data["daemonAckStatus"] == "resolved"
    assert data["remoteDecision"] == "block"
    assert data["resolution"]["status"] == "resolved"
    assert "remoteApproval" not in data
    assert store.resolved == [
        {
            "request_id": "request-block-1",
            "resolution_action": "block",
            "resolution_scope": "artifact",
            "reason": "Guard Cloud signed remote approval",
            "resolved_at": "2026-06-13T00:00:00+00:00",
        }
    ]


def test_executor_ignores_stale_remote_approval_request_id(tmp_path: Path) -> None:
    class StaleRequestStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.present_request_row = _approval_request_row("request-present")
            self.stale_request_row = _approval_request_row("request-stale")
            self.claimed_receipts: list[str] = []

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.stale_request_row if request_id == "request-stale" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            del request_id, claimed_at
            self.claimed_receipts.append(receipt_id)
            return True

    store = StaleRequestStore(tmp_path / "guard-home")
    remote_approval = _signed_remote_approval(
        store,
        store.present_request_row,
        receipt_id="cloud-receipt-stale",
    )
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "localRequestId": "request-stale",
                "action": "allow_once",
                "remoteApproval": remote_approval,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["failureCode"] == "remote_approval_request_id_mismatch"
    assert store.claimed_receipts == []


@pytest.mark.parametrize(
    ("job_extra", "payload_extra", "failure_code"),
    [
        ({}, {"targetGrantId": "grant-other"}, "approval_target_grant_mismatch"),
        ({}, {"targetRuntimeGrantId": "runtime-other"}, "approval_target_runtime_grant_mismatch"),
        ({}, {"workspaceId": "workspace-other"}, "approval_target_workspace_mismatch"),
        ({"localRequestId": "request-other"}, {}, "approval_target_local_request_mismatch"),
    ],
)
def test_executor_rejects_wrong_outer_approval_target_before_side_effect(
    tmp_path: Path,
    job_extra: dict[str, object],
    payload_extra: dict[str, object],
    failure_code: str,
) -> None:
    class ApprovalStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.request_row = _approval_request_row("request-target")
            self.claimed_receipts: list[str] = []
            self.resolved: list[str] = []

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-target" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            del request_id, claimed_at
            self.claimed_receipts.append(receipt_id)
            return True

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            del resolution_action, resolution_scope, reason, resolved_at
            self.resolved.append(request_id)
            raise AssertionError("wrong target must not resolve locally")

    store = ApprovalStore(tmp_path / "guard-home")
    remote_approval = _signed_remote_approval(
        store,
        store.request_row,
        receipt_id="cloud-receipt-wrong-target",
    )

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            **job_extra,
            "payload": {
                "localRequestId": "request-target",
                "action": "allow_once",
                "remoteApproval": remote_approval,
                **payload_extra,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["failureCode"] == failure_code
    assert store.claimed_receipts == []
    assert store.resolved == []


def test_executor_releases_remote_once_receipt_when_resolution_not_applied(tmp_path: Path) -> None:
    class ApprovalStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.claimed_receipts: list[str] = []
            self.released_receipts: list[str] = []
            self.request_row = _approval_request_row("request-1")

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-1" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            del request_id, claimed_at
            self.claimed_receipts.append(receipt_id)
            return True

        def release_remote_once_receipt(self, receipt_id: str) -> None:
            self.released_receipts.append(receipt_id)

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            del request_id, resolution_action, resolution_scope, reason, resolved_at
            return {"resolved": False, "resolved_request": {}}

    store = ApprovalStore(tmp_path / "guard-home")
    remote_approval = _signed_remote_approval(store, store.request_row)
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "localRequestId": "request-1",
                "action": "allow_once",
                "remoteApproval": remote_approval,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["data"]["status"] == "not_resolved"
    assert result["data"]["daemonAckStatus"] == "not_resolved"
    assert result["data"]["resolution"]["status"] == "not_resolved"
    assert store.claimed_receipts == ["cloud-receipt-1"]
    assert store.released_receipts == ["cloud-receipt-1"]


def test_executor_normalizes_cloud_approval_action_aliases(tmp_path: Path) -> None:
    class ApprovalStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.resolved: list[dict[str, object]] = []
            self.request_row = _approval_request_row("request-alias")

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-alias" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            del receipt_id, request_id, claimed_at
            return True

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            self.resolved.append(
                {
                    "request_id": request_id,
                    "resolution_action": resolution_action,
                    "resolution_scope": resolution_scope,
                    "reason": reason,
                    "resolved_at": resolved_at,
                }
            )
            return {"resolved": True, "resolved_request": {"request_id": request_id}}

    store = ApprovalStore(tmp_path / "guard-home")
    remote_approval = _signed_remote_approval(
        store,
        store.request_row,
        decision="allow-once",
        receipt_id="cloud-receipt-alias",
    )

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "localRequestId": "request-alias",
                "action": "allowOnce",
                "remoteApproval": remote_approval,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["data"]["remoteDecision"] == "allow"
    assert store.resolved[0]["resolution_action"] == "allow"


def test_executor_rejects_duplicate_signed_receipt_without_resolving_again(tmp_path: Path) -> None:
    class ReplayStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.request_row = _approval_request_row("request-replay")
            self.resolved: list[str] = []

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-replay" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            del receipt_id, request_id, claimed_at
            return False

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            del resolution_action, resolution_scope, reason, resolved_at
            self.resolved.append(request_id)
            raise AssertionError("replayed receipt must not resolve locally")

    store = ReplayStore(tmp_path / "guard-home")
    remote_approval = _signed_remote_approval(
        store,
        store.request_row,
        receipt_id="cloud-receipt-replay",
    )

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "localRequestId": "request-replay",
                "action": "allow_once",
                "remoteApproval": remote_approval,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["failureCode"] == "remote_approval_replayed"
    assert store.resolved == []


def test_executor_uses_signed_remote_approval_decision_over_outer_payload(tmp_path: Path) -> None:
    class ApprovalStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.resolved: list[dict[str, object]] = []
            self.request_row = _approval_request_row("request-1")

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-1" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            del receipt_id, request_id, claimed_at
            return True

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            self.resolved.append(
                {
                    "request_id": request_id,
                    "resolution_action": resolution_action,
                    "resolution_scope": resolution_scope,
                    "reason": reason,
                    "resolved_at": resolved_at,
                }
            )
            return {"resolved": True, "resolved_request": {"request_id": request_id}}

    store = ApprovalStore(tmp_path / "guard-home")
    remote_approval = _signed_remote_approval(
        store,
        store.request_row,
        decision="block",
        receipt_id="cloud-receipt-block",
    )
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "localRequestId": "request-1",
                "action": "allow_once",
                "remoteApproval": remote_approval,
                "scope": "artifact",
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["data"]["status"] == "completed"
    assert store.resolved == [
        {
            "request_id": "request-1",
            "resolution_action": "block",
            "resolution_scope": "artifact",
            "reason": "Guard Cloud signed remote approval",
            "resolved_at": "2026-06-13T00:00:00+00:00",
        }
    ]


def test_executor_releases_remote_once_receipt_on_invalid_signed_decision(tmp_path: Path) -> None:
    class ApprovalStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.claimed_receipts: list[str] = []
            self.released_receipts: list[str] = []
            self.request_row = _approval_request_row("request-1")

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-1" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            del request_id, claimed_at
            self.claimed_receipts.append(receipt_id)
            return True

        def release_remote_once_receipt(self, receipt_id: str) -> None:
            self.released_receipts.append(receipt_id)

    store = ApprovalStore(tmp_path / "guard-home")
    remote_approval = _signed_remote_approval(store, store.request_row)
    remote_approval["decision"] = "future-decision"
    remote_approval["payloadHash"] = payload_hash_for_remote_approval_envelope(remote_approval)
    remote_approval["signature"] = sign_review_payload(remote_approval)

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "localRequestId": "request-1",
                "action": "allow_once",
                "remoteApproval": remote_approval,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["failureCode"] == "invalid_remote_approval_decision"
    assert store.claimed_receipts == ["cloud-receipt-1"]
    assert store.released_receipts == ["cloud-receipt-1"]


def test_executor_syncs_policy_without_local_request_id(tmp_path: Path) -> None:
    class PolicyStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.policies: list[tuple[list[dict[str, object]], str, bool]] = []

        def replace_remote_policies(
            self,
            decisions,
            generated_at: str,
            *,
            remote_write_authorized: bool = False,
        ) -> None:
            self.policies.append(
                ([decision.to_dict() for decision in decisions], generated_at, remote_write_authorized)
            )

    store = PolicyStore(tmp_path / "guard-home")
    bundle = _signed_decision_memory_bundle(store)
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "policy_sync",
                "decisionMemoryBundle": bundle,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["data"]["status"] == "accepted"
    assert result["data"]["localRequestId"] is None
    assert len(store.policies) == 1
    persisted_rows, generated_at, remote_write_authorized = store.policies[0]
    assert generated_at == "2026-06-13T00:00:00+00:00"
    assert remote_write_authorized is True
    assert len(persisted_rows) == 1
    persisted = persisted_rows[0]
    assert persisted["harness"] == "cursor"
    assert persisted["scope"] == "workspace"
    assert persisted["action"] == "allow"
    assert persisted["artifact_id"] == "plugin:hol/deploy"
    assert persisted["artifact_hash"] == "b" * 64
    assert persisted["workspace"] == "workspace-1"
    assert persisted["publisher"] is None
    assert persisted["reason"] == "Approved in cloud."
    assert persisted["owner"] is None
    assert persisted["source"] == "cloud-signed-memory"
    assert isinstance(persisted["expires_at"], str)
    assert result["data"]["decisionMemoryAck"]["status"] == "accepted"


def test_executor_rejects_overbroad_signed_allow_memory_rules(tmp_path: Path) -> None:
    class PolicyStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.policies: list[tuple[list[dict[str, object]], str, bool]] = []

        def replace_remote_policies(
            self,
            decisions,
            generated_at: str,
            *,
            remote_write_authorized: bool = False,
        ) -> None:
            assert remote_write_authorized is True
            self.policies.append(
                ([decision.to_dict() for decision in decisions], generated_at, remote_write_authorized)
            )

    store = PolicyStore(tmp_path / "guard-home")
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "policy_sync",
                "decisionMemoryBundle": _signed_decision_memory_bundle(
                    store,
                    rule_scope="team",
                    action="allow",
                    rule_id="review-memory:receipt-team",
                    policy_version="policy-version-3",
                ),
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["data"]["status"] == "rejected"
    assert result["data"]["decisionMemoryAck"]["rejectedRuleIds"] == ["review-memory:receipt-team"]
    assert store.policies == [([], "2026-06-13T00:00:00+00:00", True)]
    assert store.get_sync_payload("guard_review_memory_policy_version") is None


def test_executor_rejects_tampered_decision_memory_bundle_hash(tmp_path: Path) -> None:
    store = _oauth_store(tmp_path)
    bundle = _signed_decision_memory_bundle(store)
    bundle["bundleHash"] = "sha256:tampered"
    bundle["payloadHash"] = "sha256:tampered"
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "policy_sync",
                "decisionMemoryBundle": bundle,
            },
        },
        context=_context(tmp_path),
        store=store,
        now=lambda: "2026-06-13T00:00:00+00:00",
    )
    assert "failureCode" in result
    assert "hash" in result["failureCode"]


def test_executor_rejects_expired_decision_memory_bundle(tmp_path: Path) -> None:
    store = _oauth_store(tmp_path)
    bundle = _signed_decision_memory_bundle(store)
    expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    bundle["expiresAt"] = expired
    for rule in bundle.get("memoryRules", []):
        rule["expiresAt"] = expired
    bundle["payloadHash"] = payload_hash_for_decision_memory_bundle(bundle)
    bundle["bundleHash"] = bundle["payloadHash"]
    bundle["signature"] = sign_review_payload(bundle)
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "policy_sync",
                "decisionMemoryBundle": bundle,
            },
        },
        context=_context(tmp_path),
        store=store,
        now=lambda: "2026-06-13T00:00:00+00:00",
    )
    assert "failureCode" in result
    assert "expired" in result["failureCode"]


def test_executor_rejects_decision_memory_bundle_wrong_workspace(tmp_path: Path) -> None:
    store = _oauth_store(tmp_path)
    bundle = _signed_decision_memory_bundle(store)
    bundle["workspaceId"] = "workspace-other"
    for rule in bundle.get("memoryRules", []):
        rule["target"]["workspaceIds"] = ["workspace-other"]
    bundle["payloadHash"] = payload_hash_for_decision_memory_bundle(bundle)
    bundle["bundleHash"] = bundle["payloadHash"]
    bundle["signature"] = sign_review_payload(bundle)
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "policy_sync",
                "decisionMemoryBundle": bundle,
            },
        },
        context=_context(tmp_path),
        store=store,
        now=lambda: "2026-06-13T00:00:00+00:00",
    )
    assert "failureCode" in result


def test_executor_rejects_decision_memory_bundle_wrong_machine_target(tmp_path: Path) -> None:
    store = _oauth_store(tmp_path)
    bundle = _signed_decision_memory_bundle(store)
    for rule in bundle.get("memoryRules", []):
        rule["target"]["machineIds"] = ["machine-other"]
    bundle["payloadHash"] = payload_hash_for_decision_memory_bundle(bundle)
    bundle["bundleHash"] = bundle["payloadHash"]
    bundle["signature"] = sign_review_payload(bundle)
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "policy_sync",
                "decisionMemoryBundle": bundle,
            },
        },
        context=_context(tmp_path),
        store=store,
        now=lambda: "2026-06-13T00:00:00+00:00",
    )
    assert "failureCode" in result


def test_executor_rejects_loose_policy_memory_payload(tmp_path: Path) -> None:
    store = _oauth_store(tmp_path)
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "policy_sync",
                "policyMemory": {
                    "action": "allow",
                    "artifactId": "plugin:hol/deploy",
                    "scope": "workspace",
                    "reason": "Should be rejected - no signed bundle",
                },
            },
        },
        context=_context(tmp_path),
        store=store,
        now=lambda: "2026-06-13T00:00:00+00:00",
    )
    assert "failureCode" in result
    assert "missing" in result["failureCode"]


def test_executor_rejects_remote_approval_for_removed_one_time_scope(tmp_path: Path) -> None:
    class RemovedScopeStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.claimed_receipts: list[str] = []
            self.resolved: list[dict[str, object]] = []
            self.request_row = _approval_request_row(
                "request-removed-scope",
                policy_action="require-reapproval",
                recommended_scope="one-time",
            )

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-removed-scope" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            del request_id, claimed_at
            self.claimed_receipts.append(receipt_id)
            return True

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            self.resolved.append(
                {
                    "request_id": request_id,
                    "resolution_action": resolution_action,
                    "resolution_scope": resolution_scope,
                    "reason": reason,
                    "resolved_at": resolved_at,
                }
            )
            return {"resolved": True, "resolved_request": {"request_id": request_id}}

    store = RemovedScopeStore(tmp_path / "guard-home")
    remote_approval = _signed_remote_approval(store, store.request_row)

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "localRequestId": "request-removed-scope",
                "action": "allow_once",
                "remoteApproval": remote_approval,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )
    assert result["failureCode"] == "invalid_remote_approval_scope"
    assert store.claimed_receipts == []
    assert store.resolved == []


def test_executor_resolves_block_policy_action_with_workspace_allow(tmp_path: Path) -> None:
    """Prove policy_action='block' can be remotely allowed with the requested scope."""

    class WorkspaceAllowStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.request_row = _approval_request_row(
                "request-workspace-allow",
                policy_action="block",
                recommended_scope="workspace",
            )
            self.resolved: list[dict[str, object]] = []
            self.claimed_receipts: list[dict[str, str]] = []

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-workspace-allow" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            self.claimed_receipts.append({"receipt_id": receipt_id})
            return True

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            self.resolved.append(
                {
                    "request_id": request_id,
                    "resolution_action": resolution_action,
                    "resolution_scope": resolution_scope,
                }
            )
            return {"resolved": True, "resolved_request": {"request_id": request_id}}

    store = WorkspaceAllowStore(tmp_path / "guard-home")
    remote_approval = _signed_remote_approval(store, store.request_row)
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "allow_once",
                "localRequestId": "request-workspace-allow",
                "remoteApproval": remote_approval,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["generatedAt"] == "2026-06-13T00:00:00+00:00"
    assert result["data"]["status"] == "completed"
    assert store.resolved == [
        {
            "request_id": "request-workspace-allow",
            "resolution_action": "allow",
            "resolution_scope": "workspace",
        }
    ]
    assert len(store.claimed_receipts) == 1


def test_executor_resolves_harness_scope_with_block(tmp_path: Path) -> None:
    """Prove `recommended_scope='harness'` flows into `resolution_scope` on block."""

    class HarnessBlockStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.request_row = _approval_request_row(
                "request-harness-block",
                policy_action="require-reapproval",
                recommended_scope="harness",
            )
            self.resolved: list[dict[str, object]] = []
            self.claimed_receipts: list[dict[str, str]] = []

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-harness-block" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            self.claimed_receipts.append({"receipt_id": receipt_id})
            return True

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            self.resolved.append(
                {
                    "request_id": request_id,
                    "resolution_action": resolution_action,
                    "resolution_scope": resolution_scope,
                }
            )
            return {"resolved": True, "resolved_request": {"request_id": request_id}}

    store = HarnessBlockStore(tmp_path / "guard-home")
    remote_approval = _signed_remote_approval(store, store.request_row, decision="block")
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "allow_once",
                "localRequestId": "request-harness-block",
                "remoteApproval": remote_approval,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["generatedAt"] == "2026-06-13T00:00:00+00:00"
    assert result["data"]["status"] == "completed"
    assert store.resolved == [
        {
            "request_id": "request-harness-block",
            "resolution_action": "block",
            "resolution_scope": "harness",
        }
    ]
    assert len(store.claimed_receipts) == 1


def test_executor_attaches_codex_resume_live_hook_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CodexStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.request_row = _approval_request_row("request-codex-live", harness="codex")

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-codex-live" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            del receipt_id, request_id, claimed_at
            return True

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            del resolution_action, resolution_scope, reason, resolved_at
            return {"resolved": True, "resolved_request": {"request_id": request_id}}

    store = CodexStore(tmp_path / "guard-home")
    monkeypatch.setattr(
        command_executors,
        "defer_request_resume_to_live_hook",
        lambda *_args, **_kwargs: {
            "status": "pending",
            "reason": "live_hook_waiting",
            "message": "Codex is still waiting.",
            "thread_id": "thread-secret",
        },
    )
    monkeypatch.setattr(
        command_executors,
        "retry_request_resume",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("live hook should consume resume")),
    )
    remote_approval = _signed_remote_approval(store, store.request_row)

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "allow_once",
                "localRequestId": "request-codex-live",
                "remoteApproval": remote_approval,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    data = result["data"]
    assert data["codexResume"]["status"] == "pending"
    assert data["codex_resume"] == data["codexResume"]
    assert data["resumeStatus"] == "pending"
    assert "thread-secret" not in str(data)


def test_executor_attaches_codex_resume_retry_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CodexStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.request_row = _approval_request_row("request-codex-retry", harness="codex")

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-codex-retry" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            del receipt_id, request_id, claimed_at
            return True

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            del resolution_action, resolution_scope, reason, resolved_at
            return {"resolved": True, "resolved_request": {"request_id": request_id}}

    store = CodexStore(tmp_path / "guard-home")
    monkeypatch.setattr(command_executors, "defer_request_resume_to_live_hook", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        command_executors,
        "retry_request_resume",
        lambda *_args, **_kwargs: {
            "status": "sent",
            "message": "Continuation sent.",
            "sent_at": "2026-06-13T00:00:00+00:00",
            "thread_id": "thread-secret",
        },
    )
    remote_approval = _signed_remote_approval(store, store.request_row)

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "allow_once",
                "localRequestId": "request-codex-retry",
                "remoteApproval": remote_approval,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    data = result["data"]
    assert data["codexResume"]["status"] == "sent"
    assert data["resumeStatus"] == "sent"
    assert data["resumeCompletedAt"] == "2026-06-13T00:00:00+00:00"
    assert "thread-secret" not in str(data)


def test_executor_attaches_pi_harness_resume_without_token(tmp_path: Path) -> None:
    class PiStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.request_row = _approval_request_row("request-pi", harness="pi")
            self.operation = {
                "operation_id": "pi-operation",
                "session_id": "pi-session",
                "harness": "oh-my-pi",
                "operation_type": "tool_call",
                "status": "waiting_on_approval",
                "approval_request_ids": ["request-pi"],
                "resume_token": "resume-token-secret",
                "metadata": {},
            }
            self.events: list[dict[str, object]] = []

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-pi" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            del receipt_id, request_id, claimed_at
            return True

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            del resolution_action, resolution_scope, reason, resolved_at
            return {"resolved": True, "resolved_request": {"request_id": request_id}}

        def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object] | None:
            return dict(self.operation) if request_id == "request-pi" else None

        def upsert_guard_operation(self, **kwargs: object) -> dict[str, object]:
            self.operation.update(kwargs)
            return dict(self.operation)

        def add_event(self, event_name: str, payload: dict[str, object], occurred_at: str) -> None:
            self.events.append({"event_name": event_name, "payload": payload, "occurred_at": occurred_at})

    store = PiStore(tmp_path / "guard-home")
    remote_approval = _signed_remote_approval(store, store.request_row)

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "allow_once",
                "localRequestId": "request-pi",
                "remoteApproval": remote_approval,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    data = result["data"]
    assert data["harnessResume"]["status"] == "resumed"
    assert data["harness_resume"] == data["harnessResume"]
    assert data["resumeStatus"] == "resumed"
    assert "codexResume" not in data
    assert "resume-token-secret" not in str(data)
    assert store.operation["status"] == "resumed"
    assert store.events[0]["event_name"] == "harness/operation_resume"


def test_validated_remote_approval_envelope_accepts_workspace_scope(tmp_path: Path) -> None:
    """The envelope validator must accept daemon decision scopes beyond artifact."""

    class WorkspaceEnvelopeStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.request_row = _approval_request_row(
                "request-workspace-envelope",
                policy_action="require-reapproval",
                recommended_scope="workspace",
            )

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-workspace-envelope" else None

    store = WorkspaceEnvelopeStore(tmp_path)
    envelope = _signed_remote_approval(store, store.request_row)
    assert envelope["scope"] == "workspace"

    validated = validated_remote_approval_envelope(envelope, store=store)
    assert validated["scope"] == "workspace"


def test_validated_remote_approval_envelope_rejects_unsupported_scope(tmp_path: Path) -> None:
    """The envelope validator must reject scopes outside daemon decision scopes."""

    class UnsupportedEnvelopeStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.request_row = _approval_request_row(
                "request-bad-envelope",
                policy_action="require-reapproval",
                recommended_scope="one-time",
            )

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-bad-envelope" else None

    store = UnsupportedEnvelopeStore(tmp_path)
    envelope = _signed_remote_approval(store, store.request_row)
    with pytest.raises(GuardReviewContractError, match="invalid_remote_approval_scope"):
        validated_remote_approval_envelope(envelope, store=store)


def test_binding_rejects_remote_approval_envelope_scope_mismatch(tmp_path: Path) -> None:
    """A signed envelope whose scope differs from the request recommended_scope is rejected."""

    class MismatchScopeStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.request_row = _approval_request_row(
                "request-scope-mismatch",
                policy_action="require-reapproval",
                recommended_scope="artifact",
            )

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-scope-mismatch" else None

    store = MismatchScopeStore(tmp_path)
    # Build a validly-signed envelope with scope='workspace' against an 'artifact' request.
    envelope = _signed_remote_approval(store, store.request_row, scope="workspace")
    oauth = guard_review_oauth_metadata(store)
    with pytest.raises(GuardReviewContractError, match="remote_approval_scope_mismatch"):
        validate_remote_approval_request_binding(
            envelope=envelope,
            request_row=store.request_row,
            oauth=oauth,
            store=store,
        )


def test_executor_rejects_remote_approval_envelope_scope_mismatch(tmp_path: Path) -> None:
    """A workspace envelope cannot bind to an artifact request through the executor path."""

    class MismatchScopeExecutorStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.claimed_receipts: list[str] = []
            self.resolved: list[dict[str, object]] = []
            self.request_row = _approval_request_row(
                "request-scope-mismatch-exec",
                policy_action="require-reapproval",
                recommended_scope="artifact",
            )

        def get_approval_request(self, request_id: str) -> dict[str, object] | None:
            return self.request_row if request_id == "request-scope-mismatch-exec" else None

        def claim_remote_once_receipt(
            self,
            receipt_id: str,
            *,
            request_id: str,
            claimed_at: str,
        ) -> bool:
            del request_id, claimed_at
            self.claimed_receipts.append(receipt_id)
            return True

        def resolve_request_with_signed_remote_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            signed_remote_result: dict[str, object],
        ) -> dict[str, object]:
            del resolution_action, resolution_scope, reason, signed_remote_result
            self.resolved.append({"request_id": request_id})
            return {"resolved": True, "resolved_request": {"request_id": request_id}}

    store = MismatchScopeExecutorStore(tmp_path / "guard-home")
    # Envelope scope is 'workspace' but the request recommends 'artifact'.
    remote_approval = _signed_remote_approval(
        store,
        store.request_row,
        receipt_id="cloud-receipt-scope-mismatch",
        scope="workspace",
    )
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "localRequestId": "request-scope-mismatch-exec",
                "action": "allow_once",
                "remoteApproval": remote_approval,
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )
    assert result["failureCode"] == "remote_approval_scope_mismatch"
    assert store.claimed_receipts == []
    assert store.resolved == []
