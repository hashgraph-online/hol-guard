from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import store as guard_store_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.daemon import client as daemon_client_module
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
    validated_decision_memory_bundle,
    validated_remote_approval_envelope,
)
from codex_plugin_scanner.guard.runtime import (
    command_executors,
    command_queue,
    command_queue_authority,
    local_request_snapshots,
)
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_oauth_token_support import oauth_binding_access_token
from tests.guard_review_signing_helpers import (
    REVIEW_SIGNING_KEY_ID,
    review_trusted_keyring_payload,
    review_verification_keys,
    sign_review_payload,
)


@pytest.fixture(autouse=True)
def _default_store_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux", raising=False)


@pytest.fixture(autouse=True)
def _isolate_legacy_queue_mechanics(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        command_queue,
        "command_capability_operations",
        lambda _store: command_executors.SUPPORTED_COMMAND_OPERATIONS,
    )
    monkeypatch.setattr(
        command_queue,
        "command_capability_status",
        lambda _store: {
            "enabled": True,
            "operations": list(command_executors.SUPPORTED_COMMAND_OPERATIONS),
            "pending_commands": [],
        },
    )
    monkeypatch.setattr(
        command_queue_authority,
        "authorize_command_job",
        lambda _store, job, **_kwargs: SimpleNamespace(
            identity={"id": job.get("id")},
            operation=job.get("operation"),
            requires_local_approval=False,
        ),
    )
    monkeypatch.setattr(command_queue, "consume_local_command_approval", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(command_queue, "mark_command_job_consumed", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(command_queue, "audit_command_decision", lambda *_args, **_kwargs: None)


def _block_local_daemon_client(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("Guard Cloud command execution must not use the local daemon client.")

    monkeypatch.setattr(daemon_client_module, "load_guard_surface_daemon_client", fail)


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
            "device_id": "machine-1",
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
        "reviewerRole": "owner",
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


def _execute_command(
    tmp_path: Path,
    job: dict[str, object],
    *,
    store: FakeStore | None = None,
) -> dict[str, object]:
    return command_executors.execute_guard_command_job(
        job,
        context=_context(tmp_path),
        store=store or FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )


def _signed_decision_memory_bundle(
    store: FakeStore,
    *,
    rule_scope: str = "workspace",
    action: str = "allow",
    rule_id: str = "review-memory:receipt-1",
    policy_version: str = "policy-version-2",
) -> dict[str, object]:
    decision_memory_keys = review_verification_keys(workspace_id=None, purpose="unscoped")
    store.set_sync_payload(
        "policy_bundle_keyring",
        decision_memory_keys,
        datetime.now(timezone.utc).isoformat(),
    )
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
        "verificationKeys": decision_memory_keys,
        "signatureAlgorithm": "rsa-pss-sha256",
        "workspaceId": oauth.workspace_id,
    }
    payload_hash = payload_hash_for_decision_memory_bundle(bundle)
    bundle["bundleHash"] = payload_hash
    bundle["payloadHash"] = payload_hash
    bundle["signature"] = sign_review_payload(bundle)
    return bundle


def test_decision_memory_accepts_its_unscoped_signing_authority(tmp_path: Path) -> None:
    store = FakeStore(tmp_path / "guard-home")
    bundle = _signed_decision_memory_bundle(store)
    assert validated_decision_memory_bundle(bundle, store=store) == bundle


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
        device_id="machine-1",
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


@pytest.mark.parametrize(
    ("trusted_keyring", "expected_error"),
    [
        (
            review_trusted_keyring_payload(purpose="policy_bundle"),
            "signing_key_purpose_mismatch",
        ),
        (
            review_trusted_keyring_payload(workspace_id="workspace-2"),
            "signing_key_workspace_mismatch",
        ),
    ],
)
def test_remote_approval_rejects_signing_key_outside_its_authority(
    tmp_path: Path,
    trusted_keyring: list[dict[str, object]],
    expected_error: str,
) -> None:
    store = FakeStore(tmp_path / "guard-home")
    request_row = _approval_request_row("request-wrong-key-authority")
    envelope = _signed_remote_approval(store, request_row)
    store.payloads["policy_bundle_keyring"] = trusted_keyring

    with pytest.raises(GuardReviewContractError, match=expected_error):
        validated_remote_approval_envelope(envelope, store=store)


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


@pytest.mark.parametrize("redaction_level", ["full", "none"])
def test_cloud_review_payload_preserves_exact_action_across_redaction_levels(
    redaction_level: str,
) -> None:
    row = {
        **_approval_request_row("req-exact-sandbox-action"),
        "policy_action": "sandbox-required",
        "action_envelope_json": {
            "action_type": "shell_command",
            "command": "python build.py",
            "pre_execution_result": "sandbox-required",
        },
    }

    payload = local_request_snapshots._cloud_safe_local_request_payload(
        row,
        redaction_level=redaction_level,
    )

    envelope = payload["action_envelope_json"]
    assert isinstance(envelope, dict)
    assert payload["policy_action"] == "sandbox-required"
    assert payload["policyAction"] == "sandbox-required"
    assert envelope["policy_action"] == "sandbox-required"
    assert envelope["policyAction"] == "sandbox-required"
    assert envelope["pre_execution_result"] == "sandbox-required"
    assert envelope["preExecutionResult"] == "sandbox-required"


def test_cloud_review_payload_projects_missing_legacy_action_fail_closed() -> None:
    row = _approval_request_row("req-legacy-missing-action")
    row.pop("policy_action")

    payload = local_request_snapshots._cloud_safe_local_request_payload(
        row,
        redaction_level="full",
    )

    assert payload["policy_action"] == "require-reapproval"
    assert payload["policyAction"] == "require-reapproval"


def test_cloud_review_payload_rejects_explicit_unknown_action() -> None:
    row = {
        **_approval_request_row("req-explicit-unknown-action"),
        "policy_action": "require-approval",
    }

    with pytest.raises(ValueError, match="authoritative_decision_inconsistent"):
        local_request_snapshots._cloud_safe_local_request_payload(
            row,
            redaction_level="full",
        )


def test_cloud_action_envelope_matches_the_dashboard_round_trip_fixture() -> None:
    fixture_path = (
        Path(__file__).resolve().parents[1] / "dashboard" / "src" / "test-fixtures" / "cloud-action-envelope.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

    actual = local_request_snapshots._cloud_safe_action_envelope(
        {
            "action_type": "shell_command",
            "command": "python build.py",
            "pre_execution_result": "sandbox-required",
        },
        redaction_level="full",
        reason="Sandbox execution is required.",
        policy_action="sandbox-required",
        fallback_action_id="req-cloud-round-trip",
        fallback_harness="codex",
    )

    assert actual == fixture


@pytest.mark.parametrize(
    ("snake_key", "camel_key"),
    [
        ("action_id", "actionId"),
        ("action_type", "actionType"),
        ("policy_action", "policyAction"),
        ("pre_execution_result", "preExecutionResult"),
    ],
)
def test_cloud_action_envelope_rejects_conflicting_documented_aliases(
    snake_key: str,
    camel_key: str,
) -> None:
    envelope: dict[str, object] = {
        "action_id": "same-action",
        "actionId": "same-action",
        "action_type": "shell_command",
        "actionType": "shell_command",
        "policy_action": "allow",
        "policyAction": "allow",
        "pre_execution_result": "allow",
        "preExecutionResult": "allow",
    }
    envelope[camel_key] = "block" if "policy" in snake_key or "execution" in snake_key else "different"

    with pytest.raises(ValueError, match="authoritative_decision_inconsistent"):
        local_request_snapshots._cloud_safe_action_envelope(
            envelope,
            redaction_level="full",
            policy_action="allow",
        )


def test_cloud_review_payload_rejects_an_envelope_action_that_differs_from_outer_authority() -> None:
    row = {
        **_approval_request_row("req-contradictory-cloud-action"),
        "policy_action": "allow",
        "action_envelope_json": {
            "action_type": "shell_command",
            "pre_execution_result": "block",
        },
    }

    with pytest.raises(ValueError, match="authoritative_decision_inconsistent"):
        local_request_snapshots._cloud_safe_local_request_payload(row, redaction_level="full")


def test_command_queue_enabled_defaults_off_without_local_capability(monkeypatch) -> None:
    monkeypatch.delenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, raising=False)

    assert command_queue.command_queue_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_command_queue_environment_cannot_grant_capability(value: str, monkeypatch) -> None:
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, value)

    assert command_queue.command_queue_enabled() is False


def test_command_queue_requires_store_with_local_capability(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, raising=False)

    assert command_queue.command_queue_enabled(FakeStore(tmp_path / "guard-home")) is True  # type: ignore[arg-type]


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
                "operations": [
                    operation
                    for operation in command_executors.SUPPORTED_COMMAND_OPERATIONS
                    if operation not in command_executors.EXACT_CLOUD_REVIEW_OPERATIONS
                ],
                "schemaVersions": {
                    operation: command_executors.COMMAND_OPERATION_SCHEMA_VERSIONS[operation]
                    for operation in command_executors.SUPPORTED_COMMAND_OPERATIONS
                    if operation not in command_executors.EXACT_CLOUD_REVIEW_OPERATIONS
                },
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
            "access_token": oauth_binding_access_token("machine-1", "grant-1", "machine-1", "workspace-1"),
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
    assert len(set(observed_access_tokens)) == 1
    credentials = store.get_oauth_local_credentials()
    assert credentials is not None
    assert credentials["refresh_token"] == "refresh-token-2"
    assert credentials["access_token"] == observed_access_tokens[0]
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
            self.alive = True

        def is_alive(self) -> bool:
            return self.alive

        def start(self) -> None:
            self.started = True

        def join(self, timeout: float | None = None) -> None:
            del timeout
            self.alive = False

    class FakeEvent:
        def __init__(self, stopped: bool = False) -> None:
            self.stopped = stopped

        def is_set(self) -> bool:
            return self.stopped

        def set(self) -> None:
            self.stopped = True

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
    result = _execute_command(
        tmp_path, {"operation": "guard.packageShims.install", "payload": {"managers": ["npm", "npm"]}}
    )
    assert result["failureCode"] == "duplicate_manager"


def test_executor_status_ignores_speculative_managers_field(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(command_executors, "package_shim_status", lambda context: {"active_managers": []})

    result = _execute_command(
        tmp_path, {"operation": "guard.packageShims.status", "payload": {"managers": ["not-a-manager"]}}
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

    result = _execute_command(
        tmp_path, {"operation": "guard.app.connect", "payload": {"harness": "codex", "surface": "cli"}}
    )
    assert calls == [("install", "codex", "cli")]
    assert result["generatedAt"] == "2026-06-13T00:00:00+00:00"
    assert isinstance(result["data"], dict)


def test_executor_returns_waiting_local_confirm_for_package_shim_remove(tmp_path: Path) -> None:
    result = _execute_command(tmp_path, {"operation": "guard.packageShims.remove", "payload": {"managers": ["npm"]}})
    assert result["waitingLocalConfirm"] is True
    assert result["data"] == {
        "confirm_command": "hol-guard package-shims uninstall --manager npm",
        "managers": ["npm"],
        "summary": ("Run the local package-shim uninstall command on this machine to confirm removal for npm."),
    }


def test_executor_returns_waiting_local_confirm_for_package_shim_remove_all_managers(tmp_path: Path) -> None:
    result = _execute_command(tmp_path, {"operation": "guard.packageShims.remove", "payload": {}})
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


def test_validated_remote_approval_envelope_accepts_workspace_scope(tmp_path: Path) -> None:
    """The envelope validator must accept daemon decision scopes beyond artifact."""

    row = _approval_request_row(
        "request-workspace-envelope",
        policy_action="require-reapproval",
        recommended_scope="workspace",
    )
    store = FakeStore(tmp_path / "guard-home")
    envelope = _signed_remote_approval(store, row)
    assert envelope["scope"] == "workspace"

    validated = validated_remote_approval_envelope(envelope, store=store)
    assert validated["scope"] == "workspace"


def test_validated_remote_approval_envelope_rejects_unsupported_scope(tmp_path: Path) -> None:
    """The envelope validator must reject scopes outside daemon decision scopes."""

    row = _approval_request_row(
        "request-bad-envelope",
        policy_action="require-reapproval",
        recommended_scope="one-time",
    )
    store = FakeStore(tmp_path / "guard-home")
    envelope = _signed_remote_approval(store, row)
    with pytest.raises(GuardReviewContractError, match="invalid_remote_approval_scope"):
        validated_remote_approval_envelope(envelope, store=store)


def test_binding_rejects_remote_approval_envelope_scope_mismatch(tmp_path: Path) -> None:
    """A signed envelope whose scope differs from the request recommended_scope is rejected."""

    row = _approval_request_row(
        "request-scope-mismatch",
        policy_action="require-reapproval",
        recommended_scope="artifact",
    )
    store = FakeStore(tmp_path / "guard-home")
    # Build a validly-signed envelope with scope='workspace' against an 'artifact' request.
    envelope = _signed_remote_approval(store, row, scope="workspace")
    oauth = guard_review_oauth_metadata(store)
    with pytest.raises(GuardReviewContractError, match="remote_approval_scope_mismatch"):
        validate_remote_approval_request_binding(
            envelope=envelope,
            request_row=row,
            oauth=oauth,
            store=store,
        )
