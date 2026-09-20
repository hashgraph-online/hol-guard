"""Explicit local consent binds exact source through durable review and receipt sync."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from codex_plugin_scanner.guard.approvals import queue_blocked_approvals
from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.memory_decision_outbox import _ensure_source_receipt_id
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.policy_memory_source import (
    capture_policy_memory_source_input,
    verified_request_policy_memory_source,
)
from codex_plugin_scanner.guard.receipts.manager import build_receipt
from codex_plugin_scanner.guard.review_contracts import (
    build_local_review_request_claim,
    compute_local_review_request_claim_hash,
)
from codex_plugin_scanner.guard.review_oauth_binding import guard_review_oauth_metadata
from codex_plugin_scanner.guard.runtime.command_capability import (
    COMMAND_CAPABILITY_STATE_KEY,
    CommandCapabilityError,
    issue_command_capability,
    revoke_command_capability,
)
from codex_plugin_scanner.guard.runtime.command_executors import SUPPORTED_COMMAND_OPERATIONS
from codex_plugin_scanner.guard.runtime.runner import _cloud_sync_receipt_payload
from tests.test_guard_command_capability import _connected_store as _connected_command_store

_COMMAND = "\tprintf 'Synthetic  Value'\r\n"
_WORKSPACE_ID = "00000000-0000-4000-8000-000000000001"


def _connected_store(tmp_path):
    store = _connected_command_store(tmp_path)
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    store.set_oauth_local_credentials(
        issuer=credentials["issuer"],
        client_id=credentials["client_id"],
        refresh_token=credentials["refresh_token"],
        dpop_private_key_pem=credentials["dpop_private_key_pem"],
        dpop_public_jwk=credentials["dpop_public_jwk"],
        dpop_public_jwk_thumbprint=credentials["dpop_public_jwk_thumbprint"],
        device_id=credentials["device_id"],
        grant_id=credentials["grant_id"],
        machine_id=store.get_or_create_installation_id(),
        workspace_id=_WORKSPACE_ID,
        now=datetime.now(timezone.utc).isoformat(),
    )
    return store


def _grant(store, *, disclose=True, redaction="none"):
    update_guard_settings(store.guard_home, {"receipt_redaction_level": redaction})
    return issue_command_capability(
        store,
        operations=("guard.review.syncPolicyMemory",),
        supported_operations=SUPPORTED_COMMAND_OPERATIONS,
        share_policy_source=disclose,
    )


def _capture(store, *, command=_COMMAND, redaction="none"):
    return capture_policy_memory_source_input(
        store,
        payload={"tool_name": "Bash", "tool_input": {"command": command}},
        harness="codex",
        artifact_id="synthetic:tool",
        redaction_level=redaction,
    )


def _queue(store, captured):
    artifact = GuardArtifact(
        artifact_id="synthetic:tool",
        name="Bash",
        harness="codex",
        artifact_type="shell_command",
        source_scope="project",
        config_path="",
        command="display withheld",
    )
    return queue_blocked_approvals(
        detection=HarnessDetection("codex", True, True, (), (artifact,)),
        evaluation={
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "artifact_hash": "a" * 64,
                    "policy_action": "review",
                    "_policyMemorySourceInput": captured,
                }
            ]
        },
        store=store,
        approval_center_url="http://127.0.0.1:8765",
        notify=False,
        redaction_level="none",
    )[0]


def test_actual_durable_request_claim_and_receipt_transport_preserve_exact_source(tmp_path):
    store = _connected_store(tmp_path)
    _grant(store)
    request = _queue(store, _capture(store))
    source = verified_request_policy_memory_source(store, request)
    assert source is not None and source["commandText"] == _COMMAND
    assert source["localRequestId"] == request["request_id"]
    assert source["installationId"] == store.get_device_metadata()["installation_id"]
    claim = build_local_review_request_claim(request_row=request, oauth=guard_review_oauth_metadata(store), store=store)
    assert claim["policyMemorySource"] == source
    changed = {**claim, "policyMemorySource": {**source, "commandText": _COMMAND.strip()}}
    assert compute_local_review_request_claim_hash(changed) != claim["claimHash"]
    receipt_id = _ensure_source_receipt_id(store, request, decision_action="approved", scope="workspace")
    assert receipt_id is not None
    receipt = store.get_receipt(receipt_id)
    assert receipt is not None
    assert "_policyMemorySource" not in receipt["envelope_redacted_json"]
    assert "policyMemorySource" not in receipt["envelope_redacted_json"]
    transported = _cloud_sync_receipt_payload(
        receipt, device_id="synthetic", device_name="Synthetic", redaction_level="none", store=store
    )
    assert transported["envelopeRedacted"]["policyMemorySource"] == source
    for redaction in ("partial", "full"):
        transport = _cloud_sync_receipt_payload(
            receipt, device_id="synthetic", device_name="Synthetic", redaction_level=redaction, store=store
        )
        assert "policyMemorySource" not in transport.get("envelopeRedacted", {})
    revoke_command_capability(store)
    assert verified_request_policy_memory_source(store, request) is None
    transport = _cloud_sync_receipt_payload(
        receipt, device_id="synthetic", device_name="Synthetic", redaction_level="none", store=store
    )
    assert "policyMemorySource" not in transport.get("envelopeRedacted", {})


@pytest.mark.parametrize(
    "disclose,local_redaction,projection",
    [
        (False, "none", "none"),
        (True, "full", "none"),
        (True, "partial", "none"),
        (True, "none", "partial"),
        (True, "none", "full"),
    ],
)
def test_disclosure_requires_both_explicit_capability_and_unredacted_privacy(
    tmp_path, disclose, local_redaction, projection
):
    store = _connected_store(tmp_path)
    _grant(store, disclose=disclose, redaction=local_redaction)
    assert _capture(store, redaction=projection) is None


def test_legacy_capability_does_not_grant_disclosure_and_other_operations_cannot(tmp_path):
    store = _connected_store(tmp_path)
    _grant(store, disclose=False)
    assert _capture(store) is None
    with pytest.raises(CommandCapabilityError, match="requires_isolated_memory"):
        issue_command_capability(
            store,
            operations=("guard.packageShims.status",),
            supported_operations=SUPPORTED_COMMAND_OPERATIONS,
            share_policy_source=True,
        )


def test_deduplication_rebinds_to_actual_request_id_and_tampering_cannot_disclose(tmp_path):
    store = _connected_store(tmp_path)
    _grant(store)
    request = _queue(store, _capture(store))
    repeated = _queue(store, _capture(store))
    assert repeated["request_id"] == request["request_id"]
    assert verified_request_policy_memory_source(store, repeated)["localRequestId"] == request["request_id"]
    corrupted = copy.deepcopy(repeated)
    corrupted["action_envelope_json"]["_policyMemorySource"]["source"]["commandText"] += " modified"
    assert verified_request_policy_memory_source(store, corrupted) is None
    for key in ("artifact_id", "harness", "request_id"):
        assert verified_request_policy_memory_source(store, {**repeated, key: "unrelated"}) is None
    old = repeated
    _grant(store)
    assert verified_request_policy_memory_source(store, old) is None


def test_expiry_and_forged_capability_flag_fail_closed(tmp_path):
    store = _connected_store(tmp_path)
    _grant(store)
    request = _queue(store, _capture(store))
    future = (datetime.now(timezone.utc) + timedelta(days=31)).isoformat()
    assert verified_request_policy_memory_source(store, request, now=future) is None
    capability = store.get_sync_payload(COMMAND_CAPABILITY_STATE_KEY)
    capability["sharePolicySource"] = False
    store.set_sync_payload(COMMAND_CAPABILITY_STATE_KEY, capability, datetime.now(timezone.utc).isoformat())
    assert verified_request_policy_memory_source(store, request) is None


def test_unsigned_display_or_envelope_fields_never_become_exact_source(tmp_path):
    store = _connected_store(tmp_path)
    _grant(store)
    request = _queue(store, None)
    assert verified_request_policy_memory_source(store, request) is None
    assert "policyMemorySource" not in build_local_review_request_claim(
        request_row=request, oauth=guard_review_oauth_metadata(store), store=store
    )
    receipt = {
        "receipt_id": "synthetic-receipt",
        "envelope_redacted_json": {"policyMemorySource": {"commandText": _COMMAND}},
    }
    assert "policyMemorySource" not in _cloud_sync_receipt_payload(
        receipt, device_id="synthetic", device_name="Synthetic"
    ).get("envelopeRedacted", {})


def test_actual_generic_hook_captures_original_shell_field_before_display_projection(tmp_path, monkeypatch, capsys):
    from codex_plugin_scanner.guard.cli import commands_hook_generic
    from codex_plugin_scanner.guard.config import GuardConfig
    from tests.test_guard_approval_precedence_generic_stdio import _run_generic_hook

    store = _connected_store(tmp_path)
    _grant(store)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(
        commands_hook_generic, "schedule_guard_daemon_ensure", lambda *args, **kwargs: "http://127.0.0.1:8765"
    )
    command = "\tsynthetic-policy-review 'Synthetic  Value'\r\n"
    _run_generic_hook(
        capsys=capsys,
        store=store,
        workspace=workspace,
        harness="codex",
        config=GuardConfig(
            guard_home=store.guard_home, workspace=workspace, default_action="review", receipt_redaction_level="none"
        ),
        payload={"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}},
    )
    requests = store.list_approval_requests(status="pending", limit=10)
    assert len(requests) == 1
    source = verified_request_policy_memory_source(store, requests[0])
    assert source is not None and source["commandText"] == command


def test_stricter_signed_privacy_setting_prevents_disclosure(tmp_path):
    from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle
    from tests.test_guard_receipt_redaction_cursor import _signed_redaction_policy_bundle

    store = _connected_store(tmp_path)
    _grant(store)
    captured = _capture(store)
    assert captured is not None
    now = datetime.now(timezone.utc).isoformat()
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(workspace_id=_WORKSPACE_ID), now)
    store.set_sync_payload(
        "policy_bundle",
        sign_policy_bundle(_signed_redaction_policy_bundle(level="full"), workspace_id=_WORKSPACE_ID),
        now,
    )
    assert _capture(store) is None
    request = _queue(store, captured)
    assert verified_request_policy_memory_source(store, request) is None


def test_previously_uploaded_unbound_receipt_is_not_rewritten_as_exact_source(tmp_path):
    store = _connected_store(tmp_path)
    _grant(store)
    request = _queue(store, _capture(store))
    earlier = build_receipt(
        harness="codex",
        artifact_id=request["artifact_id"],
        artifact_hash=request["artifact_hash"],
        policy_decision="allow",
        capabilities_summary="synthetic",
        changed_capabilities=[],
        provenance_summary="synthetic",
        artifact_name="Synthetic",
        source_scope="project",
        approval_request_id=request["request_id"],
    )
    store.add_receipt(earlier)
    old_cursor = store.latest_receipt_rowid()
    receipt_id = _ensure_source_receipt_id(
        store, {**request, "sourceReceiptId": earlier.receipt_id}, decision_action="approved", scope="workspace"
    )
    assert receipt_id != earlier.receipt_id
    rows = store.list_receipts_since_rowid(after_rowid=old_cursor, limit=10)
    assert [row["receipt_id"] for row in rows] == [receipt_id]
    transported = _cloud_sync_receipt_payload(
        rows[0], device_id="synthetic", device_name="Synthetic", redaction_level="none", store=store
    )
    assert transported["envelopeRedacted"]["policyMemorySource"]["commandText"] == _COMMAND


@pytest.mark.parametrize(
    "command,accepted", [("a" * 8192, True), ("a" * 8193, False), ("😀" * 4096, True), ("😀" * 4096 + "a", False)]
)
def test_source_disclosure_respects_shared_utf16_and_utf8_bounds(tmp_path, command, accepted):
    store = _connected_store(tmp_path)
    _grant(store)
    assert (_capture(store, command=command) is not None) is accepted


def test_source_disclosure_requires_registered_local_installation_identity(tmp_path):
    store = _connected_command_store(tmp_path)
    _grant(store)
    assert store.get_or_create_installation_id() != store.get_oauth_local_credentials(allow_primary=False)["machine_id"]
    assert _capture(store) is None
