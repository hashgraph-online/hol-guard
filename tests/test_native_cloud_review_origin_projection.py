"""Original native pauses keep one immutable Cloud claim and challenge."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_review_approval as producer
from codex_plugin_scanner.guard.daemon import hook_native_review_origin as native_origin
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from codex_plugin_scanner.guard.review_contracts import (
    GuardReviewOAuthMetadata,
    build_local_review_request_claim,
    compute_local_review_request_claim_hash,
)
from codex_plugin_scanner.guard.runtime import cloud_review_event_projection as projection
from codex_plugin_scanner.guard.runtime import native_cloud_review_v4
from codex_plugin_scanner.guard.runtime.cloud_review_request_purpose import canonical_request_kind
from codex_plugin_scanner.guard.runtime.native_cloud_review_origin import (
    NATIVE_CLOUD_REVIEW_ORIGIN_FIELD,
    NATIVE_CLOUD_REVIEW_ORIGIN_QUEUE_PREFIX,
    NATIVE_CLOUD_REVIEW_ORIGIN_UNAVAILABLE_FIELD,
    frozen_native_approval_challenge,
)
from codex_plugin_scanner.guard.runtime.native_cloud_review_v4 import NativeCloudReviewV4Error
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_approval_v4_transport import _challenge

_PAYLOAD: dict[str, object] = {"tool_name": "Bash", "tool_input": {"command": "printf 'original action'"}}
_NOW = "2026-10-07T12:00:00+00:00"


def _source() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    challenge = _challenge()
    receipt: dict[str, object] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "",
        "request_id": challenge["request_id"],
        "request_digest": challenge["request_digest"],
        "harness": challenge["harness"],
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": challenge["policy_generation"],
        "policy_digest": challenge["policy_digest"],
        "rule_digest": challenge["rule_digest"],
        "runtime_identity": challenge["runtime_identity"],
        "decision": "deny",
        "model_output_action": "not_applicable",
        "policy_action": "review",
        "observed_policy_action": None,
        "reason_code": "native_command_review",
        "workspace_bound": True,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": None,
        "origin_authentication": "e" * 64,
        "execution_intent_digest": "f" * 64,
    }
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    result: dict[str, object] = {
        "schema": "guard-pre-tool-result.v1",
        "version": 1,
        "authority": "rust",
        "decision": "deny",
        "policy_action": "review",
        "minimum_action": "review",
        "observed_policy_action": None,
        "reason_code": "native_command_review",
        "reason": "Review this original action.",
        "action": {"action_type": "command", "event": "PreToolUse"},
    }
    origin: dict[str, object] = {
        "schema": "guard-native-cloud-review-origin-result.v4",
        "version": 4,
        "request_id": challenge["request_id"],
        "challenge": challenge,
        "consent_revision": 3,
        "revocation_epoch": 1,
    }
    return origin, receipt, result


def _oauth() -> GuardReviewOAuthMetadata:
    return GuardReviewOAuthMetadata(
        device_id="device-1",
        dpop_thumbprint=None,
        grant_id="grant-1",
        installation_id="installation-1",
        machine_id="machine-1",
        runtime_id="runtime-1",
        workspace_id="workspace-1",
    )


def _queue(
    store: GuardStore,
    tmp_path: Path,
    receipt: dict[str, object],
    result: dict[str, object],
) -> dict[str, object]:
    row = producer.queue_native_pre_tool_review(
        store,
        harness="claude-code",
        payload=copy.deepcopy(_PAYLOAD),
        native_result=result,
        native_receipt=receipt,
        workspace=tmp_path,
        guard_home=store.guard_home,
        home_dir=tmp_path / "home",
    )
    assert row is not None
    return row


def _event(store: GuardStore, row: dict[str, object]) -> dict[str, object]:
    event = projection.build_cloud_review_event(
        row,
        oauth=_oauth(),
        redaction_level="none",
        store=store,
        event_sequence=1,
    )
    assert event is not None
    return event


def _request(origin: dict[str, object], receipt: dict[str, object]) -> GuardApprovalRequest:
    request_id = str(origin["request_id"])
    envelope: dict[str, object] = {
        "action_id": "sdk-action",
        "action_type": "shell_command",
        "pre_execution_result": "review",
        "command": "printf 'original action'",
        "native_origin_receipt": copy.deepcopy(receipt),
        NATIVE_CLOUD_REVIEW_ORIGIN_FIELD: copy.deepcopy(origin),
        "nativeApprovalChallenge": copy.deepcopy(origin["challenge"]),
    }
    return GuardApprovalRequest(
        request_id=request_id,
        harness="claude-code",
        artifact_id="native:tool:bash",
        artifact_name="Bash",
        artifact_hash="artifact-hash",
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=("native_pre_tool",),
        source_scope="harness",
        config_path="/guard",
        launch_target="printf 'original action'",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
        queue_group_id=NATIVE_CLOUD_REVIEW_ORIGIN_QUEUE_PREFIX + request_id,
        action_envelope_json=envelope,
        risk_summary="Original business claim.",
    )


@pytest.mark.parametrize("command_digest", [None, "a" * 64])
def test_original_native_pause_projects_authenticated_frozen_challenge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command_digest: str | None,
) -> None:
    store = GuardStore(tmp_path / "guard")
    origin, receipt, result = _source()
    if command_digest is not None:
        origin["command_sha256"] = command_digest
    original_challenge = copy.deepcopy(origin["challenge"])
    monkeypatch.setattr(native_cloud_review_v4, "request_native_cloud_review", lambda *_args: origin)
    row = _queue(store, tmp_path, receipt, result)
    event = _event(store, row)
    claim = cast(dict[str, object], event["reviewClaim"])
    payload = cast(dict[str, object], event["requestPayload"])
    assert row["request_id"] == receipt["request_id"] == event["localRequestId"]
    assert event["requestKind"] == "reviewable_pause"
    assert claim["nativeApprovalChallenge"] == payload["nativeApprovalChallenge"] == original_challenge
    assert "nativeWorkspaceReview" not in payload
    assert claim["claimHash"] == compute_local_review_request_claim_hash(claim)
    without_challenge = dict(claim)
    without_challenge.pop("nativeApprovalChallenge")
    assert claim["claimHash"] != compute_local_review_request_claim_hash(without_challenge)
    assert claim["actionEnvelopeHash"] != cast(dict[str, object], original_challenge)["action_digest"]
    assert receipt["execution_intent_digest"] != cast(dict[str, object], original_challenge)["action_digest"]


@pytest.mark.parametrize("command_digest", [None, "", "A" * 64, "a" * 63, 7])
def test_malformed_native_source_commitment_cannot_make_cloud_origin_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command_digest: object,
) -> None:
    store = GuardStore(tmp_path / "guard")
    origin, receipt, result = _source()
    origin["command_sha256"] = command_digest
    monkeypatch.setattr(native_cloud_review_v4, "request_native_cloud_review", lambda *_args: origin)
    row = _queue(store, tmp_path, receipt, result)
    event = _event(store, row)
    assert "nativeApprovalChallenge" not in cast(dict[str, object], event["reviewClaim"])
    marker = cast(
        dict[str, object],
        cast(dict[str, object], event["requestPayload"])[NATIVE_CLOUD_REVIEW_ORIGIN_UNAVAILABLE_FIELD],
    )
    assert marker["executable"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", "other-request"),
        ("request_digest", "0" * 64),
        ("harness", "codex"),
        ("policy_generation", 8),
        ("policy_digest", "0" * 64),
        ("rule_digest", "0" * 64),
        ("runtime_identity", "0" * 64),
        ("approval_eligible", False),
        ("minimum_action", "block"),
        ("workspace_binding", None),
    ],
)
def test_wrong_native_query_bindings_leave_cloud_visible_without_v4_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    store = GuardStore(tmp_path / "guard")
    origin, receipt, result = _source()
    cast(dict[str, object], origin["challenge"])[field] = value
    monkeypatch.setattr(native_origin, "get_native_approval_origin", lambda *_args: origin)
    monkeypatch.setattr(
        projection,
        "build_native_workspace_review_context",
        lambda *_args: {"schema": "guard-native-workspace-review-context.v1"},
    )
    row = _queue(store, tmp_path, receipt, result)
    event = _event(store, row)
    assert row["request_id"] != receipt["request_id"]
    assert row["status"] == "pending"
    assert "nativeApprovalChallenge" not in cast(dict[str, object], event["reviewClaim"])
    assert "nativeApprovalChallenge" not in cast(dict[str, object], event["requestPayload"])
    assert "nativeWorkspaceReview" not in cast(dict[str, object], event["requestPayload"])
    marker = cast(
        dict[str, object],
        cast(dict[str, object], event["requestPayload"])[NATIVE_CLOUD_REVIEW_ORIGIN_UNAVAILABLE_FIELD],
    )
    assert marker["executable"] is False


@pytest.mark.parametrize(
    "code",
    [
        "native_cloud_review_v4_origin_missing",
        "native_cloud_review_consent_revoked",
        "native_cloud_review_v4_unavailable",
        "native_cloud_review_v4_transport_uncertain",
    ],
)
def test_missing_private_origin_keeps_visibility_without_executable_legacy_downgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: str,
) -> None:
    store = GuardStore(tmp_path / "guard")
    _origin, receipt, result = _source()

    def unavailable(*_args: object) -> dict[str, object]:
        raise NativeCloudReviewV4Error(code)

    monkeypatch.setattr(native_origin, "get_native_approval_origin", unavailable)
    monkeypatch.setattr(
        projection,
        "build_native_workspace_review_context",
        lambda *_args: {"schema": "guard-native-workspace-review-context.v1"},
    )
    row = _queue(store, tmp_path, receipt, result)
    event = _event(store, row)
    assert row["status"] == "pending"
    assert canonical_request_kind(row) == "reviewable_pause"
    assert event["displayCommand"] == "printf 'original action'"
    assert "nativeApprovalChallenge" not in cast(dict[str, object], event["reviewClaim"])
    assert "nativeWorkspaceReview" not in cast(dict[str, object], event["requestPayload"])
    marker = cast(
        dict[str, object],
        cast(dict[str, object], event["requestPayload"])[NATIVE_CLOUD_REVIEW_ORIGIN_UNAVAILABLE_FIELD],
    )
    assert marker == {
        "schema": "guard-native-cloud-review-origin-unavailable.v4",
        "version": 4,
        "request_id": receipt["request_id"],
        "reason_code": code,
        "executable": False,
    }
    assert "exactReviewCapability" not in cast(dict[str, object], event["reviewClaim"])


@pytest.mark.parametrize("ineligible", ["unauthenticated", "watch", "retrospective", "wrong_result"])
def test_non_original_native_receipts_never_gain_a_private_origin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ineligible: str,
) -> None:
    store = GuardStore(tmp_path / "guard")
    origin, receipt, result = _source()
    if ineligible == "unauthenticated":
        receipt.pop("origin_authentication")
    elif ineligible == "watch":
        receipt["observe_mode"] = True
        receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    elif ineligible == "retrospective":
        result["agent_visible_immutable_block"] = True
    else:
        result["reason_code"] = "different_native_reason"
    monkeypatch.setattr(native_origin, "get_native_approval_origin", lambda *_args: origin)
    row = _queue(store, tmp_path, receipt, result)
    assert frozen_native_approval_challenge(row) is None
    assert row["request_id"] != receipt["request_id"]
    event = _event(store, row)
    assert "nativeWorkspaceReview" not in cast(dict[str, object], event["requestPayload"])
    assert "nativeApprovalChallenge" not in cast(dict[str, object], event["reviewClaim"])


def test_repeated_pending_origin_preserves_business_claim_and_rejects_challenge_renewal(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    origin, receipt, _result = _source()
    request = _request(origin, receipt)
    store.add_approval_request(request, _NOW)
    before = store.get_approval_request(request.request_id)
    assert before is not None
    original_claim = build_local_review_request_claim(request_row=before, oauth=_oauth(), store=store)
    store.add_approval_request(replace(request, risk_summary="Different business claim."), "2026-10-07T12:01:00+00:00")
    after = store.get_approval_request(request.request_id)
    assert after == before
    assert (
        build_local_review_request_claim(request_row=cast(dict[str, object], after), oauth=_oauth(), store=store)
        == original_claim
    )
    renewed = copy.deepcopy(request.action_envelope_json)
    assert renewed is not None
    cast(dict[str, object], renewed["nativeApprovalChallenge"])["nonce"] = "0" * 64
    cast(dict[str, object], cast(dict[str, object], renewed[NATIVE_CLOUD_REVIEW_ORIGIN_FIELD])["challenge"])[
        "nonce"
    ] = "0" * 64
    with pytest.raises(ValueError, match="native_cloud_review_original_snapshot_conflict"):
        store.add_approval_request(replace(request, action_envelope_json=renewed), "2026-10-07T12:02:00+00:00")
    assert store.get_approval_request(request.request_id) == before


def test_reconstructed_existing_row_cannot_be_upgraded_into_a_native_origin(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    origin, receipt, _result = _source()
    request = _request(origin, receipt)
    legacy_envelope = cast(dict[str, object], copy.deepcopy(request.action_envelope_json))
    legacy_envelope.pop("nativeApprovalChallenge")
    legacy_envelope.pop(NATIVE_CLOUD_REVIEW_ORIGIN_FIELD)
    store.add_approval_request(replace(request, action_envelope_json=legacy_envelope), _NOW)
    before = store.get_approval_request(request.request_id)
    with pytest.raises(ValueError, match="native_cloud_review_original_snapshot_conflict"):
        store.add_approval_request(request, "2026-10-07T12:01:00+00:00")
    assert store.get_approval_request(request.request_id) == before
    assert frozen_native_approval_challenge(cast(dict[str, object], before)) is None


@pytest.mark.parametrize(
    "invalid", ["watch", "immutable_block", "local_id", "digest", "legacy_group", "origin_metadata"]
)
def test_invalid_frozen_origin_cannot_fall_back_to_an_executable_root_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid: str,
) -> None:
    store = GuardStore(tmp_path / "guard")
    origin, receipt, result = _source()
    monkeypatch.setattr(native_origin, "get_native_approval_origin", lambda *_args: origin)
    row = _queue(store, tmp_path, receipt, result)
    if invalid == "watch":
        row["watch_only_observation"] = 1
    elif invalid == "immutable_block":
        row["policy_action"] = "block"
    elif invalid == "local_id":
        row["request_id"] = "sdk-reconstructed-request"
    elif invalid == "legacy_group":
        row["queue_group_id"] = "legacy-sdk-group"
    else:
        envelope = copy.deepcopy(cast(dict[str, object], row["action_envelope_json"]))
        if invalid == "origin_metadata":
            cast(dict[str, object], envelope[NATIVE_CLOUD_REVIEW_ORIGIN_FIELD])["consent_revision"] = 0
        else:
            cast(dict[str, object], envelope["nativeApprovalChallenge"])["action_digest"] = "0" * 64
        row["action_envelope_json"] = envelope
    monkeypatch.setattr(
        projection,
        "build_native_workspace_review_context",
        lambda *_args: {"schema": "guard-native-workspace-review-context.v1"},
    )
    if invalid == "immutable_block":
        with pytest.raises(ValueError, match="authoritative_decision_inconsistent"):
            _event(store, row)
        return
    event = _event(store, row)
    assert "nativeApprovalChallenge" not in cast(dict[str, object], event["reviewClaim"])
    assert "nativeApprovalChallenge" not in cast(dict[str, object], event["requestPayload"])
    assert "nativeWorkspaceReview" not in cast(dict[str, object], event["requestPayload"])


def test_actual_older_native_core_retains_native_proven_legacy_root_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    _origin, receipt, result = _source()

    def older_native(*_args: object) -> dict[str, object]:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_capability_unavailable")

    legacy_context = {"schema": "guard-native-workspace-review-context.v1", "request_id": "legacy-original"}
    monkeypatch.setattr(native_origin, "get_native_approval_origin", older_native)
    monkeypatch.setattr(projection, "build_native_workspace_review_context", lambda *_args: legacy_context)
    row = _queue(store, tmp_path, receipt, result)
    event = _event(store, row)
    assert cast(dict[str, object], event["requestPayload"])["nativeWorkspaceReview"] == legacy_context
    assert NATIVE_CLOUD_REVIEW_ORIGIN_UNAVAILABLE_FIELD not in cast(dict[str, object], event["requestPayload"])
    assert "nativeApprovalChallenge" not in cast(dict[str, object], event["reviewClaim"])


def test_standalone_challenge_response_is_not_an_original_native_origin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    origin, receipt, result = _source()
    monkeypatch.setattr(native_origin, "get_native_approval_origin", lambda *_args: origin["challenge"])
    row = _queue(store, tmp_path, receipt, result)
    event = _event(store, row)
    assert frozen_native_approval_challenge(row) is None
    assert "nativeApprovalChallenge" not in cast(dict[str, object], event["reviewClaim"])
    marker = cast(
        dict[str, object],
        cast(dict[str, object], event["requestPayload"])[NATIVE_CLOUD_REVIEW_ORIGIN_UNAVAILABLE_FIELD],
    )
    assert marker["reason_code"] == "native_cloud_review_v4_origin_invalid"
    assert marker["executable"] is False


def test_original_native_reapproval_floor_is_not_downgraded_to_sdk_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    origin, receipt, result = _source()
    challenge = cast(dict[str, object], origin["challenge"])
    challenge["minimum_action"] = challenge["requested_action"] = "require-reapproval"
    receipt["policy_action"] = "require-reapproval"
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    result["policy_action"] = result["minimum_action"] = "require-reapproval"
    monkeypatch.setattr(native_origin, "get_native_approval_origin", lambda *_args: origin)
    row = _queue(store, tmp_path, receipt, result)
    event = _event(store, row)
    assert row["policy_action"] == event["policyAction"] == "require-reapproval"
    assert cast(dict[str, object], row["action_envelope_json"])["pre_execution_result"] == "require-reapproval"
    claim = cast(dict[str, object], event["reviewClaim"])
    assert claim["policyAction"] == "require-reapproval"
    assert cast(dict[str, object], claim["nativeApprovalChallenge"])["requested_action"] == "require-reapproval"
