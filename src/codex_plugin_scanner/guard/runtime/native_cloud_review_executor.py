"""Exact V4 delivery: install only; actual native hooks consume later.

No saved SDK decision, provider acknowledgment or Root-v1 context verification is
native V4 consumption. This executor never resumes a harness or dispatches the
private Google business worker.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

from ..native_approval_v4_protocol import decode_native_approval_v4_proof
from .native_cloud_review_application import record_native_application_observation
from .native_cloud_review_v4 import (
    NativeCloudReviewV4Error, decode_native_application_observation, decode_native_authority_renewal,
    get_native_approval_renewal, native_renewal_matches_original, renew_native_approval_authority,
    request_native_cloud_review,
)

_BINDING_FIELDS = {"localRequestId", "nativeRequestId", "claimDigest", "decisionReceiptId", "decision", "harness",
                   "nativeApprovalChallenge", "consentRevision", "revocationEpoch", "readOnlyRecovery"}

def is_native_cloud_review_payload(payload: Mapping[str, object]) -> bool:
    return bool({"nativeApprovalContext", "nativeApprovalProof", "nativeApprovalRenewal", "nativeDeliveryBinding"} & set(payload))

def _binding(payload: Mapping[str, object]) -> dict[str, object]:
    binding = payload.get("nativeDeliveryBinding")
    context = payload.get("nativeApprovalContext")
    if not isinstance(binding, dict) or set(binding) != _BINDING_FIELDS or not isinstance(context, dict):
        raise NativeCloudReviewV4Error("native_cloud_review_v4_authenticated_binding_missing")
    if (set(context) != {"decision", "decisionReceiptId"}
        or context.get("decision") != binding.get("decision")
        or context.get("decisionReceiptId") != binding.get("decisionReceiptId")
        or binding.get("decision") not in {"allow_once", "block"}
        or type(binding.get("readOnlyRecovery")) is not bool
        or any(not isinstance(binding.get(key), str) or not binding[key]
               for key in ("localRequestId", "nativeRequestId", "claimDigest", "decisionReceiptId", "harness"))):
        raise NativeCloudReviewV4Error("native_cloud_review_v4_authenticated_binding_invalid")
    challenge = binding.get("nativeApprovalChallenge")
    if (not isinstance(challenge, dict) or challenge.get("request_id") != binding["nativeRequestId"]
        or binding["localRequestId"] != binding["nativeRequestId"] or challenge.get("harness") != binding["harness"]
        or type(binding.get("consentRevision")) is not int or cast(int, binding["consentRevision"]) < 1
        or type(binding.get("revocationEpoch")) is not int or cast(int, binding["revocationEpoch"]) < 0):
        raise NativeCloudReviewV4Error("native_cloud_review_v4_original_pending_mismatch")
    renewal = payload.get("nativeApprovalRenewal")
    expected_challenge = challenge
    if renewal is not None:
        decoded_renewal = decode_native_authority_renewal(renewal)
        if (binding["decision"] != "allow_once" or decoded_renewal is None
            or decoded_renewal["request_id"] != binding["nativeRequestId"]
            or decoded_renewal["decision_receipt_id"] != binding["decisionReceiptId"]
            or decoded_renewal["source_claim_hash"] != binding["claimDigest"]
            or decoded_renewal["revocation_epoch"] != binding["revocationEpoch"]
            or cast(int, decoded_renewal["consent_revision"]) < cast(int, binding["consentRevision"])
            or not native_renewal_matches_original(decoded_renewal, challenge)):
            raise NativeCloudReviewV4Error("native_cloud_review_v4_renewal_action_mismatch")
        expected_challenge = cast(dict[str, object], decoded_renewal["challenge"])
    proof = payload.get("nativeApprovalProof")
    if proof is not None:
        decoded_proof = decode_native_approval_v4_proof(proof)
        if decoded_proof is None or decoded_proof["challenge"] != expected_challenge:
            raise NativeCloudReviewV4Error("native_cloud_review_v4_original_challenge_mismatch")
    return cast(dict[str, object], binding)

def _request(binding: Mapping[str, object], schema: str) -> dict[str, object]:
    return {"schema":schema, "version":4, "request_id":binding["nativeRequestId"],
            "decision_receipt_id":binding["decisionReceiptId"], "source_claim_hash":binding["claimDigest"]}

def _observed(response: object, binding: Mapping[str, object]) -> dict[str, object]:
    result = decode_native_application_observation(response)
    if (result is None or result["request_id"] != binding["nativeRequestId"]
        or result["decision_receipt_id"] != binding["decisionReceiptId"]
        or result["source_claim_hash"] != binding["claimDigest"]):
        raise NativeCloudReviewV4Error("native_cloud_review_v4_observation_binding_invalid")
    return result

def prepare_native_cloud_review_renewal(
    payload: Mapping[str, object], *, guard_home: Path,
) -> dict[str, object]:
    """Prepare fresh UP+UV for an authenticated saved decision without approving again.

    Pass the authorized original nativeDeliveryBinding/context, with no fresh proof.
    After a real authenticator signs the returned challenge, submit its exact result
    as nativeApprovalRenewal alongside nativeApprovalProof to the normal executor.
    This function never installs or consumes authority.
    """
    binding = _binding(payload)
    if binding["readOnlyRecovery"] is True:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_read_only_recovery")
    if binding["decision"] != "allow_once":
        raise NativeCloudReviewV4Error("native_cloud_review_v4_immutable_binding_conflict")
    return renew_native_approval_authority(
        guard_home, request_id=cast(str, binding["nativeRequestId"]),
        decision_receipt_id=cast(str, binding["decisionReceiptId"]), source_claim_hash=cast(str, binding["claimDigest"]),
        original_challenge=cast(dict[str, object], binding["nativeApprovalChallenge"]),
    )


def execute_native_cloud_review_delivery(store, payload: Mapping[str, object], *, generated_at: str) -> dict[str, object]:
    binding = _binding(payload)
    guard_home = getattr(store, "guard_home", None)
    if not isinstance(guard_home, Path):
        raise NativeCloudReviewV4Error("native_cloud_review_v4_unavailable")
    observed: dict[str, object] | None = None
    try:
        observed = _observed(request_native_cloud_review(guard_home, "approval_consumption_query_v4",
            _request(binding, "guard-native-cloud-review-consumption-query.v4")), binding)
    except NativeCloudReviewV4Error as error:
        if error.code != "native_cloud_review_v4_not_installed":
            raise
    if observed is not None and observed["phase"] == "consumed":
        if binding["decision"] != "allow_once":
            raise NativeCloudReviewV4Error("native_cloud_review_v4_immutable_binding_conflict")
        return _positive(store, binding, observed)
    if observed is not None and observed["phase"] == "blocked":
        if binding["decision"] != "block":
            raise NativeCloudReviewV4Error("native_cloud_review_v4_immutable_binding_conflict")
        return _negative(store, binding, generated_at)
    if observed is not None and observed["phase"] == "recovery_required":
        raise NativeCloudReviewV4Error("native_cloud_review_v4_consumption_recovery_required")
    if binding["readOnlyRecovery"]:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_consumption_not_found")
    if binding["decision"] == "block":
        if payload.get("nativeApprovalProof") is not None or payload.get("nativeApprovalRenewal") is not None:
            raise NativeCloudReviewV4Error("native_cloud_review_v4_block_proof_invalid")
        observed = _observed(request_native_cloud_review(guard_home, "approval_block_v4",
            _request(binding, "guard-native-cloud-review-block-request.v4")), binding)
        if observed["phase"] != "blocked":
            raise NativeCloudReviewV4Error("native_cloud_review_v4_block_not_applied")
        return _negative(store, binding, generated_at)
    renewal_payload = payload.get("nativeApprovalRenewal")
    if renewal_payload is not None:
        protected = get_native_approval_renewal(
            guard_home, request_id=cast(str, binding["nativeRequestId"]),
            decision_receipt_id=cast(str, binding["decisionReceiptId"]), source_claim_hash=cast(str, binding["claimDigest"]),
            original_challenge=cast(dict[str, object], binding["nativeApprovalChallenge"]),
        )
        if protected != renewal_payload:
            raise NativeCloudReviewV4Error("native_cloud_review_v4_renewal_action_mismatch")
    proof = payload.get("nativeApprovalProof")
    if proof is None:
        renewal = prepare_native_cloud_review_renewal(payload, guard_home=guard_home)
        return {"status":"completed", "action":"allow", "remoteDecision":"allow", "applicationStatus":"failed_retryable",
            "applicationReason":"native_approval_waiting_for_authorization", "applicationUpdatedAt":generated_at,
            "localRequestId":binding["localRequestId"], "receiptId":binding["decisionReceiptId"],
            "nativeApprovalRenewal":renewal,
            "continuationStatus":"not_applicable", "continuationReason":"native_consumption_is_not_harness_resume",
            "continuationUpdatedAt":generated_at}
    if not isinstance(proof, dict):
        raise NativeCloudReviewV4Error("native_cloud_review_v4_proof_missing")
    install = _request(binding, "guard-native-cloud-review-install-request.v4")
    install["proof"] = proof
    observed = _observed(request_native_cloud_review(guard_home, "approval_install_v4", install), binding)
    if observed["phase"] == "consumed":
        return _positive(store, binding, observed)
    if observed["phase"] != "waiting_for_hook":
        raise NativeCloudReviewV4Error("native_cloud_review_v4_immutable_binding_conflict")
    return {"status":"completed", "action":"allow", "remoteDecision":"allow", "applicationStatus":"failed_retryable",
        "applicationReason":"native_approval_waiting_for_hook", "applicationUpdatedAt":generated_at,
        "localRequestId":binding["localRequestId"], "receiptId":binding["decisionReceiptId"],
        "continuationStatus":"not_applicable", "continuationReason":"native_consumption_is_not_harness_resume",
        "continuationUpdatedAt":generated_at}

def _positive(store, binding: Mapping[str, object], observed: Mapping[str, object]) -> dict[str, object]:
    projection = record_native_application_observation(store, observed)
    application = cast(dict[str, object], projection["nativeApplicationResult"])
    return {"status":"completed", "action":"allow", "remoteDecision":"allow", "applicationStatus":"failed_retryable",
        "applicationReason":"native_approval_consumed_observation_available", "applicationUpdatedAt":application["consumedAt"],
        "localRequestId":binding["localRequestId"], "receiptId":binding["decisionReceiptId"],
        "nativeApplicationResult":application, "nativeApplicationEventSequence":projection["outboxStreamSequence"],
        "continuationStatus":"not_applicable", "continuationReason":"native_consumption_is_not_harness_resume",
        "continuationUpdatedAt":application["consumedAt"]}


def _negative(store, binding: Mapping[str, object], generated_at: str) -> dict[str, object]:
    request = store.get_approval_request(binding["localRequestId"])
    if isinstance(request, dict) and request.get("status") == "pending":
        store.resolve_approval_request(binding["localRequestId"], resolution_action="block", resolution_scope="once",
            reason="native_cloud_review_v4_blocked:" + cast(str, binding["decisionReceiptId"]), resolved_at=generated_at)
    return {"status":"completed", "action":"block", "remoteDecision":"block", "applicationStatus":"applied",
        "applicationReason":None, "applicationUpdatedAt":generated_at,
        "localRequestId":binding["localRequestId"], "receiptId":binding["decisionReceiptId"],
        "continuationStatus":"not_applicable", "continuationReason":"native_review_is_not_harness_resume",
        "continuationUpdatedAt":generated_at}
