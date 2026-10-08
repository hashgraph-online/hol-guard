"""Bind authenticated exact delivery to the retained original native pause."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

from ..native_approval_v4_protocol import decode_native_approval_v4_proof
from ..review_contracts import GuardReviewContractError, build_local_review_request_claim
from .exact_cloud_review import ExactCloudReviewError, _oauth_metadata, _verified_capability
from .native_cloud_review_origin import frozen_native_approval_origin
from .native_cloud_review_v4 import NativeCloudReviewV4Error, get_native_approval_renewal

if TYPE_CHECKING:
    from ..store import GuardStore


def native_cloud_review_delivery_candidate(payload: object) -> bool:
    return isinstance(payload, Mapping) and bool(
        {"nativeApprovalContext", "nativeApprovalProof", "nativeApprovalRenewal", "nativeDeliveryBinding"} & payload.keys()
    )


def authorize_native_cloud_review_delivery(
    store: GuardStore,
    job: Mapping[str, object],
    identity: Mapping[str, object],
    *,
    now: str | None = None,
) -> dict[str, object]:
    payload = job.get("payload")
    required_fields = {"harness", "nativeApprovalContext", "nativeApprovalProof"}
    if not isinstance(payload, Mapping) or set(payload) not in (required_fields, required_fields | {"nativeApprovalRenewal"}):
        raise ExactCloudReviewError("remote_exact_native_payload_invalid")
    context = payload["nativeApprovalContext"]
    if (
        not isinstance(context, Mapping)
        or set(context) != {"decision", "decisionReceiptId"}
        or context["decision"] not in ("allow_once", "block")
        or not isinstance(context["decisionReceiptId"], str)
        or not 0 < len(context["decisionReceiptId"]) <= 128
        or context["decisionReceiptId"] != context["decisionReceiptId"].strip()
    ):
        raise ExactCloudReviewError("remote_exact_native_context_invalid")
    target = job.get("serverResolvedBinding")
    if not isinstance(target, Mapping) or not isinstance(target.get("localRequestId"), str):
        raise ExactCloudReviewError("remote_exact_native_binding_missing")
    local_id = target["localRequestId"]
    snapshot = store.get_raw_approval_request_snapshot(local_id)
    if not isinstance(snapshot, dict):
        raise ExactCloudReviewError("remote_exact_native_origin_missing")
    origin = frozen_native_approval_origin(snapshot)
    if origin is None:
        raise ExactCloudReviewError("remote_exact_native_origin_missing")
    challenge = origin["challenge"]
    oauth = _oauth_metadata(store)
    if identity["deviceId"] != oauth.device_id or identity["workspaceId"] != oauth.workspace_id:
        raise ExactCloudReviewError("remote_exact_native_target_mismatch")
    try:
        claim = build_local_review_request_claim(request_row=snapshot, oauth=oauth, store=store)
    except GuardReviewContractError as error:
        raise ExactCloudReviewError(error.code) from error
    if (
        payload["harness"] != snapshot.get("harness")
        or target.get("claimDigest") != claim["claimHash"]
        or target.get("approvalId") != claim["approvalId"]
        or target.get("actionDigest") != challenge["action_digest"]
        or target.get("localRequestId") != challenge["request_id"]
        or type(target.get("localRequestVersion")) is not int
        or target["localRequestVersion"] < 1
        or claim.get("nativeApprovalChallenge") != challenge
    ):
        raise ExactCloudReviewError("remote_exact_native_binding_mismatch")
    expected_challenge = challenge
    if "nativeApprovalRenewal" in payload:
        if context["decision"] != "allow_once":
            raise ExactCloudReviewError("remote_exact_native_block_proof_invalid")
        try:
            protected_renewal = get_native_approval_renewal(
                store.guard_home, request_id=cast(str, challenge["request_id"]),
                decision_receipt_id=cast(str, context["decisionReceiptId"]), source_claim_hash=cast(str, claim["claimHash"]),
                original_challenge=challenge,
            )
        except NativeCloudReviewV4Error as error:
            raise ExactCloudReviewError(error.code) from error
        if (protected_renewal != payload["nativeApprovalRenewal"]
            or protected_renewal["revocation_epoch"] != origin["revocation_epoch"]
            or cast(int, protected_renewal["consent_revision"]) < cast(int, origin["consent_revision"])):
            raise ExactCloudReviewError("remote_exact_native_renewal_mismatch")
        expected_challenge = cast(dict[str, object], protected_renewal["challenge"])
    proof = payload["nativeApprovalProof"]
    if context["decision"] == "allow_once":
        # A signed saved decision can prepare renewed authority without a proof.
        # The executable boundary still requires native fresh UP+UV installation.
        if proof is not None:
            decoded_proof = decode_native_approval_v4_proof(proof)
            if decoded_proof is None or decoded_proof["challenge"] != expected_challenge:
                raise ExactCloudReviewError("remote_exact_native_proof_mismatch")
    elif proof is not None:
        raise ExactCloudReviewError("remote_exact_native_block_proof_invalid")
    recovery_only = snapshot.get("status") != "pending"
    try:
        _verified_capability(store, now=now)
    except ExactCloudReviewError:
        # A historical positive observation is not renewed action authority.
        # The executor must query only, and reject absence without installation.
        recovery_only = True
    return {
        "localRequestId": local_id,
        "nativeRequestId": challenge["request_id"],
        "claimDigest": claim["claimHash"],
        "decisionReceiptId": context["decisionReceiptId"],
        "decision": context["decision"],
        "harness": snapshot["harness"],
        "nativeApprovalChallenge": challenge,
        "consentRevision": origin["consent_revision"],
        "revocationEpoch": origin["revocation_epoch"],
        "readOnlyRecovery": recovery_only,
    }
