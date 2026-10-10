"""Join actual bound-daemon consumption to its immutable local request/outbox.

This transports native-consumer evidence; it does not attest independently, issue
an approval, dispatch a provider business action, or resume a harness.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from ..review_contracts import build_local_review_request_claim, local_review_request_claim_hash_matches
from .exact_cloud_review import _oauth_metadata
from .native_cloud_review_v4 import (
    NativeCloudReviewV4Error,
    decode_native_application_observation,
    get_native_approval_renewal,
    native_application_result,
    native_renewal_matches_original,
)

_RECEIPT_CHALLENGE_FIELDS = (
    "request_id",
    "request_digest",
    "action_digest",
    "policy_generation",
    "policy_digest",
    "rule_digest",
    "runtime_identity",
    "runtime_protocol_version",
    "runtime_package",
    "runtime_version",
    "runtime_binary_identity",
    "harness",
    "workspace_binding",
    "device_binding",
    "installation_binding",
    "publisher_binding",
    "artifact_binding",
    "scope_contract_version",
    "scope_contract_digest",
    "scope_binding",
    "resident_epoch",
    "nonce",
    "issued_at_ms",
    "expires_at_ms",
    "requested_action",
)


def _matches_frozen_origin(
    request: dict[str, object],
    receipt: dict[str, object],
    renewal: Mapping[str, object] | None = None,
) -> bool:
    from .cloud_review_request_purpose import canonical_request_kind
    from .native_cloud_review_origin import frozen_native_approval_challenge

    if canonical_request_kind(request) != "reviewable_pause":
        return False
    challenge = frozen_native_approval_challenge(request)
    if renewal is not None:
        if not native_renewal_matches_original(renewal, challenge):
            return False
        challenge = cast(dict[str, object], renewal["challenge"])
    if challenge is None or any(receipt.get(key) != challenge.get(key) for key in _RECEIPT_CHALLENGE_FIELDS):
        return False
    webauthn = challenge.get("webauthn")
    if not isinstance(webauthn, dict):
        return False
    credential = webauthn.get("credential_id")
    nonce = challenge.get("nonce")
    if not isinstance(credential, str) or not isinstance(nonce, str):
        return False
    try:
        credential_bytes = base64.urlsafe_b64decode(credential + "=" * (-len(credential) % 4))
        nonce_bytes = bytes.fromhex(nonce)
    except ValueError:
        return False
    return (
        receipt["credential_id_digest"] == hashlib.sha256(credential_bytes).hexdigest()
        and receipt["nonce_digest"] == hashlib.sha256(nonce_bytes).hexdigest()
        and receipt["rp_id"] == webauthn.get("rp_id")
        and receipt["origin"] == webauthn.get("origin")
        and receipt["algorithm"] == webauthn.get("algorithm")
    )


def record_native_application_observation(store, observation: Mapping[str, object]) -> dict[str, object]:
    """Only call with actual hook core output or actual read-only native query output."""
    observed = decode_native_application_observation(dict(observation))
    if observed is not None and observed["phase"] == "recovery_required":
        raise NativeCloudReviewV4Error("native_cloud_review_v4_consumption_recovery_required")
    if observed is None or observed["phase"] != "consumed":
        raise NativeCloudReviewV4Error("native_cloud_review_v4_positive_invalid")
    request_id = cast(str, observed["request_id"])
    receipt = cast(dict[str, object], observed["receipt"])
    from .native_cloud_review_origin import frozen_native_approval_challenge

    raw_request = store.get_raw_approval_request_snapshot(request_id)
    raw_original = frozen_native_approval_challenge(raw_request) if isinstance(raw_request, dict) else None
    if not isinstance(raw_request, dict) or raw_original is None:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_original_pending_mismatch")
    oauth = _oauth_metadata(store)
    snapshots = store.list_review_event_snapshots(request_id)
    candidates = (
        [snapshot for snapshot in snapshots if isinstance(snapshot, dict)] if isinstance(snapshots, list) else []
    )
    # Acknowledgment may prune transport snapshots. Recovery still requires the
    # unchanged frozen native origin and the native journal's immutable source hash.
    candidates.append(raw_request)
    frozen: dict[str, object] | None = None
    renewal: dict[str, object] | None = None
    for candidate in candidates:
        original = frozen_native_approval_challenge(candidate)
        if original is None or original != raw_original:
            continue
        claim = build_local_review_request_claim(request_row=candidate, oauth=oauth, store=store)
        if not local_review_request_claim_hash_matches(claim, observed["source_claim_hash"], allow_legacy=False):
            continue
        if not _matches_frozen_origin(candidate, receipt):
            guard_home = getattr(store, "guard_home", None)
            if not isinstance(guard_home, Path):
                raise NativeCloudReviewV4Error("native_cloud_review_v4_unavailable")
            if renewal is None:
                renewal = get_native_approval_renewal(
                    guard_home,
                    request_id=request_id,
                    decision_receipt_id=cast(str, observed["decision_receipt_id"]),
                    source_claim_hash=cast(str, observed["source_claim_hash"]),
                    original_challenge=original,
                )
            if not _matches_frozen_origin(candidate, receipt, renewal):
                continue
        frozen = candidate
        break
    if frozen is None:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_immutable_source_mismatch")
    application = native_application_result(observed)
    sequence = store.append_native_application_observation(
        request_id, native_application_result=application, request_snapshot=frozen
    )
    return {"localRequestId": request_id, "outboxStreamSequence": sequence, "nativeApplicationResult": application}
