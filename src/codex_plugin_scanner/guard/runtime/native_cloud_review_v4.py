"""Bound-daemon V4 observations, never independent cryptographic attestation.

Only the native core retains original action input, verifies assertions, and
consumes them. This module transports its output without assigning authority.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from ..native_approval_v4_protocol import decode_native_approval_v4_challenge, decode_native_approval_v4_receipt
from ..native_resident_client import native_resident_client_request
from ..native_runtime import _isolated_environment, native_runtime_status
from .native_cloud_review_origin import decode_native_approval_origin_result

NATIVE_CLOUD_REVIEW_V4_FEATURE = "native-cloud-review-v4-hook-consumer"
NATIVE_CLOUD_REVIEW_CONSENT_FEATURE = "native-cloud-review-consent-v1"
NATIVE_CLOUD_REVIEW_RENEWAL_FEATURE = "native-cloud-review-v4-authority-renewal"
_MAX_BYTES = 64 * 1024
_SAFE_INTEGER = (1 << 53) - 1


class NativeCloudReviewV4Error(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def request_native_cloud_review(
    guard_home: Path,
    operation: str,
    request: Mapping[str, object],
) -> dict[str, object]:
    if operation not in {
        "approval_origin_v4",
        "approval_renew_v4",
        "approval_renewal_query_v4",
        "approval_install_v4",
        "approval_block_v4",
        "approval_consumption_query_v4",
        "approval_consumption_discover_v4",
        "cloud_review_consent_v1",
    }:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_request_invalid")
    status = native_runtime_status()
    identity = status.identity
    capabilities = status.capabilities
    features = capabilities.features if capabilities is not None else ()
    if not status.available or not status.compatible or identity is None or capabilities is None:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_unavailable")
    if "resident-protocol-v2" not in features or NATIVE_CLOUD_REVIEW_V4_FEATURE not in features:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_capability_unavailable")
    if operation == "cloud_review_consent_v1" and NATIVE_CLOUD_REVIEW_CONSENT_FEATURE not in features:
        raise NativeCloudReviewV4Error("native_cloud_review_consent_unavailable")
    if (
        operation in {"approval_renew_v4", "approval_renewal_query_v4"}
        and NATIVE_CLOUD_REVIEW_RENEWAL_FEATURE not in features
    ):
        raise NativeCloudReviewV4Error("native_cloud_review_v4_capability_unavailable")
    payload = json.dumps(
        {"operation": operation, "request": dict(request)}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if len(payload) > _MAX_BYTES:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_request_bounds_exceeded")
    encoded = native_resident_client_request(
        executable=identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=payload,
        timeout_seconds=2.0,
    )
    if encoded is None:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_transport_uncertain")
    try:
        response: object = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_response_invalid") from error
    if not isinstance(response, dict):
        raise NativeCloudReviewV4Error("native_cloud_review_v4_response_invalid")
    data = cast(dict[str, object], response)
    if isinstance(data.get("error"), str):
        raise NativeCloudReviewV4Error(cast(str, data["error"]))
    return data


def discover_native_applications(
    guard_home: Path,
    *,
    after_request_id: str | None = None,
    limit: int = 8,
) -> tuple[list[dict[str, object]], str | None]:
    """Discover protected-journal positives; caller must independently query each."""
    if (
        type(limit) is not int
        or not 1 <= limit <= 8
        or (
            after_request_id is not None
            and (not isinstance(after_request_id, str) or not after_request_id or len(after_request_id) > 256)
        )
    ):
        raise NativeCloudReviewV4Error("native_cloud_review_v4_discovery_request_invalid")
    response = request_native_cloud_review(
        guard_home,
        "approval_consumption_discover_v4",
        {
            "schema": "guard-native-cloud-review-discovery-request.v4",
            "version": 4,
            "limit": limit,
            "after_request_id": after_request_id,
        },
    )
    observations = response.get("observations")
    cursor = response.get("next_after_request_id")
    if (
        set(response) != {"schema", "version", "observations", "next_after_request_id"}
        or response.get("schema") != "guard-native-cloud-review-discovery-result.v4"
        or type(response.get("version")) is not int
        or response.get("version") != 4
        or not isinstance(observations, list)
        or len(observations) > limit
        or (cursor is not None and (not isinstance(cursor, str) or not cursor or len(cursor) > 256))
    ):
        raise NativeCloudReviewV4Error("native_cloud_review_v4_discovery_response_invalid")
    decoded: list[dict[str, object]] = []
    previous = after_request_id or ""
    for value in observations:
        observation = decode_native_application_observation(value)
        if observation is None or observation["phase"] != "consumed":
            raise NativeCloudReviewV4Error("native_cloud_review_v4_discovery_response_invalid")
        request_id = cast(str, observation["request_id"])
        if request_id <= previous:
            raise NativeCloudReviewV4Error("native_cloud_review_v4_discovery_response_invalid")
        previous = request_id
        decoded.append(observation)
    if cursor is not None and (len(decoded) != limit or cursor != previous):
        raise NativeCloudReviewV4Error("native_cloud_review_v4_discovery_response_invalid")
    return decoded, cast(str | None, cursor)


def _integer(value: object, *, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= cast(int, value) <= _SAFE_INTEGER


def get_native_approval_origin(guard_home: Path, request_id: str) -> dict[str, object]:
    response = request_native_cloud_review(
        guard_home,
        "approval_origin_v4",
        {
            "schema": "guard-native-cloud-review-origin-request.v4",
            "version": 4,
            "request_id": request_id,
        },
    )
    origin = decode_native_approval_origin_result(response)
    if origin is None or origin["request_id"] != request_id:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_origin_invalid")
    return origin


def decode_native_authority_renewal(payload: object) -> dict[str, object] | None:
    """Bound a protected-journal correlation, not a WebAuthn verification."""
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "version",
        "request_id",
        "decision_receipt_id",
        "source_claim_hash",
        "original_nonce_digest",
        "challenge",
        "consent_revision",
        "revocation_epoch",
    }:
        return None
    if (
        payload.get("schema") != "guard-native-cloud-review-renewal-result.v4"
        or payload.get("version") != 4
        or any(
            not isinstance(payload.get(key), str) or not payload[key] or len(payload[key]) > 256
            for key in ("request_id", "decision_receipt_id", "source_claim_hash")
        )
        or not _integer(payload.get("consent_revision"), minimum=1)
        or not _integer(payload.get("revocation_epoch"))
    ):
        return None
    for key in ("original_nonce_digest", "source_claim_hash"):
        digest = payload.get(key)
        if not isinstance(digest, str) or len(digest) != 64 or any(value not in "0123456789abcdef" for value in digest):
            return None
    challenge = decode_native_approval_v4_challenge(payload.get("challenge"))
    if challenge is None or challenge["request_id"] != payload["request_id"]:
        return None
    return {**payload, "challenge": challenge}


def native_renewal_matches_original(renewal: Mapping[str, object], original: object) -> bool:
    """Allow credential/policy freshness only; never change the frozen action."""
    decoded = decode_native_authority_renewal(dict(renewal))
    frozen = decode_native_approval_v4_challenge(original)
    if decoded is None or frozen is None:
        return False
    challenge = cast(dict[str, object], decoded["challenge"])
    freshness = {
        "request_digest",
        "policy_generation",
        "policy_digest",
        "resident_epoch",
        "nonce",
        "issued_at_ms",
        "expires_at_ms",
        "webauthn",
        "signing_key_id",
    }
    if any(challenge[key] != value for key, value in frozen.items() if key not in freshness):
        return False
    original_webauthn = cast(dict[str, object], frozen["webauthn"])
    fresh_webauthn = cast(dict[str, object], challenge["webauthn"])
    rotated_key = challenge["signing_key_id"] != frozen["signing_key_id"]
    webauthn_freshness = {"challenge", "credential_id", "algorithm"} if rotated_key else {"challenge"}
    if any(fresh_webauthn[key] != value for key, value in original_webauthn.items() if key not in webauthn_freshness):
        return False
    if (
        challenge["nonce"] == frozen["nonce"]
        or fresh_webauthn["challenge"] == original_webauthn["challenge"]
        or cast(int, challenge["policy_generation"]) < cast(int, frozen["policy_generation"])
        or cast(int, challenge["issued_at_ms"]) < cast(int, frozen["expires_at_ms"])
    ):
        return False
    return decoded["original_nonce_digest"] == hashlib.sha256(bytes.fromhex(cast(str, frozen["nonce"]))).hexdigest()


def _original_nonce_digest(original_challenge: Mapping[str, object], request_id: str) -> str:
    original = decode_native_approval_v4_challenge(dict(original_challenge))
    if original is None or original["request_id"] != request_id:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_original_pending_mismatch")
    return hashlib.sha256(bytes.fromhex(cast(str, original["nonce"]))).hexdigest()


def get_native_approval_renewal(
    guard_home: Path,
    *,
    request_id: str,
    decision_receipt_id: str,
    source_claim_hash: str,
    original_challenge: Mapping[str, object],
) -> dict[str, object]:
    response = request_native_cloud_review(
        guard_home,
        "approval_renewal_query_v4",
        {
            "schema": "guard-native-cloud-review-renewal-query.v4",
            "version": 4,
            "request_id": request_id,
            "decision_receipt_id": decision_receipt_id,
            "source_claim_hash": source_claim_hash,
            "original_nonce_digest": _original_nonce_digest(original_challenge, request_id),
        },
    )
    return _checked_native_renewal(response, request_id, decision_receipt_id, source_claim_hash, original_challenge)


def renew_native_approval_authority(
    guard_home: Path,
    *,
    request_id: str,
    decision_receipt_id: str,
    source_claim_hash: str,
    original_challenge: Mapping[str, object],
) -> dict[str, object]:
    """Query original outcome before native derives a fresh, uninstalled challenge.

    The caller supplies only immutable saved-decision identity, never action input.
    Actual fresh UP+UV must sign the returned challenge; this operation cannot install,
    consume, dispatch a provider action, or resume a harness.
    """
    try:
        response = request_native_cloud_review(
            guard_home,
            "approval_consumption_query_v4",
            {
                "schema": "guard-native-cloud-review-consumption-query.v4",
                "version": 4,
                "request_id": request_id,
                "decision_receipt_id": decision_receipt_id,
                "source_claim_hash": source_claim_hash,
            },
        )
    except NativeCloudReviewV4Error as error:
        if error.code != "native_cloud_review_v4_not_installed":
            raise
    else:
        observed = decode_native_application_observation(response)
        if (
            observed is None
            or observed["request_id"] != request_id
            or observed["decision_receipt_id"] != decision_receipt_id
            or observed["source_claim_hash"] != source_claim_hash
        ):
            raise NativeCloudReviewV4Error("native_cloud_review_v4_observation_invalid")
        if observed["phase"] == "consumed":
            raise NativeCloudReviewV4Error("native_cloud_review_v4_already_consumed")
        if observed["phase"] == "blocked":
            raise NativeCloudReviewV4Error("native_cloud_review_v4_immutable_binding_conflict")
        if observed["phase"] == "recovery_required":
            raise NativeCloudReviewV4Error("native_cloud_review_v4_consumption_recovery_required")
    response = request_native_cloud_review(
        guard_home,
        "approval_renew_v4",
        {
            "schema": "guard-native-cloud-review-renewal-request.v4",
            "version": 4,
            "request_id": request_id,
            "decision_receipt_id": decision_receipt_id,
            "source_claim_hash": source_claim_hash,
            "original_nonce_digest": _original_nonce_digest(original_challenge, request_id),
        },
    )
    return _checked_native_renewal(response, request_id, decision_receipt_id, source_claim_hash, original_challenge)


def _checked_native_renewal(
    response: object,
    request_id: str,
    decision_receipt_id: str,
    source_claim_hash: str,
    original_challenge: Mapping[str, object],
) -> dict[str, object]:
    renewal = decode_native_authority_renewal(response)
    if (
        renewal is None
        or renewal["request_id"] != request_id
        or renewal["decision_receipt_id"] != decision_receipt_id
        or renewal["source_claim_hash"] != source_claim_hash
        or not native_renewal_matches_original(renewal, original_challenge)
    ):
        raise NativeCloudReviewV4Error("native_cloud_review_v4_renewal_action_mismatch")
    return renewal


def decode_native_application_observation(payload: object) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        return None
    data = cast(dict[str, object], payload)
    if (
        set(data)
        != {
            "schema",
            "version",
            "request_id",
            "decision_receipt_id",
            "source_claim_hash",
            "phase",
            "consumed_at_ms",
            "receipt",
        }
        or data.get("schema") != "guard-native-cloud-review-application-result.v4"
        or data.get("version") != 4
        or any(
            not isinstance(data.get(key), str) or not data[key]
            for key in ("request_id", "decision_receipt_id", "source_claim_hash")
        )
    ):
        return None
    if data.get("phase") in {"waiting_for_authorization", "waiting_for_hook", "blocked", "recovery_required"}:
        return dict(data) if data.get("receipt") is None and data.get("consumed_at_ms") is None else None
    if data.get("phase") != "consumed" or not _integer(data.get("consumed_at_ms"), minimum=1):
        return None
    receipt = decode_native_approval_v4_receipt(data.get("receipt"), phase="consumed")
    if receipt is None or receipt.get("request_id") != data["request_id"]:
        return None
    return {**data, "receipt": receipt}


def decode_native_application_result(payload: object) -> dict[str, object] | None:
    """Validate the immutable Portal transport shape, not attest its origin."""
    if not isinstance(payload, dict) or set(payload) != {
        "decisionReceiptId",
        "sourceClaimHash",
        "consumedAt",
        "receipt",
    }:
        return None
    if any(
        not isinstance(payload.get(key), str) or not payload[key]
        for key in ("decisionReceiptId", "sourceClaimHash", "consumedAt")
    ):
        return None
    receipt = decode_native_approval_v4_receipt(payload.get("receipt"), phase="consumed")
    if receipt is None:
        return None
    try:
        consumed = datetime.fromisoformat(payload["consumedAt"].replace("Z", "+00:00"))
    except ValueError:
        return None
    if consumed.tzinfo is None:
        return None
    if consumed.microsecond % 1000:
        return None
    delta = consumed - datetime(1970, 1, 1, tzinfo=timezone.utc)
    milliseconds = delta.days * 86_400_000 + delta.seconds * 1000 + delta.microseconds // 1000
    if not receipt["issued_at_ms"] <= milliseconds < receipt["expires_at_ms"]:
        return None
    return {**payload, "receipt": receipt}


def native_application_result(observation: Mapping[str, object]) -> dict[str, object]:
    observed = decode_native_application_observation(dict(observation))
    if observed is None or observed["phase"] != "consumed":
        raise NativeCloudReviewV4Error("native_cloud_review_v4_positive_invalid")
    milliseconds = cast(int, observed["consumed_at_ms"])
    consumed = datetime.fromtimestamp(milliseconds // 1000, timezone.utc).replace(
        microsecond=(milliseconds % 1000) * 1000
    )
    result = {
        "decisionReceiptId": observed["decision_receipt_id"],
        "sourceClaimHash": observed["source_claim_hash"],
        "consumedAt": consumed.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "receipt": observed["receipt"],
    }
    if decode_native_application_result(result) is None:
        raise NativeCloudReviewV4Error("native_cloud_review_v4_positive_invalid")
    return result
