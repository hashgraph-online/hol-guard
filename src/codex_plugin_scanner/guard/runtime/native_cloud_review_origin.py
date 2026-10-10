"""Preserve private-native original challenges across pending and Cloud snapshots."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from copy import deepcopy
from typing import cast

from ..native_approval_v4_protocol import decode_native_approval_v4_challenge
from ..native_decision_receipt import validate_native_decision_receipt
from .cloud_review_request_purpose import canonical_request_kind

NATIVE_CLOUD_REVIEW_ORIGIN_FIELD = "native_cloud_review_origin"
NATIVE_CLOUD_REVIEW_ORIGIN_UNAVAILABLE_FIELD = "native_cloud_review_origin_unavailable"
NATIVE_CLOUD_REVIEW_ORIGIN_QUEUE_PREFIX = "native-origin-v4:"
_ORIGIN_FIELDS = frozenset({"schema", "version", "request_id", "challenge", "consent_revision", "revocation_epoch"})
_REVIEW_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required"})
_SAFE_INTEGER = (1 << 53) - 1


def eligible_native_origin_receipt(receipt: object, *, harness: str) -> dict[str, object] | None:
    """Only an authenticated original pause can be used for the private-origin query."""

    validated = validate_native_decision_receipt(receipt)
    if (
        validated is None
        or "origin_authentication" not in validated
        or validated.get("harness") != harness
        or validated.get("event_name") not in {"PreToolUse", "UserPromptSubmit"}
        or validated.get("decision") != "deny"
        or validated.get("policy_action") not in _REVIEW_ACTIONS
        or validated.get("observe_mode") is not False
    ):
        return None
    return validated


def decode_native_approval_origin_result(origin: object) -> dict[str, object] | None:
    """Validate transport shape; receipt binding remains a separate check."""
    if not isinstance(origin, Mapping):
        return None
    data = cast(Mapping[str, object], origin)
    if (
        not _ORIGIN_FIELDS.issubset(data)
        or set(data) - _ORIGIN_FIELDS - {"command_sha256"}
        or data.get("schema") != "guard-native-cloud-review-origin-result.v4"
        or type(data.get("version")) is not int
        or data.get("version") != 4
    ):
        return None
    for field, minimum in (("consent_revision", 1), ("revocation_epoch", 0)):
        value = data.get(field)
        if type(value) is not int or not minimum <= cast(int, value) <= _SAFE_INTEGER:
            return None
    command_digest = data.get("command_sha256")
    if "command_sha256" in data and (
        not isinstance(command_digest, str) or re.fullmatch(r"[a-f0-9]{64}", command_digest) is None
    ):
        return None
    challenge = decode_native_approval_v4_challenge(data.get("challenge"))
    if challenge is None or data.get("request_id") != challenge["request_id"]:
        return None
    return deepcopy({**data, "challenge": challenge})


def validated_native_approval_origin(
    origin: object,
    *,
    native_receipt: object,
    harness: str,
) -> dict[str, object] | None:
    """Bind a native query observation, without assigning it cryptographic authority.

    The native request digest binds the original raw hook input. Its action
    digest is a different Rust commitment, not the SDK envelope hash or the
    receipt's execution-intent digest; preserve it rather than reconstruct it.
    """

    receipt = eligible_native_origin_receipt(native_receipt, harness=harness)
    data = decode_native_approval_origin_result(origin)
    if receipt is None or data is None or data["request_id"] != receipt["request_id"]:
        return None
    challenge = cast(dict[str, object], data["challenge"])
    if (
        challenge.get("approval_eligible") is not True
        or challenge.get("floor_class") != "approvable"
        or challenge.get("minimum_action") != receipt["policy_action"]
        or challenge.get("requested_action") != receipt["policy_action"]
        or any(
            challenge.get(field) is None for field in ("workspace_binding", "device_binding", "installation_binding")
        )
    ):
        return None
    for field in (
        "request_id",
        "request_digest",
        "harness",
        "policy_generation",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
    ):
        if challenge.get(field) != receipt.get(field):
            return None
    if challenge.get("runtime_binary_identity") != receipt.get("runtime_identity"):
        return None
    return data


def native_approval_origins_match(left: Mapping[str, object] | None, right: Mapping[str, object] | None) -> bool:
    """Preserve an already frozen origin when optional source metadata appears."""

    if left is None or right is None or any(left.get(field) != right.get(field) for field in _ORIGIN_FIELDS):
        return False
    return (
        "command_sha256" not in left
        or "command_sha256" not in right
        or left["command_sha256"] == right["command_sha256"]
    )


def _snapshot_envelope(request_snapshot: Mapping[str, object]) -> Mapping[str, object]:
    envelope = request_snapshot.get("action_envelope_json")
    if isinstance(envelope, str):
        try:
            envelope = json.loads(envelope)
        except (TypeError, ValueError):
            return {}
    return cast(Mapping[str, object], envelope) if isinstance(envelope, Mapping) else {}


def has_native_approval_origin_marker(
    request_snapshot: Mapping[str, object],
    *,
    include_unavailable: bool = True,
) -> bool:
    envelope = _snapshot_envelope(request_snapshot)
    return (
        NATIVE_CLOUD_REVIEW_ORIGIN_FIELD in envelope
        or "nativeApprovalChallenge" in envelope
        or (include_unavailable and NATIVE_CLOUD_REVIEW_ORIGIN_UNAVAILABLE_FIELD in envelope)
    )


def frozen_native_approval_origin(request_snapshot: Mapping[str, object]) -> dict[str, object] | None:
    """Read only a producer-frozen v4 origin; never upgrade or renew stored rows."""

    if canonical_request_kind(request_snapshot) != "reviewable_pause":
        return None
    request_id = request_snapshot.get("request_id")
    harness = request_snapshot.get("harness")
    if (
        not isinstance(request_id, str)
        or not isinstance(harness, str)
        or request_snapshot.get("queue_group_id") != NATIVE_CLOUD_REVIEW_ORIGIN_QUEUE_PREFIX + request_id
    ):
        return None
    envelope = _snapshot_envelope(request_snapshot)
    if NATIVE_CLOUD_REVIEW_ORIGIN_UNAVAILABLE_FIELD in envelope:
        return None
    origin = validated_native_approval_origin(
        envelope.get(NATIVE_CLOUD_REVIEW_ORIGIN_FIELD),
        native_receipt=envelope.get("native_origin_receipt"),
        harness=harness,
    )
    if (
        origin is None
        or origin["request_id"] != request_id
        or envelope.get("nativeApprovalChallenge") != origin["challenge"]
    ):
        return None
    return origin


def frozen_native_approval_challenge(request_snapshot: Mapping[str, object]) -> dict[str, object] | None:
    origin = frozen_native_approval_origin(request_snapshot)
    return cast(dict[str, object], origin["challenge"]) if origin is not None else None


def frozen_native_origin_unavailable(request_snapshot: Mapping[str, object]) -> dict[str, object] | None:
    marker = _snapshot_envelope(request_snapshot).get(NATIVE_CLOUD_REVIEW_ORIGIN_UNAVAILABLE_FIELD)
    if not isinstance(marker, Mapping):
        return None
    value = cast(Mapping[str, object], marker)
    reason = value.get("reason_code")
    request_id = value.get("request_id")
    if (
        set(value) != {"schema", "version", "request_id", "reason_code", "executable"}
        or value.get("schema") != "guard-native-cloud-review-origin-unavailable.v4"
        or type(value.get("version")) is not int
        or value.get("version") != 4
        or value.get("executable") is not False
        or not isinstance(reason, str)
        or re.fullmatch(r"[a-z0-9_]{1,128}", reason) is None
        or (request_id is not None and (not isinstance(request_id, str) or not 1 <= len(request_id) <= 256))
    ):
        return None
    return deepcopy(dict(value))
