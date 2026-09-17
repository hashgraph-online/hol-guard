"""Existing Cloud generic v2 ACK contract and shared observation timestamps."""

from __future__ import annotations

import re
from datetime import datetime, timezone

GENERIC_ACK_KEYS = frozenset(
    {
        "contractVersion",
        "workspaceId",
        "deviceId",
        "bundleVersion",
        "bundleHash",
        "sequence",
        "status",
        "observedAt",
        "errorCode",
    }
)
GENERIC_ACK_IDENTITY = frozenset({"contractVersion", "workspaceId", "deviceId", "bundleVersion", "bundleHash"})
_TRANSITIONS = {
    "received": frozenset({"received", "validated", "applied", "failed", "offline"}),
    "validated": frozenset({"validated", "applied", "failed", "offline"}),
    "applied": frozenset({"applied", "offline"}),
    "failed": frozenset({"failed", "received", "offline"}),
    "offline": frozenset({"offline", "received"}),
}
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


def normalized_observed_at(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def generic_ack_matches_bundle(
    acknowledgement: dict[str, object],
    bundle: dict[str, object] | None,
    *,
    device_id: str,
) -> bool:
    if bundle is None or acknowledgement.get("deviceId") != device_id:
        return False
    return all(
        acknowledgement.get(key) == bundle.get(key)
        for key in ("workspaceId", "bundleHash", "bundleVersion", "contractVersion")
    )


def _bounded_string(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value.strip()) <= 128 and value == value.strip()


def _safe_positive_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < 2**53


def _generic_ack_error(value: dict[str, object]) -> str | None:
    if set(value) - GENERIC_ACK_KEYS:
        return "unknown_field"
    if GENERIC_ACK_KEYS - {"errorCode"} - set(value):
        return "missing_required_field"
    if value.get("contractVersion") != "guard-policy-bundle.v2":
        return "unsupported_contract_version"
    if not all(_bounded_string(value.get(key)) for key in ("workspaceId", "deviceId")):
        return "invalid_acknowledgement"
    if not all(_safe_positive_integer(value.get(key)) for key in ("bundleVersion", "sequence")):
        return "invalid_acknowledgement"
    digest = value.get("bundleHash")
    if not isinstance(digest, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None:
        return "invalid_acknowledgement"
    status = value.get("status")
    if not isinstance(status, str) or status not in _TRANSITIONS:
        return "invalid_acknowledgement_status"
    observed = value.get("observedAt")
    if not isinstance(observed, str) or _UTC_TIMESTAMP.fullmatch(observed) is None:
        return "invalid_acknowledgement"
    try:
        datetime.fromisoformat(observed.replace("Z", "+00:00"))
    except ValueError:
        return "invalid_acknowledgement"
    error = value.get("errorCode")
    if status in {"failed", "offline"}:
        if not _bounded_string(error):
            return "invalid_acknowledgement"
    elif error is not None:
        return "invalid_acknowledgement"
    return None


def validated_generic_policy_acknowledgement(
    value: dict[str, object],
    *,
    previous: dict[str, object] | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    error = _generic_ack_error(value)
    if error is not None:
        return None, error
    if previous is None:
        return value, None
    if _generic_ack_error(previous) is not None:
        return None, "invalid_previous_acknowledgement"
    if any(value.get(key) != previous.get(key) for key in GENERIC_ACK_IDENTITY):
        return None, "acknowledgement_identity_mismatch"
    sequence, prior_sequence = value["sequence"], previous["sequence"]
    assert isinstance(sequence, int) and isinstance(prior_sequence, int)
    if sequence < prior_sequence:
        return None, "acknowledgement_replay"
    if sequence == prior_sequence:
        return (value, None) if value == previous else (None, "acknowledgement_sequence_conflict")
    if value["status"] not in _TRANSITIONS[str(previous["status"])]:
        return None, "acknowledgement_transition_rejected"
    return value, None
