"""Public protocol contract for bounded Guard service recovery."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from typing import Final
from uuid import UUID

SCHEMA: Final = "hol-guard-recovery.v1"
MAX_EVENT_BYTES: Final = 16 * 1024

CAPABILITIES: Final = frozenset({"inspect", "restart", "status", "diagnostics"})
PHASES: Final = frozenset(
    {
        "checking",
        "awaiting_approval",
        "waiting_for_owner",
        "stopping",
        "starting",
        "reconnecting",
        "verifying",
        "complete",
        "needs_action",
        "failed",
        "timed_out_waiting",
    }
)
OUTCOMES: Final = frozenset({"pending", "reconnected", "started", "restarted", "not_recovered"})
SERVICE_STATES: Final = frozenset({"unknown", "unavailable", "ready"})
PROTECTION_STATES: Final = frozenset({"unknown", "verified", "needs_attention", "off"})
CHECK_RESULTS: Final = frozenset({"pass", "fail", "unknown"})
CHECK_IDS: Final = frozenset(
    {
        "update_idle",
        "protection_posture",
        "process_identity",
        "runtime_identity",
        "authenticated_service",
        "dashboard_ready",
        "protection_health",
    }
)
REASON_CODES: Final = frozenset(
    {
        "healthy",
        "service_missing",
        "service_unresponsive",
        "session_invalid",
        "endpoint_conflict",
        "identity_unverified",
        "runtime_mismatch",
        "multiple_instances",
        "protection_off",
        "approval_required",
        "operation_busy",
        "update_busy",
        "permission_denied",
        "storage_unavailable",
        "startup_failed",
        "deadline_exceeded",
        "worker_exit_unconfirmed",
        "unsupported_protocol",
        "unknown",
    }
)

_FIELDS: Final = frozenset(
    {
        "schema",
        "capabilities",
        "operationId",
        "sequence",
        "startedAt",
        "updatedAt",
        "phase",
        "activeElapsedMs",
        "workerActive",
        "retryAllowed",
        "outcome",
        "reasonCode",
        "service",
        "protection",
        "requiresHumanAction",
        "checks",
    }
)
_CHECK_FIELDS: Final = frozenset({"id", "result", "reasonCode"})
_FORBIDDEN_KEY_PARTS: Final = (
    "token",
    "password",
    "totp",
    "secret",
    "cookie",
    "authorization",
    "argv",
    "command",
    "path",
    "url",
    "error",
)


class RecoveryContractError(ValueError):
    """Raised when a public recovery payload violates the frozen protocol."""


def validate_recovery_snapshot(payload: object, *, allow_inspection: bool = True) -> dict[str, object]:
    """Validate and copy one complete public recovery snapshot."""

    if not isinstance(payload, Mapping):
        raise RecoveryContractError("recovery_snapshot_not_object")
    fields = set(payload)
    if fields != _FIELDS:
        raise RecoveryContractError("recovery_snapshot_fields_invalid")
    _reject_forbidden_keys(payload)
    if payload.get("schema") != SCHEMA:
        raise RecoveryContractError("unsupported_protocol")
    capabilities = payload.get("capabilities")
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or not all(isinstance(item, str) and item in CAPABILITIES for item in capabilities)
    ):
        raise RecoveryContractError("recovery_capabilities_invalid")
    if len(set(capabilities)) != len(capabilities):
        raise RecoveryContractError("recovery_capabilities_invalid")
    operation_id = payload.get("operationId")
    if operation_id is None:
        if not allow_inspection:
            raise RecoveryContractError("recovery_operation_id_required")
    elif not _valid_uuid(operation_id):
        raise RecoveryContractError("recovery_operation_id_invalid")
    sequence = payload.get("sequence")
    elapsed = payload.get("activeElapsedMs")
    if type(sequence) is not int or sequence < 0:
        raise RecoveryContractError("recovery_sequence_invalid")
    if type(elapsed) is not int or elapsed < 0:
        raise RecoveryContractError("recovery_elapsed_invalid")
    _require_timestamp(payload.get("startedAt"), "recovery_started_at_invalid")
    _require_timestamp(payload.get("updatedAt"), "recovery_updated_at_invalid")
    _require_member(payload, "phase", PHASES)
    _require_member(payload, "outcome", OUTCOMES)
    _require_member(payload, "reasonCode", REASON_CODES)
    _require_member(payload, "service", SERVICE_STATES)
    _require_member(payload, "protection", PROTECTION_STATES)
    for field in ("workerActive", "retryAllowed", "requiresHumanAction"):
        if type(payload.get(field)) is not bool:
            raise RecoveryContractError(f"recovery_{field}_invalid")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise RecoveryContractError("recovery_checks_invalid")
    validated_checks = [_validate_check(check) for check in checks]
    check_ids = [str(check["id"]) for check in validated_checks]
    if len(set(check_ids)) != len(check_ids):
        raise RecoveryContractError("recovery_checks_duplicate")
    normalized = dict(payload)
    if isinstance(operation_id, str):
        normalized["operationId"] = str(UUID(operation_id))
    normalized["capabilities"] = list(capabilities)
    normalized["checks"] = validated_checks
    _validate_terminal_invariants(normalized)
    encoded = json.dumps(normalized, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(encoded) > MAX_EVENT_BYTES:
        raise RecoveryContractError("recovery_event_too_large")
    return normalized


def encode_recovery_event(payload: object) -> bytes:
    """Return one validated newline-delimited JSON event."""

    snapshot = validate_recovery_snapshot(payload)
    return json.dumps(snapshot, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"


def validate_event_sequence(previous: Mapping[str, object] | None, current: object) -> dict[str, object]:
    """Reject late or cross-operation events before they can replace UI state."""

    snapshot = validate_recovery_snapshot(current, allow_inspection=False)
    if previous is None:
        return snapshot
    previous_snapshot = validate_recovery_snapshot(previous, allow_inspection=False)
    if previous_snapshot["operationId"] != snapshot["operationId"]:
        raise RecoveryContractError("recovery_operation_changed")
    current_sequence = snapshot["sequence"]
    previous_sequence = previous_snapshot["sequence"]
    if not isinstance(current_sequence, int) or not isinstance(previous_sequence, int):
        raise RecoveryContractError("recovery_sequence_invalid")
    if current_sequence <= previous_sequence:
        raise RecoveryContractError("recovery_sequence_not_increasing")
    return snapshot


def _validate_check(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _CHECK_FIELDS:
        raise RecoveryContractError("recovery_check_fields_invalid")
    _reject_forbidden_keys(value)
    check_id = value.get("id")
    result = value.get("result")
    reason = value.get("reasonCode")
    if (
        not isinstance(check_id, str)
        or not isinstance(result, str)
        or not isinstance(reason, str)
        or check_id not in CHECK_IDS
        or result not in CHECK_RESULTS
        or reason not in REASON_CODES
    ):
        raise RecoveryContractError("recovery_check_invalid")
    return {"id": str(check_id), "result": str(result), "reasonCode": str(reason)}


def _validate_terminal_invariants(snapshot: Mapping[str, object]) -> None:
    phase = snapshot["phase"]
    if phase == "complete":
        if snapshot["workerActive"] or not snapshot["retryAllowed"]:
            raise RecoveryContractError("recovery_complete_worker_invalid")
        if snapshot["service"] != "ready" or snapshot["outcome"] in {"pending", "not_recovered"}:
            raise RecoveryContractError("recovery_complete_outcome_invalid")
    if phase == "timed_out_waiting" and (not snapshot["workerActive"] or snapshot["retryAllowed"]):
        raise RecoveryContractError("recovery_timeout_worker_invalid")
    checks = snapshot["checks"]
    if not isinstance(checks, list):
        raise RecoveryContractError("recovery_checks_invalid")
    if snapshot["protection"] == "verified" and not any(
        check["id"] == "protection_health" and check["result"] == "pass" for check in checks
    ):
        raise RecoveryContractError("recovery_protection_unverified")


def _reject_forbidden_keys(value: Mapping[object, object]) -> None:
    for key in value:
        lowered = str(key).lower()
        if any(part in lowered for part in _FORBIDDEN_KEY_PARTS):
            raise RecoveryContractError("recovery_sensitive_field_forbidden")


def _require_member(payload: Mapping[object, object], field: str, allowed: frozenset[str]) -> None:
    value = payload.get(field)
    if not isinstance(value, str) or value not in allowed:
        raise RecoveryContractError(f"recovery_{field}_invalid")


def _require_timestamp(value: object, code: str) -> None:
    if not isinstance(value, str) or not value:
        raise RecoveryContractError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RecoveryContractError(code) from error
    if parsed.tzinfo is None:
        raise RecoveryContractError(code)


def _valid_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value.lower()
    except ValueError:
        return False


__all__ = [
    "CAPABILITIES",
    "CHECK_IDS",
    "MAX_EVENT_BYTES",
    "OUTCOMES",
    "PHASES",
    "PROTECTION_STATES",
    "REASON_CODES",
    "SCHEMA",
    "SERVICE_STATES",
    "RecoveryContractError",
    "encode_recovery_event",
    "validate_event_sequence",
    "validate_recovery_snapshot",
]
