"""Strict validation for privacy-safe network status projections."""

from __future__ import annotations

import math
import re
import time
from collections.abc import Mapping
from typing import TypeGuard, cast

from codex_plugin_scanner.guard.runtime.network_capability_contract import (
    PlatformFamily,
    enforcement_grade_rank,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import EnforcementGrade, NetworkAction
from codex_plugin_scanner.guard.runtime.provider_recovery import RecoveryPhase

_ENFORCING_GRADES = frozenset(
    grade for grade in EnforcementGrade if grade not in {EnforcementGrade.UNAVAILABLE, EnforcementGrade.OBSERVE}
)
_SAFE_IDENTIFIER = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")
_DIGEST = re.compile(r"[0-9a-f]{64}")


class NetworkStatusSchemaError(ValueError):
    """Raised when daemon status cannot safely be treated as network truth."""


def _is_object(value: object) -> TypeGuard[Mapping[str, object]]:
    return isinstance(value, Mapping) and all(isinstance(key, str) for key in value)


def _exact_bool(value: object) -> bool:
    return type(value) is bool


def _valid_optional_string(value: object) -> bool:
    return value is None or isinstance(value, str)


def _is_safe_identifier(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and len(value) <= 128 and _SAFE_IDENTIFIER.fullmatch(value) is not None


def _is_optional_digest(value: object) -> bool:
    return value is None or (isinstance(value, str) and _DIGEST.fullmatch(value) is not None)


def _require_enum(
    value: object,
    enum_type: type[PlatformFamily] | type[EnforcementGrade] | type[RecoveryPhase],
) -> None:
    if not isinstance(value, str):
        raise NetworkStatusSchemaError("network status enum must be a string")
    try:
        enum_type(value)
    except ValueError as error:
        raise NetworkStatusSchemaError("network status enum is invalid") from error


def _validate_header(payload: object) -> tuple[Mapping[str, object], object, EnforcementGrade]:
    if not _is_object(payload) or payload.get("schema") != "guard.network-status.v1":
        raise NetworkStatusSchemaError("network status schema is invalid")
    host_platform = payload.get("host_platform")
    if host_platform != "unsupported":
        _require_enum(host_platform, PlatformFamily)
    _require_enum(payload.get("effective_grade"), EnforcementGrade)
    _require_enum(payload.get("independently_observed_grade"), EnforcementGrade)
    for field in ("protection_active", "independently_observed"):
        if not _exact_bool(payload.get(field)):
            raise NetworkStatusSchemaError("network status boolean is invalid")
    if not _is_safe_identifier(payload.get("reason_code")):
        raise NetworkStatusSchemaError("network status reason is invalid")
    return payload, host_platform, EnforcementGrade(str(payload["effective_grade"]))


def _validate_backend(
    raw_backend: object,
    *,
    host_platform: object,
    backend_ids: set[str],
) -> tuple[Mapping[str, object], bool]:
    if not _is_object(raw_backend):
        raise NetworkStatusSchemaError("network status backend is invalid")
    if not _is_safe_identifier(raw_backend.get("backend_id")):
        raise NetworkStatusSchemaError("network status backend id is invalid")
    backend_id = cast(str, raw_backend["backend_id"])
    if backend_id in backend_ids:
        raise NetworkStatusSchemaError("network status backend id is duplicated")
    backend_ids.add(backend_id)
    _require_enum(raw_backend.get("platform"), PlatformFamily)
    _require_enum(raw_backend.get("advertised_maximum_grade"), EnforcementGrade)
    _require_enum(raw_backend.get("effective_grade"), EnforcementGrade)
    for field in (
        "supported",
        "installed",
        "verified",
        "active",
        "observed",
        "production_ready",
        "requires_privilege",
    ):
        if not _exact_bool(raw_backend.get(field)):
            raise NetworkStatusSchemaError("network status backend boolean is invalid")
    if not _is_safe_identifier(raw_backend.get("reason_code")) or not _is_safe_identifier(
        raw_backend.get("reference_reason_code")
    ):
        raise NetworkStatusSchemaError("network status backend reason is invalid")
    if raw_backend["verified"] and not raw_backend["installed"]:
        raise NetworkStatusSchemaError("verified network backend must be installed")
    advertised_grade = EnforcementGrade(str(raw_backend["advertised_maximum_grade"]))
    backend_grade = EnforcementGrade(str(raw_backend["effective_grade"]))
    if enforcement_grade_rank(backend_grade) > enforcement_grade_rank(advertised_grade):
        raise NetworkStatusSchemaError("network backend exceeds its advertised grade")
    active = bool(raw_backend["active"])
    if active:
        if not raw_backend["supported"] or not raw_backend["verified"]:
            raise NetworkStatusSchemaError("active network backend must be verified")
        if not raw_backend["production_ready"]:
            raise NetworkStatusSchemaError("active network backend must be production ready")
        if raw_backend["platform"] != host_platform:
            raise NetworkStatusSchemaError("active network backend must match the host")
        if backend_grade not in _ENFORCING_GRADES:
            raise NetworkStatusSchemaError("active network backend must enforce")
    elif backend_grade in _ENFORCING_GRADES:
        raise NetworkStatusSchemaError("inactive network backend cannot enforce")
    return raw_backend, active


def _validate_backends(
    payload: Mapping[str, object],
    *,
    host_platform: object,
) -> tuple[list[Mapping[str, object]], list[Mapping[str, object]]]:
    raw_backends = payload.get("backends")
    if not isinstance(raw_backends, list):
        raise NetworkStatusSchemaError("network status backends are invalid")
    active_backends: list[Mapping[str, object]] = []
    validated_backends: list[Mapping[str, object]] = []
    backend_ids: set[str] = set()
    for candidate in raw_backends:
        backend, active = _validate_backend(candidate, host_platform=host_platform, backend_ids=backend_ids)
        if active:
            active_backends.append(backend)
        validated_backends.append(backend)
    return active_backends, validated_backends


def _validate_summaries(
    payload: Mapping[str, object],
    *,
    effective_grade: EnforcementGrade,
    active_backends: list[Mapping[str, object]],
    validated_backends: list[Mapping[str, object]],
) -> tuple[bool, bool, EnforcementGrade]:
    protection_active = bool(payload["protection_active"])
    if protection_active != bool(active_backends):
        raise NetworkStatusSchemaError("network protection summary is inconsistent")
    if protection_active and len(active_backends) != 1:
        raise NetworkStatusSchemaError("network protection requires one active backend")
    if not protection_active and effective_grade is not EnforcementGrade.UNAVAILABLE:
        raise NetworkStatusSchemaError("inactive network protection must be unavailable")
    if protection_active and all(
        EnforcementGrade(str(backend["effective_grade"])) is not effective_grade for backend in active_backends
    ):
        raise NetworkStatusSchemaError("network protection grade is inconsistent")

    independently_observed = bool(payload["independently_observed"])
    observed_grade = EnforcementGrade(str(payload["independently_observed_grade"]))
    if independently_observed != (observed_grade is not EnforcementGrade.UNAVAILABLE):
        raise NetworkStatusSchemaError("network observer summary is inconsistent")
    observed_backends = [backend for backend in validated_backends if bool(backend["observed"])]
    if bool(observed_backends) != independently_observed:
        raise NetworkStatusSchemaError("network backend observer summary is inconsistent")
    if independently_observed:
        observed_backend_grades = [EnforcementGrade(str(backend["effective_grade"])) for backend in observed_backends]
        if any(grade is EnforcementGrade.UNAVAILABLE for grade in observed_backend_grades):
            raise NetworkStatusSchemaError("observed network backend grade is invalid")
        maximum_observed_grade = max(observed_backend_grades, key=enforcement_grade_rank)
        if observed_grade is not maximum_observed_grade:
            raise NetworkStatusSchemaError("network observer grade is inconsistent")
    return protection_active, independently_observed, observed_grade


def _validate_supervisor_shape(supervisor: object) -> Mapping[str, object]:
    if not _is_object(supervisor):
        raise NetworkStatusSchemaError("network supervisor is invalid")
    supervisor_fields = {
        "phase",
        "backend_id",
        "backend_digest",
        "effective_grade",
        "healthy_until_epoch_ms",
        "retry_attempt",
        "next_retry_seconds",
        "permits_enforcement",
        "independently_observed",
    }
    if not supervisor_fields.issubset(supervisor):
        raise NetworkStatusSchemaError("network supervisor is incomplete")
    _require_enum(supervisor.get("phase"), RecoveryPhase)
    _require_enum(supervisor.get("effective_grade"), EnforcementGrade)
    return supervisor


def _validate_supervisor_identity(supervisor: Mapping[str, object]) -> tuple[object, object]:
    for field in ("backend_id", "backend_digest"):
        if not _valid_optional_string(supervisor.get(field)):
            raise NetworkStatusSchemaError("network supervisor identity is invalid")
    supervisor_backend_id = supervisor.get("backend_id")
    if supervisor_backend_id is not None and not _is_safe_identifier(supervisor_backend_id):
        raise NetworkStatusSchemaError("network supervisor backend id is invalid")
    supervisor_digest = supervisor.get("backend_digest")
    if not _is_optional_digest(supervisor_digest):
        raise NetworkStatusSchemaError("network supervisor digest is invalid")
    healthy_until = supervisor.get("healthy_until_epoch_ms")
    if healthy_until is not None and (type(healthy_until) is not int or cast(int, healthy_until) < 0):
        raise NetworkStatusSchemaError("network supervisor expiry is invalid")
    return supervisor_digest, healthy_until


def _validate_supervisor_recovery(supervisor: Mapping[str, object]) -> None:
    retry_attempt = supervisor.get("retry_attempt")
    next_retry = supervisor.get("next_retry_seconds")
    if type(retry_attempt) is not int or cast(int, retry_attempt) < 0:
        raise NetworkStatusSchemaError("network supervisor retry is invalid")
    if type(next_retry) not in {int, float}:
        raise NetworkStatusSchemaError("network supervisor delay is invalid")
    if not math.isfinite(cast(int | float, next_retry)) or cast(int | float, next_retry) < 0:
        raise NetworkStatusSchemaError("network supervisor delay is invalid")
    for field in ("permits_enforcement", "independently_observed"):
        if not _exact_bool(supervisor.get(field)):
            raise NetworkStatusSchemaError("network supervisor boolean is invalid")


def _validate_supervisor_proof(
    supervisor: Mapping[str, object],
    *,
    supervisor_digest: object,
    healthy_until: object,
    current_epoch_ms: int,
    protection_active: bool,
    independently_observed: bool,
    effective_grade: EnforcementGrade,
    active_backends: list[Mapping[str, object]],
) -> None:
    supervisor_grade = EnforcementGrade(str(supervisor["effective_grade"]))
    expected_permits = supervisor.get("phase") == RecoveryPhase.HEALTHY.value and supervisor_grade in _ENFORCING_GRADES
    if supervisor["permits_enforcement"] is not expected_permits:
        raise NetworkStatusSchemaError("network supervisor enforcement is inconsistent")
    if bool(supervisor["permits_enforcement"]) != protection_active:
        raise NetworkStatusSchemaError("network supervisor protection summary is inconsistent")
    if bool(supervisor["independently_observed"]) != independently_observed:
        raise NetworkStatusSchemaError("network supervisor observer summary is inconsistent")
    if protection_active and (
        not expected_permits
        or supervisor_grade is not effective_grade
        or supervisor_digest is None
        or healthy_until is None
        or cast(int, healthy_until) <= current_epoch_ms
        or supervisor.get("backend_id") not in {backend["backend_id"] for backend in active_backends}
    ):
        raise NetworkStatusSchemaError("network supervisor does not prove protection")


def _validate_supervisor(
    supervisor: object,
    *,
    current_epoch_ms: int,
    protection_active: bool,
    independently_observed: bool,
    effective_grade: EnforcementGrade,
    active_backends: list[Mapping[str, object]],
) -> Mapping[str, object] | None:
    if protection_active and supervisor is None:
        raise NetworkStatusSchemaError("active network protection requires supervisor proof")
    if supervisor is None:
        return None
    validated_supervisor = _validate_supervisor_shape(supervisor)
    supervisor_digest, healthy_until = _validate_supervisor_identity(validated_supervisor)
    _validate_supervisor_recovery(validated_supervisor)
    _validate_supervisor_proof(
        validated_supervisor,
        supervisor_digest=supervisor_digest,
        healthy_until=healthy_until,
        current_epoch_ms=current_epoch_ms,
        protection_active=protection_active,
        independently_observed=independently_observed,
        effective_grade=effective_grade,
        active_backends=active_backends,
    )
    return validated_supervisor


def _project_backends(validated_backends: list[Mapping[str, object]]) -> list[dict[str, object]]:
    return [
        {
            field: backend[field]
            for field in (
                "backend_id",
                "platform",
                "supported",
                "installed",
                "verified",
                "active",
                "observed",
                "advertised_maximum_grade",
                "effective_grade",
                "production_ready",
                "requires_privilege",
                "reason_code",
                "reference_reason_code",
            )
        }
        for backend in validated_backends
    ]


def _project_supervisor(supervisor: Mapping[str, object]) -> dict[str, object]:
    return {
        field: supervisor[field]
        for field in (
            "phase",
            "backend_id",
            "backend_digest",
            "effective_grade",
            "healthy_until_epoch_ms",
            "retry_attempt",
            "next_retry_seconds",
            "permits_enforcement",
            "independently_observed",
        )
    }


def _project_legacy_policy(legacy_policy: object) -> dict[str, object] | None:
    if legacy_policy is None:
        return None
    if not _is_object(legacy_policy):
        raise NetworkStatusSchemaError("legacy network domain policy is invalid")
    raw_action = legacy_policy.get("action")
    try:
        action = NetworkAction(raw_action) if isinstance(raw_action, str) else None
    except ValueError as error:
        raise NetworkStatusSchemaError("legacy network domain action is invalid") from error
    if action is None or not _exact_bool(legacy_policy.get("sandbox_required")):
        raise NetworkStatusSchemaError("legacy network domain policy is invalid")
    return {"action": action.value, "sandbox_required": legacy_policy["sandbox_required"]}


def validate_network_status(
    payload: object,
    *,
    now_epoch_ms: int | None = None,
) -> dict[str, object]:
    """Validate the complete v1 daemon projection before presenting protection."""

    current_epoch_ms = int(time.time() * 1000) if now_epoch_ms is None else now_epoch_ms
    if current_epoch_ms < 0:
        raise ValueError("now_epoch_ms must be non-negative")
    validated_payload, host_platform, effective_grade = _validate_header(payload)
    active_backends, validated_backends = _validate_backends(validated_payload, host_platform=host_platform)
    protection_active, independently_observed, _ = _validate_summaries(
        validated_payload,
        effective_grade=effective_grade,
        active_backends=active_backends,
        validated_backends=validated_backends,
    )
    supervisor = _validate_supervisor(
        validated_payload.get("supervisor"),
        current_epoch_ms=current_epoch_ms,
        protection_active=protection_active,
        independently_observed=independently_observed,
        effective_grade=effective_grade,
        active_backends=active_backends,
    )
    projected: dict[str, object] = {
        field: validated_payload[field]
        for field in (
            "schema",
            "host_platform",
            "effective_grade",
            "independently_observed_grade",
            "protection_active",
            "independently_observed",
            "reason_code",
        )
    }
    projected["backends"] = _project_backends(validated_backends)
    if supervisor is not None:
        projected["supervisor"] = _project_supervisor(supervisor)
    legacy_policy = _project_legacy_policy(validated_payload.get("legacy_domain_policy"))
    if legacy_policy is not None:
        projected["legacy_domain_policy"] = legacy_policy
    return projected
