"""Privacy-safe projection of local network mediation capabilities."""

from __future__ import annotations

import math
import re
import sys
import time
from collections.abc import Mapping
from typing import TypeGuard, cast

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.network_capability_contract import (
    PlatformCapabilityProfile,
    PlatformFamily,
    default_platform_profiles,
    enforcement_grade_rank,
)
from codex_plugin_scanner.guard.runtime.network_legacy_config import (
    migrate_new_network_domain_action,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import EnforcementGrade, NetworkAction
from codex_plugin_scanner.guard.runtime.network_supervisor import NetworkSupervisorHealth
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


def validate_network_status(
    payload: object,
    *,
    now_epoch_ms: int | None = None,
) -> dict[str, object]:
    """Validate the complete v1 daemon projection before presenting protection."""

    current_epoch_ms = int(time.time() * 1000) if now_epoch_ms is None else now_epoch_ms
    if current_epoch_ms < 0:
        raise ValueError("now_epoch_ms must be non-negative")

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

    raw_backends = payload.get("backends")
    if not isinstance(raw_backends, list):
        raise NetworkStatusSchemaError("network status backends are invalid")
    active_backends: list[Mapping[str, object]] = []
    validated_backends: list[Mapping[str, object]] = []
    for raw_backend in raw_backends:
        if not _is_object(raw_backend):
            raise NetworkStatusSchemaError("network status backend is invalid")
        if not _is_safe_identifier(raw_backend.get("backend_id")):
            raise NetworkStatusSchemaError("network status backend id is invalid")
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
        if raw_backend["active"]:
            if not raw_backend["supported"] or not raw_backend["verified"]:
                raise NetworkStatusSchemaError("active network backend must be verified")
            if not raw_backend["production_ready"]:
                raise NetworkStatusSchemaError("active network backend must be production ready")
            if raw_backend["platform"] != host_platform:
                raise NetworkStatusSchemaError("active network backend must match the host")
            if backend_grade not in _ENFORCING_GRADES:
                raise NetworkStatusSchemaError("active network backend must enforce")
            active_backends.append(raw_backend)
        validated_backends.append(raw_backend)

    protection_active = bool(payload["protection_active"])
    effective_grade = EnforcementGrade(str(payload["effective_grade"]))
    if protection_active != bool(active_backends):
        raise NetworkStatusSchemaError("network protection summary is inconsistent")
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
    if any(bool(backend["observed"]) for backend in validated_backends) != independently_observed:
        raise NetworkStatusSchemaError("network backend observer summary is inconsistent")

    supervisor = payload.get("supervisor")
    if protection_active and supervisor is None:
        raise NetworkStatusSchemaError("active network protection requires supervisor proof")
    if supervisor is not None:
        if not _is_object(supervisor):
            raise NetworkStatusSchemaError("network supervisor is invalid")
        _require_enum(supervisor.get("phase"), RecoveryPhase)
        _require_enum(supervisor.get("effective_grade"), EnforcementGrade)
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
        if healthy_until is not None:
            if type(healthy_until) is not int:
                raise NetworkStatusSchemaError("network supervisor expiry is invalid")
            if cast(int, healthy_until) < 0:
                raise NetworkStatusSchemaError("network supervisor expiry is invalid")
        retry_attempt = supervisor.get("retry_attempt")
        next_retry = supervisor.get("next_retry_seconds")
        if type(retry_attempt) is not int:
            raise NetworkStatusSchemaError("network supervisor retry is invalid")
        if cast(int, retry_attempt) < 0:
            raise NetworkStatusSchemaError("network supervisor retry is invalid")
        if type(next_retry) not in {int, float}:
            raise NetworkStatusSchemaError("network supervisor delay is invalid")
        if not math.isfinite(cast(int | float, next_retry)) or cast(int | float, next_retry) < 0:
            raise NetworkStatusSchemaError("network supervisor delay is invalid")
        for field in ("permits_enforcement", "independently_observed"):
            if not _exact_bool(supervisor.get(field)):
                raise NetworkStatusSchemaError("network supervisor boolean is invalid")
        supervisor_grade = EnforcementGrade(str(supervisor["effective_grade"]))
        expected_permits = (
            supervisor.get("phase") == RecoveryPhase.HEALTHY.value and supervisor_grade in _ENFORCING_GRADES
        )
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

    projected: dict[str, object] = {
        "schema": payload["schema"],
        "host_platform": payload["host_platform"],
        "effective_grade": payload["effective_grade"],
        "independently_observed_grade": payload["independently_observed_grade"],
        "protection_active": payload["protection_active"],
        "independently_observed": payload["independently_observed"],
        "reason_code": payload["reason_code"],
        "backends": [
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
        ],
    }
    if supervisor is not None:
        projected["supervisor"] = {
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
    legacy_policy = payload.get("legacy_domain_policy")
    if legacy_policy is not None:
        if not _is_object(legacy_policy):
            raise NetworkStatusSchemaError("legacy network domain policy is invalid")
        raw_action = legacy_policy.get("action")
        try:
            action = NetworkAction(raw_action) if isinstance(raw_action, str) else None
        except ValueError as error:
            raise NetworkStatusSchemaError("legacy network domain action is invalid") from error
        if action is None or not _exact_bool(legacy_policy.get("sandbox_required")):
            raise NetworkStatusSchemaError("legacy network domain policy is invalid")
        projected["legacy_domain_policy"] = {
            "action": action.value,
            "sandbox_required": legacy_policy["sandbox_required"],
        }
    return projected


def _host_platform_family(platform_name: str | None = None) -> PlatformFamily | None:
    resolved = (platform_name or sys.platform).lower()
    if resolved.startswith("linux"):
        return PlatformFamily.LINUX
    if resolved == "darwin":
        return PlatformFamily.MACOS
    if resolved in {"win32", "cygwin", "msys"}:
        return PlatformFamily.WINDOWS
    return None


def _default_host_profiles(platform_name: str | None = None) -> tuple[PlatformCapabilityProfile, ...]:
    if platform_name is None:
        return default_platform_profiles()
    family = _host_platform_family(platform_name)
    if family is None:
        return ()
    return tuple(profile for profile in default_platform_profiles() if profile.platform is family)


def build_network_status(
    profiles: tuple[PlatformCapabilityProfile, ...] | None = None,
    *,
    legacy_domain_action: GuardAction | None = None,
    supervisor_health: NetworkSupervisorHealth | None = None,
    platform_name: str | None = None,
) -> dict[str, object]:
    """Return current-host truth without promoting static profiles to protection."""

    host_family = _host_platform_family(platform_name)
    resolved = profiles if profiles is not None else _default_host_profiles(platform_name)
    migrated = migrate_new_network_domain_action(legacy_domain_action) if legacy_domain_action is not None else None

    backends: list[dict[str, object]] = []
    active_grade = EnforcementGrade.UNAVAILABLE
    for profile in resolved:
        selected = (
            host_family is profile.platform
            and supervisor_health is not None
            and supervisor_health.backend_id == profile.backend_id
        )
        selected_health = supervisor_health if selected else None
        installed = selected_health is not None and selected_health.backend_digest is not None
        verified = (
            installed
            and selected_health is not None
            and selected_health.effective_grade is not EnforcementGrade.UNAVAILABLE
        )
        active = selected_health is not None and selected_health.permits_enforcement
        effective_grade = (
            selected_health.effective_grade if selected_health is not None else EnforcementGrade.UNAVAILABLE
        )
        if active:
            active_grade = effective_grade
        backends.append(
            {
                "backend_id": profile.backend_id,
                "platform": profile.platform.value,
                "supported": host_family is profile.platform or profiles is not None,
                "installed": installed,
                "verified": verified,
                "active": active,
                "observed": False,
                "advertised_maximum_grade": profile.maximum_grade.value,
                "effective_grade": effective_grade.value,
                "production_ready": False,
                "requires_privilege": profile.requires_privilege,
                "reason_code": (
                    "independent-observer-unavailable"
                    if active
                    else "no-live-provider-probe"
                    if not selected
                    else profile.reason_code
                ),
                "reference_reason_code": profile.reason_code,
            }
        )

    reason_code = "no-verified-installed-backend"
    if host_family is None:
        reason_code = "unsupported-host-platform"
    elif not resolved:
        reason_code = "no-platform-provider-profile"
    elif (
        supervisor_health is not None
        and supervisor_health.backend_id is not None
        and not any(bool(item["active"]) for item in backends)
    ):
        reason_code = "provider-probe-not-enforcing"

    status: dict[str, object] = {
        "schema": "guard.network-status.v1",
        "host_platform": host_family.value if host_family is not None else "unsupported",
        "effective_grade": active_grade.value,
        "independently_observed_grade": EnforcementGrade.UNAVAILABLE.value,
        "protection_active": any(bool(item["active"]) for item in backends),
        "independently_observed": False,
        "reason_code": reason_code,
        "backends": backends,
    }
    if migrated is not None:
        status["legacy_domain_policy"] = {
            "action": migrated.action.value,
            "sandbox_required": migrated.sandbox_required,
        }
    if supervisor_health is not None:
        status["supervisor"] = project_network_supervisor_health(supervisor_health)
    return status


def project_network_supervisor_health(health: NetworkSupervisorHealth) -> dict[str, object]:
    return {
        "phase": health.phase.value,
        "backend_id": health.backend_id,
        "backend_digest": health.backend_digest,
        "effective_grade": health.effective_grade.value,
        "healthy_until_epoch_ms": health.healthy_until_epoch_ms,
        "retry_attempt": health.retry_attempt,
        "next_retry_seconds": health.next_retry_seconds,
        "permits_enforcement": health.permits_enforcement,
        "independently_observed": False,
    }
