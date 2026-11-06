"""Privacy-safe projection of local network mediation capabilities."""

from __future__ import annotations

import sys

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.network_capability_contract import (
    PlatformCapabilityProfile,
    default_platform_profiles,
)
from codex_plugin_scanner.guard.runtime.network_legacy_config import (
    migrate_new_network_domain_action,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import EnforcementGrade
from codex_plugin_scanner.guard.runtime.network_status_validation import (
    NetworkStatusSchemaError,
    NetworkStatusValidatorUnavailableError,
    validate_network_status,
)
from codex_plugin_scanner.guard.runtime.network_supervisor import NetworkSupervisorHealth

__all__ = [
    "NetworkStatusSchemaError",
    "NetworkStatusValidatorUnavailableError",
    "build_network_status",
    "project_network_supervisor_health",
    "validate_network_status",
]


def build_network_status(
    profiles: tuple[PlatformCapabilityProfile, ...] | None = None,
    *,
    legacy_domain_action: GuardAction | None = None,
    supervisor_health: NetworkSupervisorHealth | None = None,
    platform_name: str | None = None,
) -> dict[str, object]:
    """Return current-host truth without promoting static profiles to protection.

    The native runtime (`network_status_build`) decides which backend is
    verified and active. Without it nothing is reported as protected.
    """
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    migrated = migrate_new_network_domain_action(legacy_domain_action) if legacy_domain_action is not None else None
    legacy_policy = (
        {"action": migrated.action.value, "sandbox_required": migrated.sandbox_required}
        if migrated is not None
        else None
    )
    request = {
        "platform": platform_name or sys.platform,
        "profiles": [
            {
                "backend_id": profile.backend_id,
                "platform": profile.platform.value,
                "maximum_grade": profile.maximum_grade.value,
                "production_ready": profile.production_ready,
                "requires_privilege": profile.requires_privilege,
                "reason_code": profile.reason_code,
            }
            for profile in (profiles if profiles is not None else default_platform_profiles())
        ],
        "explicit": profiles is not None,
        "host_only": profiles is None and platform_name is not None,
        "supervisor": project_network_supervisor_health(supervisor_health) if supervisor_health is not None else None,
        "legacy_domain_policy": legacy_policy,
    }
    try:
        return native_runner_authority("network_status_build", request)
    except NativeRunnerAuthorityError:
        unavailable = EnforcementGrade.UNAVAILABLE.value
        status: dict[str, object] = {
            "schema": "guard.network-status.v1",
            "host_platform": "unsupported",
            "effective_grade": unavailable,
            "independently_observed_grade": unavailable,
            "protection_active": False,
            "independently_observed": False,
            "reason_code": "native-runtime-unavailable",
            "backends": [],
        }
        if legacy_policy is not None:
            status["legacy_domain_policy"] = legacy_policy
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
