"""Privacy-safe projection of local network mediation capabilities."""

from __future__ import annotations

import sys

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.network_capability_contract import (
    PlatformCapabilityProfile,
    PlatformFamily,
    default_platform_profiles,
)
from codex_plugin_scanner.guard.runtime.network_legacy_config import (
    migrate_new_network_domain_action,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import EnforcementGrade
from codex_plugin_scanner.guard.runtime.network_status_validation import (
    NetworkStatusSchemaError,
    validate_network_status,
)
from codex_plugin_scanner.guard.runtime.network_supervisor import NetworkSupervisorHealth

__all__ = [
    "NetworkStatusSchemaError",
    "build_network_status",
    "project_network_supervisor_health",
    "validate_network_status",
]


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
            selected_health.effective_grade if selected_health is not None and active else EnforcementGrade.UNAVAILABLE
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
