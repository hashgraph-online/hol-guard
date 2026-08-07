"""Privacy-safe projection of local network mediation capabilities."""

from __future__ import annotations

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.network_capability_contract import (
    PlatformCapabilityProfile,
    default_platform_profiles,
)
from codex_plugin_scanner.guard.runtime.network_legacy_config import migrate_new_network_domain_action
from codex_plugin_scanner.guard.runtime.network_supervisor import NetworkSupervisorHealth


def build_network_status(
    profiles: tuple[PlatformCapabilityProfile, ...] | None = None,
    *,
    legacy_domain_action: GuardAction | None = None,
    supervisor_health: NetworkSupervisorHealth | None = None,
) -> dict[str, object]:
    resolved = profiles if profiles is not None else default_platform_profiles()
    migrated = migrate_new_network_domain_action(legacy_domain_action) if legacy_domain_action is not None else None
    status: dict[str, object] = {
        "schema": "guard.network-status.v1",
        "backends": [
            {
                "backend_id": profile.backend_id,
                "platform": profile.platform.value,
                "maximum_grade": profile.maximum_grade.value,
                "production_ready": profile.production_ready,
                "requires_privilege": profile.requires_privilege,
                "reason_code": profile.reason_code,
            }
            for profile in resolved
        ],
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
    }
