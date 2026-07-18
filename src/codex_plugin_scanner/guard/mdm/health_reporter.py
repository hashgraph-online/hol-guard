"""Machine-context health cadence independent of user and harness activity."""

from __future__ import annotations

import platform
from collections.abc import Callable, Mapping
from typing import cast

from .contracts import MachinePaths, ManagedPolicyState, default_machine_paths
from .health_lease import issue_or_load_pending_health_lease
from .health_lease_contract import HealthLeaseBinding, HealthLeaseOutbox
from .policy import load_managed_policy

_WORKSPACE_LOCK = "selfProtection.workspaceId"
_DEVICE_LOCK = "selfProtection.deviceId"

PolicyLoader = Callable[..., ManagedPolicyState]
LeaseIssuer = Callable[..., HealthLeaseOutbox]


def _machine_binding(policy_state: ManagedPolicyState) -> HealthLeaseBinding:
    policy = policy_state.policy
    if policy is None:
        raise OSError(policy_state.reason_code or "health_reporter_managed_policy_absent")
    if policy.install_owner != "mdm":
        raise PermissionError("health_reporter_machine_management_required")
    required_locks = {_WORKSPACE_LOCK, _DEVICE_LOCK}
    if not required_locks.issubset(policy.locked_settings):
        raise PermissionError("health_reporter_binding_unlocked")
    protection_raw = policy.settings.get("selfProtection")
    if not isinstance(protection_raw, dict):
        raise ValueError("health_reporter_binding_invalid")
    protection = cast(Mapping[str, object], protection_raw)
    workspace_id = protection.get("workspaceId")
    device_id = protection.get("deviceId")
    if not isinstance(workspace_id, str) or not isinstance(device_id, str):
        raise ValueError("health_reporter_binding_invalid")
    try:
        return HealthLeaseBinding(workspace_id, device_id)
    except ValueError as exc:
        raise ValueError("health_reporter_binding_invalid") from exc


def run_machine_health_cadence(
    *,
    paths: MachinePaths | None = None,
    system_name: str | None = None,
    policy_loader: PolicyLoader = load_managed_policy,
    lease_issuer: LeaseIssuer = issue_or_load_pending_health_lease,
) -> dict[str, object]:
    """Issue or recover the current signed lease from protected machine state."""

    resolved_system = system_name or platform.system()
    resolved_paths = paths or default_machine_paths(system_name=resolved_system)
    policy_state = policy_loader(system_name=resolved_system)
    binding = _machine_binding(policy_state)
    outbox = lease_issuer(resolved_paths, binding, system_name=resolved_system)
    claims = outbox.lease.claims
    return {
        "schemaVersion": "hol-guard-mdm-status.v1",
        "operation": "health-report",
        "healthy": True,
        "state": "lease-ready",
        "reasonCodes": ["health_lease_ready"],
        "workspaceId": claims.workspace_id,
        "deviceId": claims.device_id,
        "machineInstallationId": claims.machine_installation_id,
        "installationGeneration": claims.installation_generation,
        "sequence": claims.sequence,
        "issuedAt": claims.issued_at,
        "leaseExpiresAt": claims.lease_expires_at,
        "leaseDigest": outbox.lease.digest,
    }


__all__ = ["run_machine_health_cadence"]
