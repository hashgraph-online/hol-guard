"""Machine-context health cadence independent of user and harness activity."""

from __future__ import annotations

import hashlib
import platform
import re
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import cast

from .contracts import MachinePaths, ManagedPolicyState, default_machine_paths
from .health_key_registration import build_machine_health_key_registration
from .health_lease import acknowledge_pending_health_lease, issue_or_load_pending_health_lease
from .health_lease_ack import HealthLeaseAck
from .health_lease_contract import HealthLeaseBinding, HealthLeaseOutbox
from .health_transport import MachineHealthTransport, build_machine_health_transport
from .policy import load_managed_policy

_WORKSPACE_LOCK = "selfProtection.workspaceId"
_DEVICE_LOCK = "selfProtection.deviceId"

PolicyLoader = Callable[..., ManagedPolicyState]
LeaseIssuer = Callable[..., HealthLeaseOutbox]
LeaseAcknowledger = Callable[..., HealthLeaseAck]

_SAFE_TRANSPORT_REASON_CODES = frozenset(
    {
        "health_key_registration_ack_invalid",
        "health_lease_challenge_invalid",
        "health_lease_delivery_auth_invalid",
        "health_lease_delivery_response_oversized",
    }
)
_SAFE_HTTP_REASON = re.compile(
    r"health_(?:key_registration|lease_challenge|lease_delivery)_http_[1-5][0-9]{2}"
)
_SAFE_STRUCTURED_HTTP_REASON = re.compile(r"(health_lease_delivery_http_[1-5][0-9]{2}):(.+)")


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
    lease_acknowledger: LeaseAcknowledger = acknowledge_pending_health_lease,
    transport: MachineHealthTransport | None = None,
) -> dict[str, object]:
    """Issue or recover the current signed lease from protected machine state."""

    resolved_system = system_name or platform.system()
    resolved_paths = paths or default_machine_paths(system_name=resolved_system)
    policy_state = policy_loader(system_name=resolved_system)
    binding = _machine_binding(policy_state)
    started = time.monotonic()
    outbox = lease_issuer(resolved_paths, binding, system_name=resolved_system)
    snapshot_duration_ms = max(0, round((time.monotonic() - started) * 1000))
    delivery_latency_ms: int | None = None
    rejection_reason: str | None = None
    queue_depth = 1
    challenge_responded = False
    state = "lease-ready"
    reason_codes = ["health_lease_ready"]
    resolved_transport = transport or build_machine_health_transport(resolved_paths.state_root)
    if resolved_transport is not None:
        delivery_started = time.monotonic()
        try:
            resolved_transport.register_key(
                build_machine_health_key_registration(
                    resolved_paths,
                    binding,
                    installation_generation=outbox.lease.claims.installation_generation,
                    machine_installation_id=outbox.lease.claims.machine_installation_id,
                    key_id=outbox.lease.claims.signing_key_id,
                    system_name=resolved_system,
                )
            )
            ack = resolved_transport.deliver_lease(outbox)
            lease_acknowledger(
                resolved_paths,
                binding,
                ack.canonical_bytes(),
                system_name=resolved_system,
            )
            queue_depth = 0
            challenge = resolved_transport.poll_challenge(
                binding=binding,
                installation_generation=outbox.lease.claims.installation_generation,
                machine_installation_id=outbox.lease.claims.machine_installation_id,
            )
            if challenge is not None:
                queue_depth = 1
                outbox = lease_issuer(
                    resolved_paths,
                    binding,
                    system_name=resolved_system,
                    challenge=challenge,
                )
                challenge_ack = resolved_transport.deliver_lease(outbox)
                lease_acknowledger(
                    resolved_paths,
                    binding,
                    challenge_ack.canonical_bytes(),
                    system_name=resolved_system,
                )
                queue_depth = 0
                challenge_responded = True
            state = "lease-delivered"
            reason_codes = ["health_lease_delivered"]
        except Exception as exc:
            rejection_reason = _bounded_reason(exc)
            state = "delivery-failed"
            reason_codes = ["health_lease_delivery_failed"]
        delivery_latency_ms = max(0, round((time.monotonic() - delivery_started) * 1000))
    claims = outbox.lease.claims
    lease_age_seconds = max(
        0,
        round(
            (
                datetime.now(timezone.utc)
                - datetime.strptime(claims.issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            ).total_seconds()
        ),
    )
    return {
        "schemaVersion": "hol-guard-mdm-status.v1",
        "operation": "health-report",
        "healthy": _local_integrity_healthy(outbox),
        "state": state,
        "reasonCodes": reason_codes,
        "localEnforcementHealthy": _local_integrity_healthy(outbox),
        "workspaceId": claims.workspace_id,
        "deviceId": claims.device_id,
        "machineInstallationId": claims.machine_installation_id,
        "installationGeneration": claims.installation_generation,
        "sequence": claims.sequence,
        "issuedAt": claims.issued_at,
        "leaseExpiresAt": claims.lease_expires_at,
        "leaseDigest": outbox.lease.digest,
        "challengeResponded": challenge_responded,
        "metrics": {
            "snapshotDurationMs": snapshot_duration_ms,
            "leaseAgeSeconds": lease_age_seconds,
            "deliveryLatencyMs": delivery_latency_ms,
            "rejectionReason": rejection_reason,
            "queueDepth": queue_depth,
            "keyStorageHealth": _key_storage_health(outbox),
        },
    }


def _bounded_reason(error: BaseException) -> str:
    reason = str(error).strip()
    if reason in _SAFE_TRANSPORT_REASON_CODES or _SAFE_HTTP_REASON.fullmatch(reason):
        return reason
    structured = _SAFE_STRUCTURED_HTTP_REASON.fullmatch(reason)
    if structured is not None:
        cloud_code_digest = hashlib.sha256(structured.group(2).encode("utf-8")).hexdigest()[:12]
        return f"{structured.group(1)}:cloud_error_{cloud_code_digest}"[:128]
    if isinstance(error, TimeoutError):
        return "health_transport_timeout"
    if isinstance(error, ConnectionError):
        return "health_transport_unavailable"
    return "health_transport_failure"


def _key_storage_health(outbox: HealthLeaseOutbox) -> str:
    import json

    try:
        snapshot = json.loads(outbox.snapshot_bytes)
        state = snapshot["components"]["deviceKey"]["state"]
    except (KeyError, TypeError, json.JSONDecodeError):
        return "unknown"
    return state if isinstance(state, str) and len(state) <= 32 else "unknown"


def _local_integrity_healthy(outbox: HealthLeaseOutbox) -> bool:
    import json

    try:
        snapshot = json.loads(outbox.snapshot_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return snapshot.get("healthy") is True if isinstance(snapshot, dict) else False


__all__ = ["run_machine_health_cadence"]
