from __future__ import annotations

import json
from collections.abc import Mapping

from orchestrator_support import (
    ALPHA,
    Recorder,
    _create_job,
    _device_fault,
    _job_status,
    _publish,
    _state,
    _sync,
)


def _record_remediation_authority_guards(
    cloud: str,
    admin: str,
    recorder: Recorder,
) -> None:
    arbitrary = _create_job(
        cloud,
        admin,
        workspace=ALPHA,
        device="device-a",
        action="shell",
        parameters={"command": "curl attacker"},
        idempotency_key="idem-arbitrary-shell",
    )
    cross_tenant_job = _create_job(
        cloud,
        admin,
        workspace=ALPHA,
        device="device-d",
        action="repair",
        parameters={"scope": "machine"},
        idempotency_key="idem-cross-tenant",
    )
    recorder.add(
        "arbitrary commands and cross-tenant remediation are rejected",
        arbitrary.get("httpStatus") == 400
        and arbitrary.get("error") == "remediation_action_invalid"
        and cross_tenant_job.get("httpStatus") == 404,
        {"arbitrary": arbitrary, "crossTenant": cross_tenant_job},
    )


def _record_repair_evidence_gate(
    cloud: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
    repair: Mapping[str, object],
) -> None:
    executed = _sync(devices["device-a"])
    awaiting = _job_status(
        _state(cloud, admin, ALPHA),
        repair.get("jobId"),
    )
    verified = _sync(devices["device-a"])
    verified_status = _job_status(
        _state(cloud, admin, ALPHA),
        repair.get("jobId"),
    )
    recorder.add(
        "remediation is not complete until fresh healthy evidence arrives",
        executed.get("policyIntegrity") == "healthy"
        and awaiting == "awaiting_evidence"
        and verified.get("policyIntegrity") == "healthy"
        and verified_status == "succeeded",
        {
            "executed": executed,
            "awaiting": awaiting,
            "verifiedStatus": verified_status,
        },
    )


def _record_policy_repair_case(
    cloud: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
    *,
    fault: str,
    integrity: str,
    reason: str,
    idempotency_key: str,
    assertion_name: str,
    evidence_key: str,
) -> None:
    _device_fault(devices["device-a"], {fault: True})
    unhealthy = _sync(devices["device-a"])
    repair = _create_job(
        cloud,
        admin,
        workspace=ALPHA,
        device="device-a",
        action="repair",
        parameters={"scope": "machine"},
        idempotency_key=idempotency_key,
    )
    _sync(devices["device-a"])
    _sync(devices["device-a"])
    final_status = _job_status(
        _state(cloud, admin, ALPHA),
        repair.get("jobId"),
    )
    recorder.add(
        assertion_name,
        unhealthy.get("policyIntegrity") == integrity
        and unhealthy.get("policyIntegrityReason") == reason
        and final_status == "succeeded",
        {evidence_key: unhealthy, "job": repair},
    )


def _record_typed_actions(
    cloud: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
) -> None:
    typed_actions: tuple[tuple[str, dict[str, object]], ...] = (
        ("integrity-scan", {}),
        ("policy-refresh", {}),
        ("service-register", {"service": "machine-health"}),
        ("service-register", {"service": "supervisor"}),
        ("version-converge", {"targetVersion": "3.0.0-test"}),
        ("install", {"targetVersion": "3.0.1-test"}),
    )
    typed_results: dict[str, object] = {}
    for index, (action, parameters) in enumerate(typed_actions, start=1):
        key = f"idem-typed-{index}"
        job = _create_job(
            cloud,
            admin,
            workspace=ALPHA,
            device="device-a",
            action=action,
            parameters=parameters,
            idempotency_key=key,
        )
        _sync(devices["device-a"])
        _sync(devices["device-a"])
        typed_results[key] = {
            "action": action,
            "status": _job_status(
                _state(cloud, admin, ALPHA),
                job.get("jobId"),
            ),
        }
    recorder.add(
        "every fixed remediation action executes and is evidence-verified",
        all(isinstance(value, dict) and value.get("status") == "succeeded" for value in typed_results.values()),
        typed_results,
    )


def _record_audit_and_identity_integrity(
    cloud: str,
    admin: str,
    recorder: Recorder,
) -> None:
    final_state = _state(cloud, admin)
    serialized_state = json.dumps(final_state, sort_keys=True).lower()
    forbidden_material = (
        "enrollment-token-device-a",
        "curl attacker",
        "begin private key",
        "privatekeypem",
    )
    audit = final_state.get("audit", [])
    acknowledgements = final_state.get("acks", [])
    health = final_state.get("health", [])
    recorder.add(
        "audit evidence is hash-chained and redacts authority material",
        final_state.get("auditChainValid") is True
        and not any(material in serialized_state for material in forbidden_material),
        {
            "auditCount": len(audit) if isinstance(audit, list) else None,
            "auditChainValid": final_state.get("auditChainValid"),
        },
    )
    health_identities = {
        (item.get("workspace"), item.get("device"), item.get("sequence")) for item in health if isinstance(item, dict)
    }
    acknowledgement_ids = {item.get("request_id") for item in acknowledgements if isinstance(item, dict)}
    recorder.add(
        "all health sequences and acknowledgement identities are unique",
        isinstance(health, list)
        and len(health_identities) == len(health)
        and isinstance(acknowledgements, list)
        and len(acknowledgement_ids) == len(acknowledgements),
        {
            "healthCount": len(health) if isinstance(health, list) else None,
            "ackCount": (len(acknowledgements) if isinstance(acknowledgements, list) else None),
        },
    )


def _queue_restart_checkpoint(
    cloud: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
) -> None:
    _device_fault(devices["device-c"], {"holdOutbox": True})
    queued_publish = _publish(
        cloud,
        admin,
        ALPHA,
        ["device-c"],
        "observe",
    )
    queued = _sync(devices["device-c"])
    recorder.add(
        "restart checkpoint leaves durable endpoint evidence queued",
        queued.get("outboxDepth", 0) > 0 and queued.get("revision") == queued_publish.get("revision"),
        queued,
    )


def run_remediation_and_evidence(
    cloud: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
    repair: dict[str, object],
) -> None:
    _record_remediation_authority_guards(cloud, admin, recorder)
    _record_repair_evidence_gate(
        cloud,
        devices,
        admin,
        recorder,
        repair,
    )
    _record_policy_repair_case(
        cloud,
        devices,
        admin,
        recorder,
        fault="symlinkPolicy",
        integrity="tampered",
        reason="managed_policy_symlink",
        idempotency_key="idem-repair-symlink",
        assertion_name="managed policy symlink substitution is tampered and repairable",
        evidence_key="symlinked",
    )
    _record_policy_repair_case(
        cloud,
        devices,
        admin,
        recorder,
        fault="removePolicy",
        integrity="missing",
        reason="managed_policy_missing",
        idempotency_key="idem-repair-missing",
        assertion_name="missing managed policy remains unhealthy until repaired and re-attested",
        evidence_key="missing",
    )
    _record_typed_actions(cloud, devices, admin, recorder)
    _record_audit_and_identity_integrity(cloud, admin, recorder)
    _queue_restart_checkpoint(cloud, devices, admin, recorder)
