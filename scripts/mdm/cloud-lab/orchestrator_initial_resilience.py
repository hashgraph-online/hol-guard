from __future__ import annotations

from orchestrator_support import (
    ALPHA,
    BETA,
    Recorder,
    _ack_revisions,
    _create_job,
    _device_fault,
    _faults,
    _publish,
    _state,
    _sync,
)


def _record_ack_delivery_resilience(
    cloud: str,
    proxy: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
) -> None:
    _device_fault(devices["device-b"], {"holdOutbox": True})
    throttled_publish = _publish(
        cloud,
        admin,
        ALPHA,
        ["device-b"],
        "observe",
    )
    _sync(devices["device-b"])
    _device_fault(devices["device-b"], {"holdOutbox": False})
    _faults(
        proxy,
        admin,
        {
            "statusByDeviceAndPath": {
                "device-b|/runtime/v1/acknowledgements": 429,
            },
        },
    )
    throttled = _sync(devices["device-b"])
    _faults(proxy, admin, None)
    throttled_recovered = _sync(devices["device-b"])
    acknowledged = _ack_revisions(
        _state(cloud, admin, ALPHA),
        "device-b",
    )
    recorder.add(
        "429 throttling preserves FIFO acknowledgement delivery",
        throttled.get("outboxDepth", 0) > 0
        and throttled_recovered.get("outboxDepth") == 0
        and throttled_publish.get("revision") in acknowledged,
        {"throttled": throttled, "recovered": throttled_recovered},
    )
    partition_publish = _publish(
        cloud,
        admin,
        ALPHA,
        ["device-b"],
        "enforce",
    )
    previous_revision = throttled_recovered.get("revision")
    _faults(proxy, admin, {"partitionedDevices": ["device-b"]})
    partitioned = _sync(devices["device-b"])
    _faults(proxy, admin, None)
    partition_recovered = _sync(devices["device-b"])
    recorder.add(
        "network partition preserves last known good policy and later converges",
        partitioned.get("revision") == previous_revision
        and partitioned.get("error") == "fault_partitioned"
        and partition_recovered.get("revision") == partition_publish.get("revision"),
        {"partitioned": partitioned, "recovered": partition_recovered},
    )


def _record_corrupt_configuration_recovery(
    cloud: str,
    proxy: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
    canary_revision: int | None,
) -> dict[str, object]:
    corrupt_publish = _publish(
        cloud,
        admin,
        ALPHA,
        ["device-a"],
        "enforce",
    )
    _faults(proxy, admin, {"corruptNextConfigurationFor": ["device-a"]})
    corrupt = _sync(devices["device-a"])
    _faults(proxy, admin, None)
    recovered = _sync(devices["device-a"])
    recorder.add(
        "corrupt signed configuration fails closed and valid retry converges",
        type(canary_revision) is int
        and corrupt.get("revision") == canary_revision
        and corrupt.get("error") == "configuration_hash_mismatch"
        and recovered.get("revision") == corrupt_publish.get("revision"),
        {"failed": corrupt, "recovered": recovered},
    )
    for fault_name, expected_error in (
        ("truncateNextFor", "configuration_shape_invalid"),
        ("malformedJsonNextFor", "configuration_shape_invalid"),
    ):
        published = _publish(
            cloud,
            admin,
            ALPHA,
            ["device-a"],
            "prompt",
        )
        previous_revision = recovered.get("revision")
        _faults(proxy, admin, {fault_name: ["device-a"]})
        failed = _sync(devices["device-a"])
        _faults(proxy, admin, None)
        recovered = _sync(devices["device-a"])
        recorder.add(
            f"{fault_name} cannot replace the accepted policy",
            failed.get("revision") == previous_revision
            and failed.get("error") == expected_error
            and recovered.get("revision") == published.get("revision"),
            {"failed": failed, "recovered": recovered},
        )
    return recovered


def _record_etag_replay_and_rollback(
    cloud: str,
    proxy: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
    recovered: dict[str, object],
) -> None:
    etag_publish = _publish(
        cloud,
        admin,
        ALPHA,
        ["device-a"],
        "enforce",
    )
    previous_revision = recovered.get("revision")
    _faults(proxy, admin, {"stripEtagFor": ["device-a"]})
    missing_etag = _sync(devices["device-a"])
    _faults(proxy, admin, None)
    etag_recovered = _sync(devices["device-a"])
    recorder.add(
        "configuration without an ETag is rejected",
        missing_etag.get("revision") == previous_revision
        and missing_etag.get("error") == "configuration_etag_missing"
        and etag_recovered.get("revision") == etag_publish.get("revision"),
        {"failed": missing_etag, "recovered": etag_recovered},
    )
    stable = _publish(cloud, admin, ALPHA, ["device-a"], "observe")
    stable_sync = _sync(devices["device-a"])
    stale_target = _publish(cloud, admin, ALPHA, ["device-a"], "prompt")
    _faults(
        proxy,
        admin,
        {"replayPreviousConfigurationFor": ["device-a"]},
    )
    stale = _sync(devices["device-a"])
    _faults(proxy, admin, None)
    stale_recovered = _sync(devices["device-a"])
    recorder.add(
        "stale signed configuration replay cannot downgrade a device",
        stable_sync.get("revision") == stable.get("revision")
        and stale.get("revision") == stable.get("revision")
        and stale.get("error") == "configuration_revision_not_monotonic"
        and stale_recovered.get("revision") == stale_target.get("revision"),
        {"failed": stale, "recovered": stale_recovered},
    )
    rollback = _publish(
        cloud,
        admin,
        ALPHA,
        ["device-a"],
        "observe",
        rollback=True,
        rollback_reason="verified canary rollback",
    )
    rollback_sync = _sync(devices["device-a"])
    recorder.add(
        "authorized rollback remains a newer signed revision",
        rollback_sync.get("revision") == rollback.get("revision") and rollback_sync.get("error") is None,
        {"publish": rollback, "sync": rollback_sync},
    )


def _record_request_binding_and_crash_recovery(
    cloud: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
) -> None:
    _device_fault(devices["device-c"], {"replayNext": True})
    replay = _sync(devices["device-c"])
    recorder.add(
        "sender-constrained request proof replay is rejected",
        replay.get("error") == "request_replay",
        replay,
    )
    replay_recovered = _sync(devices["device-c"])
    recorder.add(
        "device recovers after replay rejection",
        replay_recovered.get("error") is None,
        replay_recovered,
    )
    _device_fault(devices["device-c"], {"workspaceOverride": BETA})
    wrong_workspace = _sync(devices["device-c"])
    _device_fault(devices["device-c"], {"workspaceOverride": None})
    recorder.add(
        "workspace substitution using a valid device key is rejected",
        wrong_workspace.get("error") == "device_binding_unknown",
        wrong_workspace,
    )
    _device_fault(devices["device-c"], {"clockOffsetSeconds": 7_200})
    clock_skew = _sync(devices["device-c"])
    _device_fault(devices["device-c"], {"clockOffsetSeconds": 0})
    recorder.add(
        "requests outside the clock window are rejected",
        clock_skew.get("error") == "request_time_invalid",
        clock_skew,
    )
    crash_publish = _publish(
        cloud,
        admin,
        ALPHA,
        ["device-c"],
        "prompt",
    )
    _device_fault(devices["device-c"], {"crashAfterWrite": True})
    crashed = _sync(devices["device-c"])
    recovered = _sync(devices["device-c"])
    recorder.add(
        "crash after atomic policy write recovers its pending checkpoint",
        crashed.get("error") == "fault_crash_after_write"
        and recovered.get("revision") == crash_publish.get("revision")
        and recovered.get("outboxDepth") == 0,
        {"crashed": crashed, "recovered": recovered},
    )


def _record_policy_tamper(
    devices: dict[str, str],
    recorder: Recorder,
) -> None:
    _device_fault(devices["device-a"], {"tamperPolicy": True})
    tampered = _sync(devices["device-a"])
    recorder.add(
        "file content and permission tampering is reported unhealthy",
        tampered.get("policyIntegrity") == "tampered"
        and tampered.get("policyIntegrityReason")
        in {
            "managed_policy_permissions_invalid",
            "managed_policy_hash_mismatch",
        },
        tampered,
    )


def _create_idempotent_repair(
    cloud: str,
    admin: str,
    recorder: Recorder,
) -> dict[str, object]:
    repair = _create_job(
        cloud,
        admin,
        workspace=ALPHA,
        device="device-a",
        action="repair",
        parameters={"scope": "machine"},
        idempotency_key="idem-repair-tampered",
        job_id="job-repair-tampered",
    )
    repair_retry = _create_job(
        cloud,
        admin,
        workspace=ALPHA,
        device="device-a",
        action="repair",
        parameters={"scope": "machine"},
        idempotency_key="idem-repair-tampered",
    )
    repair_conflict = _create_job(
        cloud,
        admin,
        workspace=ALPHA,
        device="device-a",
        action="repair",
        parameters={"scope": "users"},
        idempotency_key="idem-repair-tampered",
    )
    job_id_conflict = _create_job(
        cloud,
        admin,
        workspace=ALPHA,
        device="device-a",
        action="integrity-scan",
        parameters={},
        idempotency_key="idem-other-job",
        job_id="job-repair-tampered",
    )
    recorder.add(
        "remediation idempotency returns the stored job and rejects semantic conflicts",
        repair.get("httpStatus") == 201
        and repair_retry.get("httpStatus") == 200
        and repair_retry.get("jobId") == repair.get("jobId")
        and repair_conflict.get("httpStatus") == 409
        and repair_conflict.get("error") == "remediation_idempotency_conflict"
        and job_id_conflict.get("httpStatus") == 409
        and job_id_conflict.get("error") == "remediation_job_id_conflict",
        {
            "created": repair,
            "retry": repair_retry,
            "idempotencyConflict": repair_conflict,
            "jobIdConflict": job_id_conflict,
        },
    )
    return repair


def run_resilience_and_repair_setup(
    cloud: str,
    proxy: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
    canary_revision: int | None,
) -> dict[str, object]:
    _record_ack_delivery_resilience(
        cloud,
        proxy,
        devices,
        admin,
        recorder,
    )
    recovered = _record_corrupt_configuration_recovery(
        cloud,
        proxy,
        devices,
        admin,
        recorder,
        canary_revision,
    )
    _record_etag_replay_and_rollback(
        cloud,
        proxy,
        devices,
        admin,
        recorder,
        recovered,
    )
    _record_request_binding_and_crash_recovery(
        cloud,
        devices,
        admin,
        recorder,
    )
    _record_policy_tamper(devices, recorder)
    return _create_idempotent_repair(cloud, admin, recorder)
