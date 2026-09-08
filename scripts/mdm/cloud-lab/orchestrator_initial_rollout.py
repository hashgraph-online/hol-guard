from __future__ import annotations

import hashlib

from lab_common import ADMIN_HEADER, http_request
from orchestrator_support import (
    ALPHA,
    BETA,
    Recorder,
    _ack_revisions,
    _device_fault,
    _faults,
    _publish,
    _raw_request,
    _state,
    _sync,
)

from codex_plugin_scanner.guard.mdm.cloud_control import ENROLL_SCHEMA


def _record_endpoint_enrollment(
    devices: dict[str, str],
    recorder: Recorder,
) -> None:
    expected = {"device-a", "device-b", "device-c", "device-d"}
    recorder.add(
        "four device endpoints are present",
        set(devices) == expected,
        sorted(devices),
    )
    for name in sorted(devices):
        response = _sync(devices[name])
        recorder.add(
            f"{name} enrolls independently",
            response.get("httpStatus") == 200 and response.get("error") is None,
            response,
        )


def _collect_identities(
    devices: dict[str, str],
    recorder: Recorder,
) -> dict[str, dict[str, object]]:
    identities: dict[str, dict[str, object]] = {}
    for name, url in devices.items():
        status, _, payload = http_request("GET", url + "/identity")
        identity = payload if isinstance(payload, dict) else {}
        identities[name] = identity
        recorder.add(
            f"{name} exposes only its public enrollment identity",
            status == 200 and identity.get("deviceId") == name and isinstance(identity.get("publicKeyPem"), str),
            {"status": status, "keyId": identity.get("keyId")},
        )
    valid_key_ids = [
        key_id for identity in identities.values() if isinstance((key_id := identity.get("keyId")), str) and key_id
    ]
    recorder.add(
        "all managed devices have distinct machine keys",
        len(valid_key_ids) == len(devices) and len(set(valid_key_ids)) == len(devices),
        sorted(valid_key_ids),
    )
    return identities


def _record_enrollment_abuse_rejection(
    proxy: str,
    identities: dict[str, dict[str, object]],
    recorder: Recorder,
) -> None:
    # These deterministic values are public fixtures shared with the isolated lab stack, not deployed secrets.
    replay_identity = identities["device-a"]
    replay_status, _, replay_body = http_request(
        "POST",
        proxy + "/runtime/v1/enroll",
        {
            "schemaVersion": ENROLL_SCHEMA,
            "workspaceId": ALPHA,
            "deviceId": "device-a",
            "installationGeneration": "a" * 32,
            "keyId": replay_identity.get("keyId"),
            "publicKeyPem": replay_identity.get("publicKeyPem"),
            "token": "enrollment-token-device-a",  # NOSONAR - public deterministic lab fixture
        },
    )
    recorder.add(
        "one-time enrollment token replay is rejected",
        replay_status == 401 and isinstance(replay_body, dict) and replay_body.get("error") == "enrollment_denied",
        {"status": replay_status, "body": replay_body},
    )
    clone_status, _, clone_body = http_request(
        "POST",
        proxy + "/runtime/v1/enroll",
        {
            "schemaVersion": ENROLL_SCHEMA,
            "workspaceId": ALPHA,
            "deviceId": "device-clone-probe",
            "installationGeneration": "e" * 32,
            "keyId": replay_identity.get("keyId"),
            "publicKeyPem": replay_identity.get("publicKeyPem"),
            "token": "enrollment-token-clone-probe",  # NOSONAR - public deterministic lab fixture
        },
    )
    recorder.add(
        "cloned machine public keys are rejected",
        clone_status == 409
        and isinstance(clone_body, dict)
        and clone_body.get("error") == "enrollment_key_or_identity_reused",
        {"status": clone_status, "body": clone_body},
    )


def _record_admin_request_guards(
    cloud: str,
    admin: str,
    recorder: Recorder,
) -> None:
    denied_status, _, denied = http_request("GET", cloud + "/admin/state")
    recorder.add(
        "Cloud administrative state requires explicit authorization",
        denied_status == 401 and isinstance(denied, dict) and denied.get("error") == "admin_denied",
        {"status": denied_status, "body": denied},
    )
    duplicate_body = b'{"workspaceId":"one","workspaceId":"two"}'
    duplicate_status, duplicate_response = _raw_request(
        "POST",
        cloud + "/admin/policies",
        duplicate_body,
        {
            ADMIN_HEADER: admin,
            "content-type": "application/json",
            "content-length": str(len(duplicate_body)),
        },
    )
    recorder.add(
        "duplicate JSON keys are rejected before policy authority",
        duplicate_status == 400 and b"duplicate_json_key" in duplicate_response,
        {
            "status": duplicate_status,
            "bodyHash": hashlib.sha256(duplicate_response).hexdigest(),
        },
    )
    oversized_body = b"{}"
    oversized_status, _ = _raw_request(
        "POST",
        cloud + "/admin/policies",
        oversized_body,
        {
            ADMIN_HEADER: admin,
            "content-type": "application/json",
            "content-length": str(1024 * 1024 + 64),
        },
    )
    recorder.add(
        "oversized Cloud requests are rejected",
        oversized_status == 413,
        {"status": oversized_status},
    )


def _record_baseline_and_tenant_isolation(
    cloud: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
) -> None:
    alpha_baseline = _publish(
        cloud,
        admin,
        ALPHA,
        ["device-a", "device-b", "device-c"],
        "observe",
    )
    beta_baseline = _publish(cloud, admin, BETA, ["device-d"], "enforce")
    recorder.add(
        "independent workspace baseline policies are published",
        alpha_baseline.get("httpStatus") == 201
        and beta_baseline.get("httpStatus") == 201
        and alpha_baseline.get("revision") == 1
        and beta_baseline.get("revision") == 1,
        {"alpha": alpha_baseline, "beta": beta_baseline},
    )
    for name in sorted(devices):
        response = _sync(devices[name])
        recorder.add(
            f"{name} applies its workspace baseline",
            response.get("httpStatus") == 200 and response.get("revision") == 1 and response.get("error") is None,
            response,
        )
    alpha_state = _state(cloud, admin, ALPHA)
    beta_state = _state(cloud, admin, BETA)
    alpha_devices = {item.get("device") for item in alpha_state.get("devices", []) if isinstance(item, dict)}
    beta_devices = {item.get("device") for item in beta_state.get("devices", []) if isinstance(item, dict)}
    recorder.add(
        "workspace-scoped Cloud projection isolates tenants",
        alpha_devices == {"device-a", "device-b", "device-c"} and beta_devices == {"device-d"},
        {
            "alphaDevices": sorted(item for item in alpha_devices if isinstance(item, str)),
            "betaDevices": sorted(item for item in beta_devices if isinstance(item, str)),
        },
    )
    wrong_tenant_publish = _publish(
        cloud,
        admin,
        ALPHA,
        ["device-d"],
        "prompt",
    )
    recorder.add(
        "cross-workspace policy targeting is rejected",
        wrong_tenant_publish.get("httpStatus") == 404 and wrong_tenant_publish.get("error") == "publish_device_unknown",
        wrong_tenant_publish,
    )


def _record_revision_and_canary_behavior(
    cloud: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
) -> int | None:
    same_content = _publish(cloud, admin, ALPHA, ["device-a"], "observe")
    same_content_sync = _sync(devices["device-a"])
    recorder.add(
        "newer same-content revisions are not hidden by ETag reuse",
        same_content.get("revision") == 2
        and same_content_sync.get("revision") == 2
        and same_content_sync.get("applied") is True,
        {"publish": same_content, "sync": same_content_sync},
    )
    canary = _publish(cloud, admin, ALPHA, ["device-a"], "prompt")
    canary_sync = _sync(devices["device-a"])
    non_canary = _sync(devices["device-b"])
    recorder.add(
        "canary policy advances only the selected device",
        canary.get("revision") == 3 and canary_sync.get("revision") == 3 and non_canary.get("revision") == 1,
        {"canary": canary_sync, "nonCanary": non_canary},
    )
    revision = canary_sync.get("revision")
    return revision if isinstance(revision, int) else None


def _record_historical_acknowledgement(
    cloud: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
) -> None:
    _device_fault(devices["device-b"], {"holdOutbox": True})
    historical = _publish(cloud, admin, ALPHA, ["device-b"], "prompt")
    historical_sync = _sync(devices["device-b"])
    superseding = _publish(cloud, admin, ALPHA, ["device-b"], "enforce")
    _device_fault(devices["device-b"], {"holdOutbox": False})
    catch_up = _sync(devices["device-b"])
    history_revisions = _ack_revisions(
        _state(cloud, admin, ALPHA),
        "device-b",
    )
    recorder.add(
        "historical acknowledgements survive a superseding assignment",
        historical_sync.get("outboxDepth", 0) > 0
        and historical.get("revision") in history_revisions
        and superseding.get("revision") in history_revisions
        and catch_up.get("revision") == superseding.get("revision"),
        {
            "historicalRevision": historical.get("revision"),
            "supersedingRevision": superseding.get("revision"),
            "ackRevisions": sorted(history_revisions),
            "device": catch_up,
        },
    )


def _record_lost_response_idempotency(
    cloud: str,
    proxy: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
) -> None:
    _device_fault(devices["device-b"], {"holdOutbox": True})
    dropped_publish = _publish(cloud, admin, ALPHA, ["device-b"], "prompt")
    _sync(devices["device-b"])
    _device_fault(devices["device-b"], {"holdOutbox": False})
    _faults(proxy, admin, {"dropResponseAfterForwardFor": ["device-b"]})
    dropped_retry = _sync(devices["device-b"])
    _faults(proxy, admin, None)
    dropped_state = _state(cloud, admin, ALPHA)
    dropped_revisions = _ack_revisions(dropped_state, "device-b")
    matching_acks = [
        item
        for item in dropped_state.get("acks", [])
        if isinstance(item, dict)
        and item.get("device") == "device-b"
        and item.get("revision") == dropped_publish.get("revision")
    ]
    recorder.add(
        "lost success responses retry idempotently without duplicate evidence",
        dropped_publish.get("revision") in dropped_revisions
        and dropped_retry.get("outboxDepth") == 0
        and len(matching_acks) == 1,
        {"revision": dropped_publish.get("revision"), "device": dropped_retry},
    )


def run_enrollment_and_rollout(
    cloud: str,
    proxy: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
) -> int | None:
    _record_endpoint_enrollment(devices, recorder)
    identities = _collect_identities(devices, recorder)
    _record_enrollment_abuse_rejection(proxy, identities, recorder)
    _record_admin_request_guards(cloud, admin, recorder)
    _record_baseline_and_tenant_isolation(cloud, devices, admin, recorder)
    canary_revision = _record_revision_and_canary_behavior(
        cloud,
        devices,
        admin,
        recorder,
    )
    _record_historical_acknowledgement(cloud, devices, admin, recorder)
    _record_lost_response_idempotency(
        cloud,
        proxy,
        devices,
        admin,
        recorder,
    )
    return canary_revision
