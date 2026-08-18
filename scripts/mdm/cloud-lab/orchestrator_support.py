#!/usr/bin/env python3
"""Drive the multi-device MDM Cloud integration and emit bounded evidence."""

from __future__ import annotations

import http.client
from urllib.parse import urlsplit

from lab_common import ADMIN_HEADER, http_request

ALPHA = "workspace-mdm-alpha"
BETA = "workspace-mdm-beta"


def policy(mode: str) -> dict[str, object]:
    return {
        "schemaVersion": "hol-guard-mdm-policy.v1",
        "settings": {"mode": mode},
        "lockedSettings": ["mode"],
        "requiredHarnesses": [],
        "network": {"proxyMode": "system", "allowPublicRegistries": True},
        "update": {"owner": "mdm", "channel": "stable", "allowDowngrade": False},
        "daemonStartup": "login",
    }


def _bounded(value: object, depth: int = 0) -> object:
    if depth > 5:
        return "[bounded]"
    if isinstance(value, dict):
        output: dict[str, object] = {}
        for key, item in list(value.items())[:24]:
            if any(token in key.lower() for token in ("token", "private", "secret", "password")):
                output[key] = "[redacted]"
            else:
                output[key] = _bounded(item, depth + 1)
        return output
    if isinstance(value, list):
        return [_bounded(item, depth + 1) for item in value[:24]]
    if isinstance(value, str):
        return value[:512]
    if value is None or isinstance(value, bool | int | float):
        return value
    return str(value)[:256]


class Recorder:
    def __init__(self, existing: list[dict[str, object]] | None = None) -> None:
        self.steps = list(existing or [])

    def add(self, name: str, passed: bool, evidence: object) -> None:
        self.steps.append(
            {
                "name": name,
                "passed": bool(passed),
                "durationMs": 0,
                "evidence": _bounded(evidence),
            }
        )


def _raw_request(
    method: str,
    url: str,
    body: bytes,
    headers: dict[str, str],
) -> tuple[int, bytes]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("raw request URL must use HTTP or HTTPS and include a host")
    connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    default_port = 443 if parsed.scheme == "https" else 80
    connection = connection_type(
        parsed.hostname,
        parsed.port or default_port,
        timeout=10,
    )
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    try:
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read(2 * 1024 * 1024)
    finally:
        connection.close()


def _admin(
    cloud: str,
    admin: str,
    method: str,
    path: str,
    payload: object | None = None,
) -> tuple[int, dict[str, str], object | None]:
    return http_request(method, cloud + path, payload, {ADMIN_HEADER: admin})


def _faults(
    proxy: str,
    admin: str,
    payload: object | None = None,
) -> tuple[int, dict[str, str], object | None]:
    return http_request(
        "DELETE" if payload is None else "POST",
        proxy + "/__faults",
        payload,
        {ADMIN_HEADER: admin},
    )


def _device_fault(url: str, payload: dict[str, object]) -> object | None:
    return http_request("POST", url + "/fault", payload)[2]


def _sync(url: str) -> dict[str, object]:
    status, _, payload = http_request("GET", url + "/sync", timeout=30)
    if isinstance(payload, dict):
        return {"httpStatus": status, **payload}
    return {"httpStatus": status, "error": "invalid_device_response"}


def _state(cloud: str, admin: str, workspace: str | None = None) -> dict[str, object]:
    suffix = "" if workspace is None else f"?workspaceId={workspace}"
    status, _, payload = _admin(cloud, admin, "GET", "/admin/state" + suffix)
    if status != 200 or not isinstance(payload, dict):
        return {"error": "state_unavailable", "status": status}
    return payload


def _publish(
    cloud: str,
    admin: str,
    workspace: str,
    devices: list[str],
    mode: str,
    *,
    rollback: bool = False,
    rollback_reason: str | None = None,
) -> dict[str, object]:
    status, _, payload = _admin(
        cloud,
        admin,
        "POST",
        "/admin/policies",
        {
            "workspaceId": workspace,
            "deviceIds": devices,
            "policy": policy(mode),
            "rollback": rollback,
            "rollbackReason": rollback_reason,
        },
    )
    return {
        "httpStatus": status,
        **(payload if isinstance(payload, dict) else {"error": "invalid_publish_response"}),
    }


def _create_job(
    cloud: str,
    admin: str,
    *,
    workspace: str,
    device: str,
    action: str,
    parameters: dict[str, object],
    idempotency_key: str,
    job_id: str | None = None,
) -> dict[str, object]:
    request: dict[str, object] = {
        "workspaceId": workspace,
        "deviceId": device,
        "action": action,
        "parameters": parameters,
        "maxAttempts": 2,
        "idempotencyKey": idempotency_key,
    }
    if job_id is not None:
        request["jobId"] = job_id
    status, _, payload = _admin(cloud, admin, "POST", "/admin/remediations", request)
    return {
        "httpStatus": status,
        **(payload if isinstance(payload, dict) else {"error": "invalid_job_response"}),
    }


def _job_status(state: dict[str, object], job_id: object) -> str | None:
    jobs = state.get("jobs")
    if not isinstance(jobs, list):
        return None
    for job in jobs:
        if isinstance(job, dict) and job.get("job_id") == job_id:
            status = job.get("status")
            return status if isinstance(status, str) else None
    return None


def _ack_revisions(state: dict[str, object], device: str) -> set[int]:
    acknowledgements = state.get("acks")
    if not isinstance(acknowledgements, list):
        return set()
    return {
        int(item["revision"])
        for item in acknowledgements
        if isinstance(item, dict) and item.get("device") == device and isinstance(item.get("revision"), int)
    }
