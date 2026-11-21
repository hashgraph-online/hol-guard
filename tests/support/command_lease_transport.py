"""Lease Guard Cloud command jobs over the command queue's request functions in unit tests.

The native ``cloud-event-sync`` command leases command jobs itself, so a test
that fakes ``command_queue._exact_json_request`` or ``command_queue._json_request``
would otherwise never see the lease. This double replays the native lease over
those functions: the same bodies, routes and answer.

The native lease is tested in
``rust/crates/guard-runtime/src/cloud_command_lease_tests.rs``; mark a test
``native_command_lease`` to run the real command.
"""

from __future__ import annotations

import socket
import urllib.error
from collections.abc import Callable, Mapping

EXACT_OPERATION = "guard.review.resolveExact"
EXACT_BASE = "/api/guard/review/v2/commands"
QUEUE_BASE = "/api/guard/commands"
_PROTOCOL_UPGRADE = {"protocol": "cloud_review_protocol_upgrade_required"}

Post = Callable[[dict[str, object]], Mapping[str, object]]


def lease_over(exact_request: Post, queue_request: Post) -> Callable[[Mapping[str, object]], dict[str, object]]:
    """A native-lease double that posts each lease body through the two route functions."""

    def lease(call: Mapping[str, object]) -> dict[str, object]:
        return _lease(call, exact_request, queue_request)

    return lease


def command_lease_over_command_queue(
    auth_context: Mapping[str, object], call: Mapping[str, object]
) -> dict[str, object]:
    """Lease the way the Python command queue did before the native command."""

    from codex_plugin_scanner.guard.runtime import command_queue

    def exact(body: dict[str, object]) -> Mapping[str, object]:
        return command_queue._exact_json_request(dict(auth_context), method="POST", path="/lease", payload=body)

    def queue(body: dict[str, object]) -> Mapping[str, object]:
        return command_queue._json_request(dict(auth_context), method="POST", path="/lease", payload=body)

    return _lease(call, exact, queue)


def _lease(call: Mapping[str, object], exact_request: Post, queue_request: Post) -> dict[str, object]:
    operations = [str(operation) for operation in _list(call.get("operations"))]
    generic = [operation for operation in operations if operation != EXACT_OPERATION]
    max_jobs = _int(call.get("maxJobs"), 1)
    wait_ms = _int(call.get("waitMs"), 0)
    lease: dict[str, object] = {
        "item": None,
        "exact": False,
        "extras": [],
        "exactRoute": None,
        "exactRefusal": None,
        "batchLimit": None,
        "responses": [],
    }
    responses: list[object] = []
    lease["responses"] = responses

    def answer(failure: dict[str, object] | None = None) -> dict[str, object]:
        return {"lease": lease, "failure": failure}

    if EXACT_OPERATION in operations:
        body = _body(call, [EXACT_OPERATION], wait_ms if not generic else 0, max_jobs)
        kind, reply = _post(exact_request, body)
        if kind == "refusal":
            status = reply.get("status")
            if max_jobs > 1 and status == 400:
                lease["batchLimit"] = 1
            if status == 401 or not generic:
                return answer({"refusal": reply, "route": EXACT_BASE})
            lease["exactRoute"] = "failed"
            lease["exactRefusal"] = reply
        elif kind == "transport":
            return answer({"transport": reply, "route": EXACT_BASE})
        else:
            if not _exact_protocol(reply):
                return answer(dict(_PROTOCOL_UPGRADE))
            lease["exactRoute"] = "ok"
            limit = reply.get("maxJobs")
            lease["batchLimit"] = limit if isinstance(limit, int) and not isinstance(limit, bool) and limit >= 1 else 1
            responses.append(reply)
            item = reply.get("item")
            if isinstance(item, Mapping) and item:
                if not _exact_protocol(item):
                    return answer(dict(_PROTOCOL_UPGRADE))
                if call.get("collectExtras") is True:
                    lease["extras"] = _extras(reply, item)
                lease["item"] = dict(item)
                lease["exact"] = True
                return answer()
    if not generic:
        return answer()
    kind, reply = _post(queue_request, _body(call, generic, wait_ms, 1))
    if kind != "response":
        return answer({kind: reply, "route": QUEUE_BASE})
    item = reply.get("item")
    lease["item"] = dict(item) if isinstance(item, Mapping) and item else None
    responses.append(reply)
    return answer()


def _body(call: Mapping[str, object], operations: list[str], wait_ms: int, max_jobs: int) -> dict[str, object]:
    exact_only = operations == [EXACT_OPERATION]
    capabilities: dict[str, object] = {"operations": list(operations)}
    known = call.get("schemaVersions")
    versions = known if isinstance(known, Mapping) else {}
    schema_versions = {
        operation: versions[operation]
        for operation in operations
        if operation != EXACT_OPERATION and operation in versions
    }
    if schema_versions:
        capabilities["schemaVersions"] = schema_versions
    body: dict[str, object] = {
        "workspaceId": call.get("workspaceId"),
        "deviceId": call.get("deviceId"),
        "daemonVersion": call.get("daemonVersion"),
        "capabilities": capabilities,
        "maxJobs": max_jobs if exact_only else 1,
        "waitMs": wait_ms,
    }
    if exact_only:
        body["protocolVersion"] = 2
    return body


def _post(request: Post, body: dict[str, object]) -> tuple[str, dict[str, object]]:
    try:
        return "response", dict(request(body))
    except urllib.error.HTTPError as error:
        headers = {name: value for name, value in (error.headers or {}).items()}
        raw = error.read() if error.fp is not None else b""
        return "refusal", {"status": error.code, "headers": headers, "body": raw.decode("utf-8", "replace")}
    except urllib.error.URLError as error:
        reason = error.reason
        return "transport", {
            "reason": str(reason),
            "timeout": isinstance(reason, (TimeoutError, socket.timeout)),
            "outage": isinstance(reason, ConnectionError),
        }


def _exact_protocol(value: Mapping[str, object]) -> bool:
    version = value.get("protocolVersion")
    return not isinstance(version, bool) and isinstance(version, (int, float)) and version == 2


def _extras(response: Mapping[str, object], first: Mapping[str, object]) -> list[object]:
    seen = {first.get("leaseId")}
    extras: list[object] = []
    for job in _list(response.get("items")):
        if not isinstance(job, Mapping):
            continue
        lease = job.get("leaseId")
        if not isinstance(lease, str) or not lease or lease in seen or not _exact_protocol(job):
            continue
        seen.add(lease)
        extras.append(dict(job))
    return extras


def _list(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def _int(value: object, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default
