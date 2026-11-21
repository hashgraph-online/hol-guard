"""Mechanical bridge to the native Bash owner; no Python execution fallback."""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import cast

from .codex_hook_launch_runtime import run_isolated_hook_process
from .native_context import _canonical_request_sha256
from .native_execution import _resident_request
from .native_runtime import NativeRuntimeStatus, _isolated_environment, native_runtime_status

FEATURE = "native-bash-owner-protocol-v1"
ARTIFACT_ID = "native-bash-owner:native-pretool:v3"
LEGACY_ARTIFACT_IDS = (
    "native-bash-launch:v1",
    "native-bash-owner:native-pretool:v1",
    "native-bash-owner:native-pretool:v2",
)
ARTIFACT_TYPE = "native_bash_request"
DESCRIPTOR_SCHEMA = "guard-native-bash-review.v4"
DESCRIPTOR_FEATURE = "native-bash-review-descriptor-v1"
HOST_LIVENESS_FEATURE = "native-bash-host-liveness-v1"
MAX_REQUEST_BYTES = 512 * 1024
_BASE = {"schema", "request_id", "request_sha256", "status", "code", "payload"}


class NativeBashError(RuntimeError):
    """A bounded diagnostic, without request contents or integrity material."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def request_id() -> str:
    return "native-bash-" + uuid.uuid4().hex


def runtime_status() -> NativeRuntimeStatus:
    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or not {
            FEATURE,
            DESCRIPTOR_FEATURE,
            HOST_LIVENESS_FEATURE,
            "native-bash-invocation-lifetime-v1",
            "native-bash-review-lineage-v1",
            "native-bash-reply-validation-v1",
            "resident-protocol-v2",
        }.issubset(status.capabilities.features)
    ):
        raise NativeBashError("native_bash_owner_unavailable")
    return status


def encode(value: dict[str, object]) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        if len(encoded.encode()) > MAX_REQUEST_BYTES:
            raise ValueError
        return encoded
    except (ValueError, TypeError, RecursionError) as error:
        raise NativeBashError("native_bash_request_invalid") from error


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise NativeBashError("native_bash_response_invalid")
        result[key] = value
    return result


def decode(raw: str) -> dict[str, object]:
    try:
        result = json.loads(raw, object_pairs_hook=_unique, parse_constant=_invalid_constant)
    except (ValueError, RecursionError) as error:
        raise NativeBashError("native_bash_response_invalid") from error
    if not isinstance(result, dict):
        raise NativeBashError("native_bash_response_invalid")
    return result


def _invalid_constant(_value: str) -> None:
    raise NativeBashError("native_bash_response_invalid")


def validate_reply(
    result: dict[str, object],
    request: dict[str, object],
    *,
    kind: str,
    extra: frozenset[str] = frozenset(),
    statuses: frozenset[str] = frozenset({"ok", "error", "unavailable"}),
) -> None:
    if (
        set(result) != _BASE | extra
        or result.get("schema") != f"guard-native-bash-{kind}-result.v1"
        or result.get("request_id") != request.get("request_id")
        or result.get("request_sha256") != "sha256:" + _canonical_request_sha256(request)
        or not isinstance(result.get("status"), str)
        or result["status"] not in statuses
        or not isinstance(result.get("code"), str)
        or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", str(result["code"])) is None
        or (result["status"] == "ok") != (result["code"] == "ok")
    ):
        raise NativeBashError("native_bash_response_binding_invalid")


def observe_host(capture: dict[str, object], *, cwd: Path) -> dict[str, object]:
    """Observe the sink's environment, not a daemon or an earlier hook's."""
    status = runtime_status()
    assert status.identity is not None
    request: dict[str, object] = {
        "schema": "guard-native-bash-host-request.v1",
        "request_id": request_id(),
        "capture": capture,
        "budget_ms": 5000,
    }
    reply = run_isolated_hook_process(
        [str(status.identity.path), "native-bash-host-context", "--stdin"],
        input_text=encode(request),
        cwd=cwd,
        environment=dict(os.environ),
        timeout_seconds=6,
        output_limit=MAX_REQUEST_BYTES,
    )
    if reply.returncode != 0 or reply.timed_out or reply.output_limit_exceeded or reply.containment_failed:
        raise NativeBashError("native_bash_host_observation_unavailable")
    result = decode(reply.stdout)
    validate_reply(result, request, kind="host")
    payload = result["payload"]
    if result["status"] != "ok":
        raise NativeBashError(str(result["code"]))
    if not isinstance(payload, dict) or set(payload) != set(capture):
        raise NativeBashError("native_bash_host_response_invalid")
    # Intent is retained; only native-observed host fields may change.
    intent = ("harness", "command", "workspace", "guard_home", "budget_ms")
    if any(payload.get(key) != capture.get(key) for key in intent):
        raise NativeBashError("native_bash_host_response_invalid")
    return payload


def prepare(request: dict[str, object], *, guard_home: Path) -> dict[str, object]:
    status = runtime_status()
    _ = encode(request)
    result = _resident_request(
        operation="native_bash_prepare",
        request=request,
        guard_home=guard_home,
        timeout_seconds=6,
        required_feature=FEATURE,
        response_schema="guard-native-bash-prepare-result.v1",
        status=status,
        max_request_bytes=MAX_REQUEST_BYTES,
        record_success=False,
    )
    if result is None:
        raise NativeBashError("native_bash_prepare_unavailable")
    validate_reply(result, request, kind="prepare", statuses=frozenset({"ok", "error", "denied", "unavailable"}))
    if result["status"] != "ok":
        raise NativeBashError(str(result["code"]))
    return cast(dict[str, object], result["payload"])


def verify_review_request(request: dict[str, object], *, guard_home: Path) -> None:
    status = runtime_status()
    _ = encode(request)
    result = _resident_request(
        operation="native_bash_review_check",
        request=request,
        guard_home=guard_home,
        timeout_seconds=10,
        required_feature=DESCRIPTOR_FEATURE,
        response_schema="guard-native-bash-review-check-result.v1",
        status=status,
        max_request_bytes=MAX_REQUEST_BYTES,
        record_success=False,
    )
    if result is None:
        raise NativeBashError("native_bash_review_check_unavailable")
    validate_reply(result, request, kind="review-check")
    if result["status"] != "ok":
        raise NativeBashError(str(result["code"]))
    descriptor = request["descriptor"]
    assert isinstance(descriptor, dict)
    lineage = descriptor["review_lineage"]
    assert isinstance(lineage, dict)
    if result["payload"] != {
        "approval_request_id": request["approval_request_id"],
        "lineage_id": lineage["lineage_id"],
        "artifact_hash": descriptor["artifact_hash"],
    }:
        raise NativeBashError("native_bash_review_check_invalid")


def execute(
    request: dict[str, object],
    *,
    guard_home: Path,
    cwd: Path,
    host_owner_pid: int | None = None,
) -> dict[str, object]:
    status = runtime_status()
    assert status.identity is not None
    timeout_ms = request.get("timeout_ms")
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 120_000:
        raise NativeBashError("native_bash_timeout_invalid")
    if host_owner_pid is not None and (type(host_owner_pid) is not int or not 2 <= host_owner_pid <= 2_147_483_647):
        raise NativeBashError("native_bash_host_owner_invalid")
    # A dedicated Rust client owns this connection. The inherited parent pipe
    # closes even if this Python sink is killed; the pooled helper cannot give
    # that guarantee while synchronously waiting for a long execution reply.
    envelope: dict[str, object] = {
        "operation": "native_bash_execute",
        "request": request,
        "deadline_budget_ms": timeout_ms + 1000,
    }
    command = [str(status.identity.path), "native-bash-execute-client", "--stdin", str(guard_home / "native-runtime")]
    if host_owner_pid is not None:
        command.extend(["--host-owner-pid", str(host_owner_pid)])
    reply = run_isolated_hook_process(
        command,
        input_text=encode(envelope),
        cwd=cwd,
        environment=_isolated_environment(),
        timeout_seconds=timeout_ms / 1000 + 2,
        output_limit=2 * 1024 * 1024,
        parent_liveness=True,
    )
    if reply.returncode != 0 or reply.timed_out or reply.output_limit_exceeded or reply.containment_failed:
        # The attempt may have dispatched. Retain its operation_id; never
        # manufacture a fresh attempt in response to an uncertain transport.
        raise NativeBashError("native_bash_execution_reply_unavailable")
    result = decode(reply.stdout)
    validate_reply(
        result,
        request,
        kind="execute",
        statuses=frozenset({"ok", "error", "recorded"}),
        extra=frozenset({"grant_claimed", "dispatch_acknowledged", "replayed", "operation", "review_lineage"}),
    )
    return result


def activity(operation_id: str, *, guard_home: Path) -> dict[str, object]:
    """Observe active ownership; absence does not prove completion or consent."""
    request: dict[str, object] = {
        "schema": "guard-native-bash-activity-request.v1",
        "request_id": request_id(),
        "guard_home": str(guard_home),
        "operation_id": operation_id,
    }
    result = _resident_request(
        operation="native_bash_activity",
        request=request,
        guard_home=guard_home,
        timeout_seconds=2,
        required_feature="native-bash-activity-v1",
        response_schema="guard-native-bash-activity-result.v1",
        status=runtime_status(),
        max_request_bytes=16 * 1024,
        record_success=False,
    )
    if result is None:
        raise NativeBashError("native_bash_activity_unavailable")
    validate_reply(result, request, kind="activity")
    payload = result["payload"]
    if result["status"] != "ok":
        raise NativeBashError(str(result["code"]))
    if (
        not isinstance(payload, dict)
        or set(payload) != {"operation_id", "active", "cancellation_requested"}
        or payload.get("operation_id") != operation_id
        or type(payload.get("active")) is not bool
        or type(payload.get("cancellation_requested")) is not bool
        or (payload["cancellation_requested"] and not payload["active"])
    ):
        raise NativeBashError("native_bash_activity_invalid")
    return payload
