"""Thin resident transport for the authenticated resident health operation.

Rust decides everything here. Python bounds the request, forwards it over the
existing resident protocol and validates the shape of the reply. It computes no
status of its own: an answer means the resident is alive and authenticating,
and no answer means Python has nothing to say about it beyond that.

The operation runs on the resident's reserved control lane, so a resident whose
evaluation queue is full still answers. That is the whole point: the older
``health`` operation is refused with ``native_overloaded`` exactly as work is,
which leaves a caller unable to tell a loaded resident from a dead one.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .native_resident_client import native_resident_client_request
from .native_runtime import NativeRuntimeStatus, _isolated_environment, native_runtime_status
from .strict_json_pairs import unique_json_object

RESIDENT_HEALTH_FEATURE = "resident-health-v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
# The framing version a resident advertising the feature above must report.
_RESIDENT_PROTOCOL_VERSION = 2
_REQUEST_SCHEMA = "guard-resident-health-request.v1"
_RESULT_SCHEMA = "guard-resident-health-result.v1"
# Python and the native runtime are installed as separate artifacts, and a
# desktop bundle can carry either one ahead of the other, so this module reads
# the reply by the fields it needs rather than by an exact field list. A reply
# that has grown a field stays readable to an older Python, and a runtime that
# predates a field this one knows about still answers. Every field named below
# is required and type-checked; every other entry must still be a count.
_LANE_FIELDS = frozenset({"workers", "queue_capacity"})
_COUNTER_FIELDS = frozenset(
    {
        "served_requests",
        "service_micros_total",
        "service_micros_max",
        "request_bytes_total",
        "request_bytes_max",
        "auth_failures",
        "frame_errors",
        "deadline_exceeded",
        "digest_mismatches",
        "panics",
    }
)
_RESULT_FIELDS = frozenset(
    {
        "schema",
        "request_id",
        "request_sha256",
        "status",
        "protocol_version",
        "runtime_version",
        "build_sha",
        "target",
        "uptime_ms",
        "evaluation",
        "control",
        "overloaded_requests",
    }
)


def _supports_resident_health(status: NativeRuntimeStatus) -> bool:
    if not status.available or not status.compatible:
        return False
    if status.identity is None or status.capabilities is None:
        return False
    features = set(status.capabilities.features)
    return _RESIDENT_PROTOCOL_FEATURE in features and RESIDENT_HEALTH_FEATURE in features


def _counts(value: Any, required: frozenset[str]) -> dict[str, Any] | None:
    """``value`` when it is an object whose every entry is a count.

    ``required`` must all be present. Anything else the runtime reports is
    carried through unchanged, because it is a count too and the caller only
    prints it.
    """

    if not isinstance(value, dict) or not set(value) >= required:
        return None
    for field in value:  # type: ignore[union-attr]
        count = value[field]
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            return None
    return dict(value)  # type: ignore[arg-type]


def _validated_lane(value: Any) -> dict[str, Any] | None:
    return _counts(value, _LANE_FIELDS)


def _validated_result(decoded: Any, request: dict[str, str]) -> dict[str, Any] | None:
    if not isinstance(decoded, dict) or not set(decoded) >= _RESULT_FIELDS:
        return None
    if decoded["schema"] != _RESULT_SCHEMA or decoded["request_id"] != request["request_id"]:
        return None
    if decoded["status"] != "serving":
        return None
    for field in ("request_sha256", "runtime_version", "build_sha", "target"):
        if not isinstance(decoded[field], str) or not decoded[field]:
            return None
    # The reply names the digest Rust computed over the request it decoded.
    # Python requires it to be there and leaves it at that: this request is a
    # constant schema and the identifier compared above, so recomputing the
    # digest here would add a second canonical encoder that has to stay byte
    # identical to Rust's in order to repeat what that comparison already says.
    for field in ("protocol_version", "uptime_ms", "overloaded_requests"):
        value = decoded[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return None
    if decoded["protocol_version"] != _RESIDENT_PROTOCOL_VERSION:
        return None
    blocks: dict[str, dict[str, Any] | None] = {
        lane: _validated_lane(decoded[lane]) for lane in ("evaluation", "control")
    }
    # A resident built before the aggregate counters existed reports no
    # `counters` block at all; one that reports it must report all of it.
    if "counters" in decoded:
        blocks["counters"] = _counts(decoded["counters"], _COUNTER_FIELDS)
    if any(block is None for block in blocks.values()):
        return None
    return {**decoded, **blocks}


def native_resident_health(
    *,
    guard_home: Path,
    timeout_seconds: float = 2.0,
) -> dict[str, Any] | None:
    """Ask the serving resident how it is doing, or return ``None``.

    ``None`` covers every way the question went unanswered — no installed
    runtime, a runtime too old to carry the operation, a refused or malformed
    reply, or a resident that is gone. The caller reports an unanswered
    question as exactly that; it must not read a verdict into it.

    This never starts a resident: the runtime refuses the operation rather
    than spawn one to answer it, and the request is sent as a diagnostic, so
    it neither arms nor clears the restart hold that gates hook execution and
    leaves no client stream parked behind it. Asking how loaded a resident is
    cannot be what takes it out of service.
    """
    deadline = time.monotonic() + timeout_seconds
    request = {"schema": _REQUEST_SCHEMA, "request_id": f"rh-{time.monotonic_ns():x}"}
    try:
        status = native_runtime_status(deadline_monotonic=deadline)
        if not _supports_resident_health(status) or status.identity is None:
            return None
        envelope = {
            "operation": "resident_health",
            "request": request,
            "deadline_budget_ms": max(1, int((deadline - time.monotonic()) * 1000)),
        }
        response = native_resident_client_request(
            executable=status.identity.path,
            guard_home=guard_home,
            environment=_isolated_environment(),
            payload=json.dumps(envelope, separators=(",", ":")).encode("utf-8"),
            timeout_seconds=max(0.001, deadline - time.monotonic()),
            deadline_monotonic=deadline,
            diagnostic=True,
        )
    except (OSError, RuntimeError, ValueError):
        # An optional diagnostic that cannot be taken must read as unanswered,
        # not abort the report it is one line of.
        return None
    if response is None:
        return None
    try:
        decoded = json.loads(response.decode("utf-8"), object_pairs_hook=unique_json_object)
    except (UnicodeDecodeError, ValueError):
        return None
    return _validated_result(decoded, request)


__all__ = ["RESIDENT_HEALTH_FEATURE", "native_resident_health"]
