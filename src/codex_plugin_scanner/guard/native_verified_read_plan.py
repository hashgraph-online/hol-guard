"""Typed client for the native verified-read plan; no Python grammar."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

if TYPE_CHECKING:
    from .native_runtime_values import NativeRuntimeIdentity

_FEATURE = "verified-read-plan-v1"
_REQUEST_SCHEMA = "guard-verified-read-plan-request.v1"
_RESULT_SCHEMA = "guard-verified-read-plan-result.v1"
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "detail", "plan"})
_PLAN_KEYS = frozenset({"operation_id", "target", "selection"})
_WORKING_DIRECTORY: Final = "working_directory"
_LEADING_LINES: Final = "leading_lines"
_TRAILING_LINES: Final = "trailing_lines"
_LINE_RANGE: Final = "line_range"
_REFUSED = "native_verified_read_plan_refused"
_MAX_DETAIL_CHARS = 256
# The resident accepts a canonical request up to 16 KiB; the wire envelope
# carries the same material plus framing, so leave room for both.
_MAX_REQUEST_BYTES = 16 * 1024
_MAX_WIRE_BYTES = 6 * _MAX_REQUEST_BYTES + 4096


class NativeVerifiedReadPlanError(RuntimeError):
    """The native owner could not supply a complete, request-bound plan."""


class NativeVerifiedReadPlanRefusedError(NativeVerifiedReadPlanError):
    """The resident answered: this argv is outside the verified-read grammar."""

    def __init__(self, detail: str) -> None:
        super().__init__(_REFUSED)
        self.detail = detail


@dataclass(frozen=True, slots=True)
class VerifiedReadPlan:
    """The one bounded read the resident says this argv asks for."""

    operation_id: str
    target: str | None
    select: str
    count: int
    start: int
    end: int


def verified_read_plan(
    argv: tuple[str, ...],
    *,
    guard_home: Path | None = None,
    timeout_seconds: float = 10.0,
) -> VerifiedReadPlan:
    """Return the resident's plan for one verified workspace read.

    The grammar that decides which read an argv names, and how much of a file
    it may show, is the resident's. Every outcome other than a well-formed,
    request-bound ``ok`` reply raises ``NativeVerifiedReadPlanError``; callers
    must not parse the argv themselves instead, which would be a second place
    a verified read's bounds are set.
    """

    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id("verified_read_plan"),
        "argv": list(argv),
    }
    try:
        home = _resolve_digest_home(guard_home)
        if not ensure_resident_prerequisite(home):
            raise NativeVerifiedReadPlanError("native_verified_read_plan_unavailable")
        request_sha256 = _canonical_request_sha256(wire)
        # Resolved once: the transport and the health record below must name
        # the same binary, and the lookup walks the runtime on disk.
        status = native_runtime_status()
        decoded = native_execution._resident_request(
            operation="verified_read_plan",
            request=wire,
            guard_home=home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_WIRE_BYTES,
            # Success is recorded below, once the reply is known to be usable.
            record_success=False,
            status=status,
        )
    except (OSError, TypeError, ValueError) as error:
        raise NativeVerifiedReadPlanError("native_verified_read_plan_unavailable") from error
    if decoded is None:
        raise NativeVerifiedReadPlanError("native_verified_read_plan_unavailable")
    try:
        plan = _validated_plan(decoded, wire, request_sha256)
    except NativeVerifiedReadPlanRefusedError:
        # A request-bound refusal is a healthy resident answering the question.
        _record(home, status.identity, success=True)
        raise
    except NativeVerifiedReadPlanError:
        _record(home, status.identity, success=False)
        raise
    _record(home, status.identity, success=True)
    return plan


def _validated_plan(decoded: dict[str, Any], wire: dict[str, object], request_sha256: str) -> VerifiedReadPlan:
    if set(decoded) != _RESULT_KEYS:
        raise NativeVerifiedReadPlanError("native_verified_read_plan_invalid_result")
    if decoded.get("request_id") != wire["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeVerifiedReadPlanError("native_verified_read_plan_request_mismatch")
    status, code = decoded.get("status"), decoded.get("code")
    if status == "error" and code == _REFUSED:
        detail: Any = decoded.get("detail")
        bounded = isinstance(detail, str) and 0 < len(detail) <= _MAX_DETAIL_CHARS
        if not bounded or decoded.get("plan") is not None:
            raise NativeVerifiedReadPlanError("native_verified_read_plan_invalid_result")
        raise NativeVerifiedReadPlanRefusedError(detail)
    if status != "ok" or code != "ok":
        raise NativeVerifiedReadPlanError("native_verified_read_plan_invalid_result")
    payload: Any = decoded.get("plan")
    if not isinstance(payload, dict) or set(payload) != _PLAN_KEYS:
        raise NativeVerifiedReadPlanError("native_verified_read_plan_invalid_result")
    operation_id: Any = payload.get("operation_id")
    target: Any = payload.get("target")
    if not isinstance(operation_id, str) or not operation_id:
        raise NativeVerifiedReadPlanError("native_verified_read_plan_invalid_result")
    if target is not None and (not isinstance(target, str) or not target):
        raise NativeVerifiedReadPlanError("native_verified_read_plan_invalid_result")
    return _validated_selection(payload.get("selection"), operation_id=operation_id, target=target)


def _validated_selection(selection: Any, *, operation_id: str, target: str | None) -> VerifiedReadPlan:
    if not isinstance(selection, dict):
        raise NativeVerifiedReadPlanError("native_verified_read_plan_invalid_result")
    select: Any = selection.get("select")
    if select == _WORKING_DIRECTORY and set(selection) == {"select"} and target is None:
        return VerifiedReadPlan(operation_id, None, _WORKING_DIRECTORY, 0, 0, 0)
    if target is None:
        raise NativeVerifiedReadPlanError("native_verified_read_plan_invalid_result")
    if select in {_LEADING_LINES, _TRAILING_LINES} and set(selection) == {"select", "count"}:
        count = _bound(selection.get("count"))
        return VerifiedReadPlan(operation_id, target, select, count, 0, 0)
    if select == _LINE_RANGE and set(selection) == {"select", "start", "end"}:
        start = _bound(selection.get("start"))
        end = _bound(selection.get("end"))
        if start > end:
            raise NativeVerifiedReadPlanError("native_verified_read_plan_invalid_result")
        return VerifiedReadPlan(operation_id, target, _LINE_RANGE, 0, start, end)
    raise NativeVerifiedReadPlanError("native_verified_read_plan_invalid_result")


def _bound(value: Any) -> int:
    """Read one line bound as sent; the resident decides what it may be."""

    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise NativeVerifiedReadPlanError("native_verified_read_plan_invalid_result")
    return value


def _record(home: Path, identity: NativeRuntimeIdentity | None, *, success: bool) -> None:
    if identity is None:
        return
    if success:
        native_record_resident_success(identity.sha256, home)
    else:
        native_record_resident_failure(identity.sha256, home, reason="native_verified_read_plan_result")
