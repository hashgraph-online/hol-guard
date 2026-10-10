"""Typed client for the native data-flow exfiltration owner; no Python evaluator."""

from __future__ import annotations

from pathlib import Path

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .runtime.actions import GuardActionEnvelope
from .runtime.signals import RiskSignalV2

_FEATURE = "data-flow-analyze-v1"
_REQUEST_SCHEMA = "guard-data-flow-analyze-request.v1"
_RESULT_SCHEMA = "guard-data-flow-analyze-result.v1"
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "signals"})
_MAX_SIGNALS = 64
# The resident accepts commands up to 256 KiB of UTF-8. ``json.dumps`` escapes
# every control character to six bytes, so the wire envelope can be six times
# larger than the command; leave that room plus the envelope itself.
_MAX_COMMAND_BYTES = 256 * 1024
_MAX_WIRE_BYTES = 6 * _MAX_COMMAND_BYTES + 4096


class NativeDataFlowError(RuntimeError):
    """The native owner could not supply a complete, request-bound data-flow result."""


def detect_data_flow_exfiltration(
    action: GuardActionEnvelope,
    *,
    workspace: Path | None,
    guard_home: Path | None = None,
    timeout_seconds: float = 10.0,
) -> tuple[RiskSignalV2, ...]:
    """Return the resident's ordered data-flow signals for ``action``.

    Every outcome other than a well-formed, request-bound ``ok`` reply raises
    ``NativeDataFlowError``; callers must not substitute a Python evaluation.
    Only shell commands carry shell data flow, so every other action returns no
    signals without contacting the resident, exactly as the native rules do.
    """

    if action.action_type != "shell_command" or action.command is None:
        return ()
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id("data_flow_analyze"),
        "action_type": action.action_type,
        "command": action.command,
        "workspace": str(workspace) if workspace is not None else None,
    }
    try:
        home = _resolve_digest_home(guard_home)
        if not ensure_resident_prerequisite(home):
            raise NativeDataFlowError("native_data_flow_unavailable")
        request_sha256 = _canonical_request_sha256(request)
        decoded = native_execution._resident_request(
            operation="data_flow_analyze",
            request=request,
            guard_home=home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_WIRE_BYTES,
        )
    except (OSError, TypeError, ValueError) as error:
        raise NativeDataFlowError("native_data_flow_unavailable") from error
    if decoded is None:
        raise NativeDataFlowError("native_data_flow_unavailable")
    if set(decoded) != _RESULT_KEYS or decoded.get("code") != "ok":
        raise NativeDataFlowError("native_data_flow_invalid_result")
    if decoded.get("request_id") != request["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeDataFlowError("native_data_flow_request_mismatch")
    signals = decoded.get("signals")
    if not isinstance(signals, list) or len(signals) > _MAX_SIGNALS:
        raise NativeDataFlowError("native_data_flow_invalid_result")
    if not all(isinstance(item, dict) for item in signals):
        raise NativeDataFlowError("native_data_flow_invalid_result")
    try:
        return tuple(RiskSignalV2.from_dict(item) for item in signals)
    except (TypeError, ValueError) as error:
        raise NativeDataFlowError("native_data_flow_invalid_result") from error
