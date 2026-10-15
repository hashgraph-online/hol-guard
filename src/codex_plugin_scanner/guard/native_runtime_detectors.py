"""Typed client for the native runtime detector run; no Python evaluator.

Rust owns the default runtime detectors (secret paths, data-flow exfiltration,
prompt injection, skill content, supply chain, safe decode, false-positive
hints, persistence, Guard bypass and MCP tool risk). Python ships the action
fields and the registry options, binds the answer to the request by
``request_id`` and canonical ``request_sha256``, and renders the per-detector
entries. Every outcome other than a well-formed, request-bound ``ok`` reply
raises ``NativeRuntimeDetectorError``; callers must fail closed and never
substitute a Python evaluation.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, cast

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .runtime.signals import RiskSignalCategory, RiskSignalV2

if TYPE_CHECKING:
    from .runtime.actions import GuardActionEnvelope
    from .runtime.detectors import DetectorRunStatus

_FEATURE = "runtime-detector-run-v1"
_REQUEST_SCHEMA = "guard-runtime-detector-run-request.v1"
_RESULT_SCHEMA = "guard-runtime-detector-run-result.v1"
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "payload"})
_ENTRY_KEYS = frozenset({"detector_id", "categories", "status", "elapsed_ms", "error_type", "signals"})
_STATUSES = frozenset({"ok", "disabled", "filtered", "timeout", "error"})
# The resident bounds the ASCII-escaped canonical request at 4 MiB. The wire
# envelope is serialized with spaced separators, so it is checked only against
# the resident's 6 MiB frame limit and the canonical bound stays authoritative.
_MAX_WIRE_BYTES = 6 * 1024 * 1024
_MAX_ENTRIES = 32
# The resident runs every detector in one call and clamps client deadlines for
# this operation to nine seconds, so the transport waits for exactly that long.
_TRANSPORT_TIMEOUT_SECONDS = 9.0
_INVALID = "native_runtime_detector_run_invalid_result"

DetectorEntry = tuple[
    str, tuple[RiskSignalCategory, ...], "DetectorRunStatus", int, str | None, tuple[RiskSignalV2, ...]
]


class NativeRuntimeDetectorError(RuntimeError):
    """The native owner could not supply a complete, request-bound detector run."""


def native_runtime_detector_entries(
    action: GuardActionEnvelope,
    *,
    workspace: Path | None,
    guard_home: Path | None,
    timeout_ms: int,
    disabled_detector_ids: Sequence[str],
    enabled_categories: Sequence[RiskSignalCategory] | None,
) -> tuple[DetectorEntry, ...]:
    """Return ``(detector_id, categories, status, elapsed_ms, error_type, signals)`` per native detector."""

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id("runtime_detector_run"),
        "guard_home": "",
        "workspace": str(workspace) if workspace is not None else None,
        "action": {
            "action_type": action.action_type,
            "command": action.command,
            "prompt_text": action.prompt_text,
            "prompt_excerpt": action.prompt_excerpt,
            "mcp_tool": action.mcp_tool,
            "target_paths": list(action.target_paths),
        },
        "timeout_ms": max(0, int(timeout_ms)),
        "disabled_detector_ids": list(disabled_detector_ids),
        "enabled_categories": list(enabled_categories) if enabled_categories is not None else None,
    }
    try:
        home = _resolve_digest_home(guard_home)
        request["guard_home"] = str(home)
        if not ensure_resident_prerequisite(home):
            raise NativeRuntimeDetectorError("native_runtime_detector_run_unavailable")
        request_sha256 = _canonical_request_sha256(request)
        decoded = native_execution._resident_request(
            operation="runtime_detector_run",
            request=request,
            guard_home=home,
            timeout_seconds=_TRANSPORT_TIMEOUT_SECONDS,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_WIRE_BYTES,
        )
    except (OSError, TypeError, ValueError) as error:
        raise NativeRuntimeDetectorError("native_runtime_detector_run_unavailable") from error
    if decoded is None:
        raise NativeRuntimeDetectorError("native_runtime_detector_run_unavailable")
    if not set(decoded) <= _RESULT_KEYS or decoded.get("status") != "ok" or decoded.get("code") != "ok":
        raise NativeRuntimeDetectorError(_INVALID)
    if decoded.get("request_id") != request["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeRuntimeDetectorError("native_runtime_detector_run_request_mismatch")
    payload = decoded.get("payload")
    entries = payload.get("detectors") if isinstance(payload, dict) else None
    if not isinstance(entries, list) or len(entries) > _MAX_ENTRIES:
        raise NativeRuntimeDetectorError(_INVALID)
    parsed = tuple(_entry(entry) for entry in entries)
    ids = [entry[0] for entry in parsed]
    if ids != sorted(set(ids)):
        raise NativeRuntimeDetectorError(_INVALID)
    return parsed


def _entry(entry: object) -> DetectorEntry:
    if not isinstance(entry, dict) or set(entry) != _ENTRY_KEYS:
        raise NativeRuntimeDetectorError(_INVALID)
    detector_id = entry["detector_id"]
    categories = entry["categories"]
    status = entry["status"]
    elapsed_ms = entry["elapsed_ms"]
    error_type = entry["error_type"]
    signals = entry["signals"]
    if (
        not isinstance(detector_id, str)
        or not detector_id
        or not isinstance(categories, list)
        or not all(isinstance(category, str) for category in categories)
        or status not in _STATUSES
        or not isinstance(elapsed_ms, int)
        or isinstance(elapsed_ms, bool)
        or elapsed_ms < 0
        or not (error_type is None or isinstance(error_type, str))
        or not isinstance(signals, list)
        or not all(isinstance(signal, dict) for signal in signals)
    ):
        raise NativeRuntimeDetectorError(_INVALID)
    try:
        parsed_signals = tuple(RiskSignalV2.from_dict(signal) for signal in signals)
    except (TypeError, ValueError) as error:
        raise NativeRuntimeDetectorError(_INVALID) from error
    return (
        detector_id,
        cast("tuple[RiskSignalCategory, ...]", tuple(categories)),
        cast("DetectorRunStatus", status),
        elapsed_ms,
        error_type,
        parsed_signals,
    )
