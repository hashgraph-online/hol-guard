"""Typed client for the native false-positive rules owner; no Python evaluator.

Rust owns the advisory false-positive signals for a runtime action (read-only
source searches, localhost health checks, read-only HTTP probes, version-pin,
manifest and docs/example file reads). Python ships the action type, command
and target paths, binds the answer to the request by ``request_id`` and
canonical ``request_sha256``, and renders the signals. Any transport, scope, or
binding failure raises ``NativeFalsePositiveRulesError`` (never another
exception type), which callers treat as "no false-positive signal": nothing
here ever classifies a command or path locally.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .native_context import (
    _COLD_START_ALLOWANCE_SECONDS,
    _canonical_request_sha256,
    _native_error,
    _native_runtime_status_memo,
    _resolve_digest_home,
    ensure_resident_prerequisite,
)
from .native_resident_client import native_resident_client_ready, native_resident_client_request
from .native_runtime import _isolated_environment
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)
from .runtime.signals import RiskSignalV2

_FEATURE = "false-positive-rules-v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_REQUEST_SCHEMA = "guard-false-positive-rules-request.v1"
_RESULT_SCHEMA = "guard-false-positive-rules-result.v1"
_MAX_REQUEST_BYTES = 256 * 1024
# Steady-state round-trip budget for this advisory call. It is deliberately
# small: the signals only annotate a decision, so a slow resident must degrade
# to "no signals" rather than hold up the detector registry. A resident that
# still has to be spawned gets the same one-off allowance the context digest
# grants, so a cold start is not recorded as a resident failure.
_TIMEOUT_SECONDS = 0.5
_MAX_DEADLINE_BUDGET_MS = 9_000
_INVALID_RESULT = "native_false_positive_rules_result_invalid"
DETECTOR_ID = "false_positive.suppressor"


class NativeFalsePositiveRulesError(ValueError):
    """The native owner could not supply bound, typed false-positive signals."""


def validate_false_positive_signals(payloads: Sequence[dict[str, object]]) -> tuple[RiskSignalV2, ...]:
    """Parse resident signals, rejecting malformed ones and ones this owner does not emit."""

    try:
        signals = tuple(RiskSignalV2.from_dict(payload) for payload in payloads)
    except ValueError as error:
        raise NativeFalsePositiveRulesError(_INVALID_RESULT) from error
    if any(signal.category != "false_positive" or signal.detector != DETECTOR_ID for signal in signals):
        raise NativeFalsePositiveRulesError(_INVALID_RESULT)
    return signals


def native_false_positive_signals(
    *,
    action_type: str,
    command: str | None,
    target_paths: Sequence[str],
    guard_home: Path | None = None,
    timeout_seconds: float | None = None,
) -> list[dict[str, object]]:
    """Return the resident's ``RiskSignalV2`` dicts for the action, in emission order.

    ``timeout_seconds`` is the caller's budget; it never drops below the
    steady-state floor, and the resident is told the same deadline the client
    enforces, so neither side waits past it.
    """

    guard_home = _resolve_digest_home(guard_home)
    request: dict[str, Any] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": uuid.uuid4().hex,
        "guard_home": str(guard_home),
        "action_type": action_type,
        "command": command,
        "target_paths": list(target_paths),
    }
    status = _native_runtime_status_memo()
    if (
        status.mode == "off"
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _FEATURE not in status.capabilities.features
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
    ):
        raise NativeFalsePositiveRulesError("native_false_positive_rules_unavailable")
    try:
        prerequisite = ensure_resident_prerequisite(guard_home)
    except Exception as error:
        raise NativeFalsePositiveRulesError("native_false_positive_rules_prerequisite_unavailable") from error
    if not prerequisite:
        raise NativeFalsePositiveRulesError("native_false_positive_rules_prerequisite_unavailable")
    try:
        request_sha256 = _canonical_request_sha256(request)
        # Rust bounds the ASCII-escaped canonical form, which can exceed the
        # UTF-8 envelope for non-ASCII text; reject on whichever is larger.
        canonical_size = len(
            json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        )
        budget_seconds = max(_TIMEOUT_SECONDS, timeout_seconds or 0.0)
        if not native_resident_client_ready(status.identity.path, guard_home):
            budget_seconds += _COLD_START_ALLOWANCE_SECONDS
        deadline_budget_ms = max(1, min(_MAX_DEADLINE_BUDGET_MS, int(budget_seconds * 1_000)))
        envelope = json.dumps(
            {"operation": "false_positive_rules", "deadline_budget_ms": deadline_budget_ms, "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeFalsePositiveRulesError("native_false_positive_rules_component_unencodable") from error
    if max(len(envelope), canonical_size) > _MAX_REQUEST_BYTES:
        raise NativeFalsePositiveRulesError("native_false_positive_rules_request_too_large")
    try:
        output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=guard_home,
            environment=_isolated_environment(),
            payload=envelope,
            deadline_monotonic=time.monotonic() + deadline_budget_ms / 1_000,
        )
    except Exception:
        # RuntimeError (thread start), OSError, timeouts: all one typed failure.
        output = None
    if output is None:
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_false_positive_rules_resident_unavailable"
        )
        raise NativeFalsePositiveRulesError("native_false_positive_rules_resident_unavailable")
    try:
        payload = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        raise NativeFalsePositiveRulesError(_INVALID_RESULT) from error
    error_code = _native_error(payload)
    if error_code is not None:
        if error_code == "native_overloaded":
            native_record_overload(status.identity.sha256, guard_home)
        else:
            native_record_resident_failure(status.identity.sha256, guard_home, reason=error_code)
        raise NativeFalsePositiveRulesError(error_code)
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != _RESULT_SCHEMA
        or payload.get("request_id") != request["request_id"]
        or payload.get("request_sha256") != request_sha256
        or payload.get("status") != "ok"
        or payload.get("code") != "ok"
        or not isinstance(payload.get("payload"), dict)
    ):
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        code = payload.get("code") if isinstance(payload, dict) else None
        raise NativeFalsePositiveRulesError(
            code if isinstance(code, str) and code.startswith("native_false_positive_rules_") else _INVALID_RESULT
        )
    signals = payload["payload"].get("signals")
    if not isinstance(signals, list) or not all(isinstance(signal, dict) for signal in signals):
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        raise NativeFalsePositiveRulesError(_INVALID_RESULT)
    try:
        validate_false_positive_signals(signals)
    except NativeFalsePositiveRulesError:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        raise
    native_record_resident_success(status.identity.sha256, guard_home)
    return signals
