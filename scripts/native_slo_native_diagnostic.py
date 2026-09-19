"""Read-only native-call diagnostics captured inside the actual worker context.

Never reset the client failure ContextVar, refresh runtime health/readiness,
reissue a request, or change the caller's deadline. Cached publisher flags are
observations, not a fresh readiness or policy-acceptance assertion.
"""

from __future__ import annotations

import hashlib
import math
import threading
import time
from collections.abc import Callable, Mapping
from typing import TypeVar, cast

from codex_plugin_scanner.guard.native_approval_errors import NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_failure_code
from scripts.native_slo_edge_diagnostic import collect_native_edge_stages

_T = TypeVar("_T")
_PYTHON_CLIENT_CODES = frozenset(
    {
        "native_client_containment_failed",
        "native_client_timed_out",
        "native_client_output_limit_exceeded",
        "native_client_status_missing",
        "native_client_exit_nonzero",
        "native_client_output_missing",
        "native_client_process_failed",
        "native_client_pool_exhausted",
        "native_client_request_invalid",
        "native_client_launcher_failed",
        "native_client_start_failed",
        "native_client_stdin_unavailable",
        "native_client_stream_failed",
    }
)
_CLIENT_CODES = NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES | _PYTHON_CLIENT_CODES
_MAX_LABEL_CHARS = 128
_MAX_INTERVAL_MS = 86_400_000.0


def _code(value: object) -> dict[str, object]:
    """Keep a closed code or a bounded digest, never free-form error text."""
    if value is None:
        return {"state": "absent"}
    if not isinstance(value, str):
        return {"state": "invalid_type"}
    bounded = value[:_MAX_LABEL_CHARS]
    known = len(value) <= _MAX_LABEL_CHARS and value in _CLIENT_CODES
    result: dict[str, object] = {
        "state": "known" if known else "unlisted",
        "digest": hashlib.sha256(bounded.encode("utf-8", errors="replace")).hexdigest(),
        "digest_complete": len(value) <= _MAX_LABEL_CHARS,
    }
    if known:
        result["value"] = value
    return result


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _milliseconds(value: float) -> float:
    return round(max(-_MAX_INTERVAL_MS, min(_MAX_INTERVAL_MS, value * 1000)), 3)


def _publisher_cached_state(worker: object) -> dict[str, object]:
    """Inspect only cached primitive fields under a nonblocking lock attempt."""
    publisher = getattr(worker, "policy_snapshot_publisher", None)
    condition = getattr(publisher, "_condition", None)
    if not isinstance(condition, threading.Condition):
        return {"publisher_cache": "unavailable"}
    if not condition.acquire(blocking=False):
        return {"publisher_cache": "busy"}
    try:
        result: dict[str, object] = {"publisher_cache": "captured"}
        for name in ("acked", "closed", "started"):
            value = getattr(publisher, "_" + name, None)
            result["publisher_" + name] = value if type(value) is bool else None
        result["publisher_snapshot_present"] = isinstance(getattr(publisher, "_snapshot", None), Mapping)
        count = getattr(publisher, "_failure_count", None)
        result["publisher_failure_count"] = count if type(count) is int and 0 <= count <= 2**63 - 1 else None
        error = _code(getattr(publisher, "_last_error", None))
        result.update(("publisher_error_" + key, value) for key, value in error.items())
        return result
    finally:
        condition.release()


def observe_native_call(
    operation: Callable[[], _T],
    *,
    worker: object,
    deadline: object = None,
    policy_snapshot: object = None,
) -> tuple[_T, dict[str, object]]:
    """Return the identical result and bounded evidence from this call's context.

    The caller must invoke this inside its existing native worker wrapper.
    Exceptions from operation propagate unchanged. An unchanged client code
    may predate the call: early native-edge refusals need not enter the client.
    """
    before = _code(native_resident_client_failure_code())
    began = time.monotonic()
    with collect_native_edge_stages() as stages:
        edge = operation()
        # This read must precede every health/clock/serialization operation after
        # the real call. Reading in the collector/main thread loses ContextVar data.
        after_code = native_resident_client_failure_code()
        ended = time.monotonic()
    after = _code(after_code)
    result: dict[str, object] = {
        "schema": "hol-guard.native-call-diagnostic.v1",
        "capture_context": "native_worker_wrapper",
        "elapsed_ms": _milliseconds(ended - began),
        "client_code_changed": before != after,
        "client_code_attribution": "context_transition" if before != after else "unchanged_or_stale",
        "policy_binding_supplied": isinstance(policy_snapshot, Mapping),
    }
    # Source and capacity failures add list/dict layers around this record.
    # Keep stage facts flat so their scalar values stay inside the unchanged
    # six-level privacy bound even in the deepest exported failure shape.
    for stage, fields in stages.items():
        if type(fields) is dict:
            result.update((f"edge_{stage}_{key}", value) for key, value in fields.items())
        else:
            result["edge_" + stage] = fields
    for phase, code in (("before", before), ("after", after)):
        result.update(("client_" + phase + "_" + key, value) for key, value in code.items())
    effective_deadline = _number(deadline)
    result["caller_deadline_valid"] = effective_deadline is not None
    if effective_deadline is not None:
        result.update(
            caller_remaining_ms_before=_milliseconds(effective_deadline - began),
            caller_remaining_ms_after=_milliseconds(effective_deadline - ended),
            caller_expired_before=began >= effective_deadline,
            caller_expired_after=ended >= effective_deadline,
        )
    if isinstance(policy_snapshot, Mapping):
        binding = cast(Mapping[str, object], policy_snapshot)
        generation = binding.get("generation")
        result["policy_generation_valid"] = type(generation) is int and 0 < generation <= 2**63 - 1
        mode = binding.get("mode")
        result["policy_mode"] = mode if isinstance(mode, str) and mode in {"enforce", "observe"} else "unclassified"
    try:
        result.update(_publisher_cached_state(worker))
    except Exception:
        # Optional diagnostics must not change the native return or its errors.
        result["publisher_cache"] = "collection_failed"
    return edge, result
