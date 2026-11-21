"""Get the resident's finalization decision while the caller holds the generation lock."""

from __future__ import annotations

import time
from pathlib import Path

from .native_execution import _resident_request
from .native_policy_integrity_rows import (
    _RESULT_SCHEMA,
    _TIMEOUT_SECONDS,
    NativePolicyIntegrityUnavailableError,
    _bound_payload,
    _request,
)
from .native_runtime import native_runtime_status


def native_policy_integrity_finalization(
    guard_home: Path,
    *,
    current: dict[str, object] | None,
    proposed: dict[str, object],
    deadline: float | None = None,
) -> dict[str, object] | None:
    if deadline is not None and deadline <= time.monotonic():
        return None
    status = native_runtime_status(deadline_monotonic=deadline)
    timeout = _TIMEOUT_SECONDS if deadline is None else min(_TIMEOUT_SECONDS, deadline - time.monotonic())
    if timeout <= 0:
        return None
    request = _request(key=None, key_id=None, verify=[], sign=[])
    request["finalize"] = {"current_state": current, "next_state": proposed}
    try:
        response = _resident_request(
            operation="policy_integrity_rows",
            request=request,
            guard_home=guard_home,
            timeout_seconds=timeout,
            required_feature="policy-integrity-finalize-v1",
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=16 * 1024,
            record_success=False,
            status=status,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    if deadline is not None and time.monotonic() >= deadline:
        return None
    payload = _bound_payload(response, request, guard_home, status)
    if payload is None or set(payload) != {"verify", "sign", "finalize"}:
        raise NativePolicyIntegrityUnavailableError()
    result = payload["finalize"]
    if (
        payload["verify"] != []
        or payload["sign"] != []
        or not isinstance(result, dict)
        or set(result) != {"next_state"}
    ):
        raise NativePolicyIntegrityUnavailableError()
    next_state = result["next_state"]
    return next_state if isinstance(next_state, dict) else None
