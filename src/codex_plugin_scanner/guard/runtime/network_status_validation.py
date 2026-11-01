"""Strict validation for privacy-safe network status projections.

The native runtime validates the daemon's `guard.network-status.v1` payload
(`network-status-validation --stdin`) and answers its projection. Without a
runtime that offers it, no payload is treated as network truth.
"""

from __future__ import annotations

import json
import time
from typing import cast

_FEATURE = "native-network-status-validation-v1"
_SCHEMA = "network-status-validation.v1"
_TIMEOUT_SECONDS = 10.0
_OUTPUT_LIMIT = 1024 * 1024


class NetworkStatusSchemaError(ValueError):
    """Raised when daemon status cannot safely be treated as network truth."""


def validate_network_status(
    payload: object,
    *,
    now_epoch_ms: int | None = None,
) -> dict[str, object]:
    """Validate the complete v1 daemon projection before presenting protection."""

    current_epoch_ms = int(time.time() * 1000) if now_epoch_ms is None else now_epoch_ms
    if current_epoch_ms < 0:
        raise ValueError("now_epoch_ms must be non-negative")
    try:
        request = json.dumps(
            {"schema": _SCHEMA, "status": payload, "now_epoch_ms": current_epoch_ms},
            allow_nan=False,
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise NetworkStatusSchemaError("network status is not JSON") from error

    from ..mdm.runtime_request import runtime_answer

    answer = runtime_answer(
        _FEATURE,
        "network-status-validation",
        request,
        output_limit=_OUTPUT_LIMIT,
        timeout_seconds=_TIMEOUT_SECONDS,
    )
    if answer is None:
        raise NetworkStatusSchemaError("network status validation requires the native runtime")
    status = answer.get("status")
    if isinstance(status, dict):
        return cast(dict[str, object], status)
    error = answer.get("error")
    raise NetworkStatusSchemaError(error if isinstance(error, str) else "network status is invalid")
