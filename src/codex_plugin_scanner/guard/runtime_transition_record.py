"""Write and open the signed runtime transition journal through the native runtime.

The runtime signs, encodes, writes, reads, authenticates and shape-checks the
journal under `<guard home>/managed` and the not-started refusal receipts
beside it. The caller holds the install lock and passes the policy integrity
key it read from the platform secret store. Any refusal, and no answer at
all, raises `TransitionRecordRefusedError` with the runtime's reason.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

_FEATURE = "native-runtime-transition-record-v1"
_SCHEMA = "runtime-transition-record.v1"
_TIMEOUT_SECONDS = 30.0
# A journal is at most 32 MiB; the answer carries one decoded payload.
_OUTPUT_LIMIT = 96 * 1024 * 1024
RUNTIME_UNAVAILABLE = "runtime_unavailable"


class TransitionRecordRefusedError(Exception):
    """The runtime refused the record, or did not answer."""

    def __init__(self, reason: str, detail: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def record_request(
    op: str,
    home: Path,
    key: tuple[bytes, str] | None,
    *,
    deadline: float | None = None,
    **fields: object,
) -> dict[str, object]:
    """The runtime's answer to one journal operation under `home`."""

    from .mdm.runtime_request import runtime_answer

    request: dict[str, object] = {"schema": _SCHEMA, "op": op, "guard_home": str(home), **fields}
    if key is not None:
        request["integrity_key_b64"] = base64.urlsafe_b64encode(key[0]).rstrip(b"=").decode("ascii")
        request["integrity_key_id"] = key[1]
    bound = time.monotonic() + _TIMEOUT_SECONDS
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransitionRecordRefusedError("deadline_exceeded")
        request["deadline_seconds"] = remaining
        bound = min(bound, deadline)
    # A value JSON cannot carry, such as an infinite deadline, is the
    # caller's error, as it was when the record was encoded here.
    encoded = json.dumps(request, allow_nan=False, separators=(",", ":"))
    try:
        answer = runtime_answer(
            _FEATURE,
            "runtime-transition-record",
            encoded,
            output_limit=_OUTPUT_LIMIT,
            deadline=bound,
        )
    except (TypeError, ValueError) as exc:
        raise TransitionRecordRefusedError("invalid") from exc
    if not isinstance(answer, dict):
        if deadline is not None and time.monotonic() >= deadline:
            raise TransitionRecordRefusedError("deadline_exceeded")
        raise TransitionRecordRefusedError(RUNTIME_UNAVAILABLE)
    error = answer.get("error")
    if isinstance(error, str):
        detail = answer.get("detail")
        raise TransitionRecordRefusedError(error, detail if isinstance(detail, str) else None)
    return answer


__all__ = ["RUNTIME_UNAVAILABLE", "TransitionRecordRefusedError", "record_request"]
