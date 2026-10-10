"""Request-path persistence over ``guard.db`` owned by the native resident.

The resident opens the store, runs one named method in a single SQLite
transaction (same busy timeout, WAL and cache pragmas as the Python
connection), finalizes trigger-written outbox payload hashes, commits, and
reports the outbox generation when rows changed. Python keeps only the
process-local concerns around it: the storage-access gate, fatal-store
recovery, wake notification, wall-clock timestamps, and DTO shaping.

A resident that is unavailable, replies unbound, or violates the contract
never yields a silent default: the call raises ``NativeGuardStoreUnavailable``,
a ``sqlite3.OperationalError`` so existing store-failure handling applies.
"""

from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypeVar
from uuid import uuid4

from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

GUARD_STORE_FEATURE = "guard-store-v1"
GUARD_STORE_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_REQUEST_SCHEMA = "guard-store-request.v1"
_RESULT_SCHEMA = "guard-store-result.v1"
_ENVELOPE_SLACK_BYTES = 4096
_CODE = re.compile(r"^native_guard_store_[a-z_]{1,48}$")
_SQLITE_ERROR, _SQLITE_BUSY, _SQLITE_IOERR, _SQLITE_CORRUPT = 1, 5, 10, 11


class NativeGuardStoreUnavailable(sqlite3.OperationalError):
    """The resident gave no authoritative answer; the store call did not run."""

    reason: str = "native_guard_store_unavailable"


_DatabaseErrorT = TypeVar("_DatabaseErrorT", bound=sqlite3.DatabaseError)


def _failure(error: _DatabaseErrorT, code: int) -> _DatabaseErrorT:
    setattr(error, "sqlite_errorcode", code)  # noqa: B010
    return error


def _unavailable(reason: str) -> NativeGuardStoreUnavailable:
    error = NativeGuardStoreUnavailable(f"Guard store native runtime unavailable ({reason}).")
    error.reason = reason
    return _failure(error, _SQLITE_ERROR)


def unavailable_outbox_status(error: NativeGuardStoreUnavailable) -> dict[str, object]:
    """Report the Review outbox as unavailable; never a locally computed answer.

    The outbox lives behind the native resident. When it cannot answer, status
    surfaces say so explicitly instead of reporting zeroes or a stale snapshot.
    """

    return {
        "outbox_available": False,
        "unavailable_reason": error.reason,
        "state": "unavailable",
        "binding_state": "unavailable",
        "binding_hint": "The native Guard runtime is unavailable, so the Review outbox cannot be read.",
    }


def _raise_for_code(code: object, payload: object) -> None:
    message = payload.get("message") if isinstance(payload, dict) else None
    text = message if isinstance(message, str) else "Guard store operation failed."
    if code == "native_guard_store_value_error":
        raise ValueError(text)
    if code == "native_guard_store_integrity_error":
        raise sqlite3.IntegrityError(text)
    if code == "native_guard_store_busy":
        raise _failure(sqlite3.OperationalError("database is locked"), _SQLITE_BUSY)
    if code == "native_guard_store_sqlite_corrupt":
        raise _failure(sqlite3.DatabaseError("database disk image is malformed"), _SQLITE_CORRUPT)
    if code == "native_guard_store_sqlite_io":
        raise _failure(sqlite3.OperationalError("disk I/O error"), _SQLITE_IOERR)
    if code == "native_guard_store_sqlite_error":
        raise _failure(sqlite3.OperationalError(text), _SQLITE_ERROR)
    reason = code if isinstance(code, str) and _CODE.fullmatch(code) else "native_guard_store_unavailable"
    if code == "native_guard_store_invalid" and isinstance(message, str) and _CODE.fullmatch(message):
        # The resident names the contract violation; keep it for diagnostics.
        reason = message
    raise _unavailable(reason)


def native_guard_store_call(
    *,
    store_path: Path,
    guard_home: Path,
    source: str,
    method: str,
    args: Mapping[str, object],
    deadline_monotonic: float,
) -> tuple[Any, int | None]:
    """Run one store method in the resident; return ``(payload, outbox_generation)``.

    ``deadline_monotonic`` is the caller's operation deadline, fixed before any
    storage-gate wait. The remaining budget is recomputed here, after startup
    work, and bounds both the SQLite busy timeout and the transport wait, so the
    call never outlasts the caller's deadline.
    """

    if not ensure_resident_prerequisite(guard_home):
        raise _unavailable("native_guard_store_prerequisite_unavailable")
    remaining_seconds = deadline_monotonic - time.monotonic()
    if remaining_seconds <= 0:
        raise TimeoutError("Guard storage operation deadline expired.")
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"guard-store-{uuid4().hex}",
        "store_path": str(store_path),
        "guard_home": str(guard_home),
        "method": method,
        "source": source,
        "busy_timeout_ms": max(1, int(remaining_seconds * 1000)),
        "args": dict(args),
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        raise _unavailable("native_guard_store_request_invalid") from None
    remaining_seconds = deadline_monotonic - time.monotonic()
    if remaining_seconds <= 0:
        raise TimeoutError("Guard storage operation deadline expired.")
    response = _resident_request(
        operation="guard_store",
        request=request,
        guard_home=guard_home,
        timeout_seconds=remaining_seconds,
        required_feature=GUARD_STORE_FEATURE,
        response_schema=_RESULT_SCHEMA,
        max_request_bytes=GUARD_STORE_MAX_REQUEST_BYTES + _ENVELOPE_SLACK_BYTES,
        record_success=False,
    )
    identity = native_runtime_status().identity
    if (
        response is None
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        if response is not None and identity is not None:
            native_record_resident_failure(identity.sha256, guard_home, reason="native_guard_store_binding")
        raise _unavailable("native_guard_store_unavailable")
    status, code, payload = response.get("status"), response.get("code"), response.get("payload")
    if identity is not None:
        native_record_resident_success(identity.sha256, guard_home)
    if status == "error":
        _raise_for_code(code, payload)
    generation = response.get("outbox_generation")
    if status != "ok" or code != "ok" or (generation is not None and (type(generation) is not int or generation < 0)):
        raise _unavailable("native_guard_store_response_invalid")
    return payload, generation


__all__ = [
    "GUARD_STORE_FEATURE",
    "NativeGuardStoreUnavailable",
    "native_guard_store_call",
    "unavailable_outbox_status",
]
