"""Thin adapter over the native recovery store (`daemon-recovery --stdin`, mode `store`).

The native runtime owns the `hol-guard-recovery.v1` contract, the recovery
state and receipt files, and the diagnostics archive. This module only sends
one request and maps the reply onto the exceptions the CLI already handles.
"""

from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, cast

SCHEMA: Final = "hol-guard-recovery.v1"
DIAGNOSTICS_SCHEMA: Final = "hol-guard-recovery-diagnostics.v1"
DIAGNOSTICS_ARCHIVE_SCHEMA: Final = "hol-guard-recovery-diagnostics-archive.v1"
DIAGNOSTICS_STATE_NAME: Final = "daemon-recovery-diagnostics.json"
MAX_RETAINED_INCIDENTS: Final = 20
MAX_EVENT_BYTES: Final = 16 * 1024
MAX_DIAGNOSTICS_BYTES: Final = 64 * 1024
CHECK_IDS: Final = frozenset(
    {
        "update_idle",
        "protection_posture",
        "process_identity",
        "runtime_identity",
        "authenticated_service",
        "dashboard_ready",
        "protection_health",
    }
)
REASON_CODES: Final = frozenset(
    {
        "healthy",
        "service_missing",
        "service_unresponsive",
        "session_invalid",
        "endpoint_conflict",
        "identity_unverified",
        "runtime_mismatch",
        "multiple_instances",
        "protection_off",
        "approval_required",
        "operation_busy",
        "update_busy",
        "permission_denied",
        "storage_unavailable",
        "startup_failed",
        "deadline_exceeded",
        "worker_exit_unconfirmed",
        "unsupported_protocol",
        "unknown",
    }
)

_STORE_FEATURE: Final = "daemon-recovery-store-v1"
_SESSION_SCHEMA: Final = "daemon-recovery.v1"


class RecoveryContractError(ValueError):
    """Raised when a public recovery payload violates the frozen protocol."""


class RecoveryDiagnosticsError(ValueError):
    """Raised when a local diagnostics payload is not contract-safe."""


def recovery_runtime_path(feature: str = _STORE_FEATURE) -> str:
    from .native_runtime import native_runtime_status

    status = native_runtime_status(deadline_monotonic=time.monotonic() + 10.0)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or feature not in status.capabilities.features
    ):
        raise RuntimeError("Guard daemon recovery needs the native runtime.")
    return str(status.identity.path)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _retention_now() -> datetime | None:
    """The retention clock; `None` lets the runtime read the wall clock."""

    return None


def _store(guard_home: Path | None, op: str, **fields: object) -> object:
    request: dict[str, object] = {"op": op}
    request.update({key: value for key, value in fields.items() if value is not None})
    now = _iso(_retention_now())
    if now is not None and guard_home is not None:
        request["now"] = now
    line = json.dumps(
        {
            "schema": _SESSION_SCHEMA,
            "mode": "store",
            "guard_home": str(guard_home) if guard_home is not None else "",
            "store": request,
        }
    )
    completed = subprocess.run(
        [recovery_runtime_path(), "daemon-recovery", "--stdin"],
        input=line + "\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30.0,
        check=False,
    )
    try:
        reply = cast(object, json.loads(completed.stdout))
    except json.JSONDecodeError as error:
        raise RuntimeError("Guard daemon recovery runtime sent an invalid reply.") from error
    if not isinstance(reply, dict):
        raise RuntimeError("Guard daemon recovery runtime sent an invalid reply.")
    reply = cast(dict[str, object], reply)
    if "done" in reply:
        return reply["done"]
    code = str(reply.get("error", "recovery_store_failed"))
    kind = reply.get("kind")
    if kind == "missing":
        raise KeyError(code)
    if kind == "storage":
        raise OSError(code)
    if kind == "state":
        raise RuntimeError(code)
    if kind == "diagnostics":
        raise RecoveryDiagnosticsError(code)
    raise RecoveryContractError(code)


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError("Guard daemon recovery runtime sent an invalid reply.")
    return cast(dict[str, object], value)


def _optional(value: object) -> dict[str, object] | None:
    return None if value is None else _mapping(value)


def _public(value: object) -> object:
    """Tuples become lists, so a caller's snapshot crosses as JSON."""

    return json.loads(json.dumps(value, default=lambda item: list(item) if isinstance(item, tuple) else str(item)))


def validate_recovery_snapshot(payload: object, *, allow_inspection: bool = True) -> dict[str, object]:
    return _mapping(_store(None, "validate", snapshot=_public(payload), allow_inspection=allow_inspection))


def encode_recovery_event(payload: object) -> bytes:
    snapshot = validate_recovery_snapshot(payload)
    return json.dumps(snapshot, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"


def validate_event_sequence(previous: object, current: object) -> dict[str, object]:
    return _mapping(_store(None, "sequence", previous=_public(previous), snapshot=_public(current)))


def build_recovery_diagnostics(snapshots: object, *, generated_at: datetime | None = None) -> dict[str, object]:
    return _mapping(_store(None, "build_diagnostics", snapshots=_public(snapshots), generated_at=_iso(generated_at)))


def validate_recovery_diagnostics(value: object) -> dict[str, object]:
    return _mapping(_store(None, "validate_diagnostics", report=_public(value)))


def encode_recovery_diagnostics(value: object) -> bytes:
    report = validate_recovery_diagnostics(value)
    return json.dumps(report, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")


def persist_recovery_diagnostics(
    guard_home: Path, snapshots: object, *, generated_at: datetime | None = None
) -> dict[str, object]:
    return _mapping(
        _store(guard_home, "persist_diagnostics", snapshots=_public(snapshots), generated_at=_iso(generated_at))
    )


def load_recovery_diagnostics(guard_home: Path) -> dict[str, object] | None:
    return _optional(_store(guard_home, "load_diagnostics"))


def recovery_diagnostics_for_operation(guard_home: Path, operation_id: str) -> dict[str, object]:
    return _mapping(_store(guard_home, "diagnostics_for", operation_id=operation_id))


def persist_recovery_snapshot(guard_home: Path, snapshot: object) -> None:
    _store(guard_home, "persist", snapshot=_public(snapshot))


def load_latest_recovery_snapshot(guard_home: Path) -> dict[str, object] | None:
    return _optional(_store(guard_home, "latest"))


def load_recovery_receipt(guard_home: Path, operation_id: object) -> dict[str, object] | None:
    return _optional(_store(guard_home, "receipt", operation_id=str(operation_id)))


def load_recovery_status(guard_home: Path, operation_id: object) -> dict[str, object]:
    return _mapping(_store(guard_home, "status", operation_id=str(operation_id)))


def load_recovery_report(guard_home: Path, operation_id: object) -> dict[str, object]:
    return _mapping(_store(guard_home, "diagnostics", operation_id=str(operation_id)))


__all__ = [
    "CHECK_IDS",
    "DIAGNOSTICS_ARCHIVE_SCHEMA",
    "DIAGNOSTICS_SCHEMA",
    "DIAGNOSTICS_STATE_NAME",
    "MAX_DIAGNOSTICS_BYTES",
    "MAX_EVENT_BYTES",
    "MAX_RETAINED_INCIDENTS",
    "REASON_CODES",
    "SCHEMA",
    "RecoveryContractError",
    "RecoveryDiagnosticsError",
    "build_recovery_diagnostics",
    "encode_recovery_diagnostics",
    "encode_recovery_event",
    "load_latest_recovery_snapshot",
    "load_recovery_diagnostics",
    "load_recovery_receipt",
    "load_recovery_report",
    "load_recovery_status",
    "persist_recovery_diagnostics",
    "persist_recovery_snapshot",
    "recovery_diagnostics_for_operation",
    "recovery_runtime_path",
    "validate_event_sequence",
    "validate_recovery_diagnostics",
    "validate_recovery_snapshot",
]
