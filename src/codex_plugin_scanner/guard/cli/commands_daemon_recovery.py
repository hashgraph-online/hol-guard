"""Strict CLI adapter for user-requested daemon recovery."""

from __future__ import annotations

import hashlib
import json
import sys
import uuid
from contextlib import suppress
from pathlib import Path
from typing import TextIO

from ..daemon.recovery_diagnostics import (
    RecoveryDiagnosticsError,
    build_recovery_diagnostics,
    load_recovery_diagnostics,
    persist_recovery_diagnostics,
    recovery_diagnostics_for_operation,
)
from ..daemon.user_recovery import AuthorizationDecision, RecoveryHooks, UserRecoveryCoordinator
from ..daemon.user_recovery_contract import (
    RecoveryContractError,
    encode_recovery_event,
    validate_recovery_snapshot,
)
from ..native_command_control_authority_io import read_private_state, write_private_state
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from .commands_lifecycle_gate import LifecycleGateContext, validate_lifecycle_gate_context

_STATE_NAME = "daemon-user-recovery.json"
_MAX_STATE_BYTES = 16 * 1024
_RECEIPT_NAME = "daemon-user-recovery-receipts.json"
_MAX_RECEIPT_BYTES = 64 * 1024
_MAX_RECEIPTS = 64
_RECEIPT_SCHEMA = "hol-guard-recovery.receipts.v1"
_RECEIPT_PHASES = frozenset({"stopping", "starting", "verifying", "timed_out_waiting", "complete"})
_RECOVERY_LIFECYCLE_ACTION = "daemon.restart"
_RECOVERY_LIFECYCLE_SCOPE = "local-protection"
_RECOVERY_LIFECYCLE_SUBJECT = "local-daemon"


def _uuid(value: object, *, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError(f"{field}_invalid") from error


def _receipt_home_key(guard_home: Path) -> str:
    canonical = str(Path(guard_home).expanduser().resolve())
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_receipt_records(guard_home: Path) -> list[dict[str, object]]:
    payload = read_private_state(guard_home, _RECEIPT_NAME, _MAX_RECEIPT_BYTES)
    if payload is None:
        return []
    try:
        decoded = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise RuntimeError("recovery_receipt_invalid") from error
    if (
        not isinstance(decoded, dict)
        or decoded.get("schema") != _RECEIPT_SCHEMA
        or decoded.get("homeKey") != _receipt_home_key(guard_home)
    ):
        raise RuntimeError("recovery_receipt_invalid")
    raw_records = decoded.get("records")
    if not isinstance(raw_records, list) or len(raw_records) > _MAX_RECEIPTS:
        raise RuntimeError("recovery_receipt_invalid")
    records: list[dict[str, object]] = []
    for raw_record in raw_records:
        if not isinstance(raw_record, dict):
            raise RuntimeError("recovery_receipt_invalid")
        try:
            operation_id = _uuid(raw_record.get("operationId"), field="operation_id")
            snapshot = validate_recovery_snapshot(raw_record.get("snapshot"), allow_inspection=False)
        except (ValueError, RecoveryContractError) as error:
            raise RuntimeError("recovery_receipt_invalid") from error
        if snapshot.get("operationId") != str(operation_id):
            raise RuntimeError("recovery_receipt_invalid")
        records.append({"operationId": str(operation_id), "snapshot": snapshot})
    return records


def _load_receipt(guard_home: Path, operation_id: uuid.UUID) -> dict[str, object] | None:
    for record in _load_receipt_records(guard_home):
        if record["operationId"] == str(operation_id):
            snapshot = record["snapshot"]
            assert isinstance(snapshot, dict)
            return snapshot
    return None


def _persist_receipt(guard_home: Path, snapshot: dict[str, object]) -> None:
    records = _load_receipt_records(guard_home)
    operation_id = str(snapshot["operationId"])
    records = [record for record in records if record["operationId"] != operation_id]
    records.append({"operationId": operation_id, "snapshot": snapshot})
    records = records[-_MAX_RECEIPTS:]
    while True:
        encoded = json.dumps(
            {
                "schema": _RECEIPT_SCHEMA,
                "homeKey": _receipt_home_key(guard_home),
                "records": records,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) <= _MAX_RECEIPT_BYTES or len(records) <= 1:
            break
        records.pop(0)
    write_private_state(guard_home, _RECEIPT_NAME, encoded, _MAX_RECEIPT_BYTES)


def _persist_snapshot(guard_home: Path, snapshot: object) -> None:
    validated = validate_recovery_snapshot(snapshot, allow_inspection=False)
    if validated.get("phase") in _RECEIPT_PHASES:
        _persist_receipt(guard_home, validated)
    payload = encode_recovery_event(validated)
    write_private_state(guard_home, _STATE_NAME, payload, _MAX_STATE_BYTES)
    # Diagnostics are best effort and never change the recovery outcome.  The
    # report itself is written through the same owner-private atomic helper.
    try:
        previous = load_recovery_diagnostics(guard_home)
        previous_events = previous.get("events") if previous is not None else None
        if (
            previous is not None
            and previous.get("operationId") == validated.get("operationId")
            and isinstance(previous_events, list)
        ):
            events = [*previous_events, validated]
        else:
            events = [validated]
        persist_recovery_diagnostics(guard_home, events)
    except (OSError, NativePolicySnapshotError, RecoveryDiagnosticsError):
        return


def _load_snapshot(guard_home: Path, operation_id: uuid.UUID) -> dict[str, object]:
    snapshot = _load_latest_snapshot(guard_home)
    if snapshot is not None and snapshot["operationId"] == str(operation_id):
        return snapshot
    receipt = _load_receipt(guard_home, operation_id)
    if receipt is not None:
        return receipt
    raise KeyError(str(operation_id))


def _load_latest_snapshot(guard_home: Path) -> dict[str, object] | None:
    payload = read_private_state(guard_home, _STATE_NAME, _MAX_STATE_BYTES)
    if payload is None:
        return None
    try:
        decoded = json.loads(payload)
        snapshot = validate_recovery_snapshot(decoded, allow_inspection=False)
    except (json.JSONDecodeError, UnicodeDecodeError, RecoveryContractError) as error:
        raise RuntimeError("recovery_state_invalid") from error
    return snapshot


def _load_diagnostics(guard_home: Path, operation_id: uuid.UUID) -> dict[str, object]:
    try:
        return recovery_diagnostics_for_operation(guard_home, str(operation_id))
    except KeyError:
        pass
    except (OSError, NativePolicySnapshotError, RecoveryDiagnosticsError):
        # An archive is an optional projection of the mandatory operation
        # record.  Rebuild a bounded report from that record when the archive
        # is malformed, unavailable, or fails its owner-private integrity
        # checks.  The exception text never crosses this boundary.
        pass
    snapshot = _load_snapshot(guard_home, operation_id)
    report = build_recovery_diagnostics(snapshot)
    with suppress(OSError, NativePolicySnapshotError, RecoveryDiagnosticsError):
        persist_recovery_diagnostics(guard_home, [snapshot])
    return report


def _write_json(payload: dict[str, object], stream: TextIO) -> None:
    stream.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    stream.flush()


def _restart_exit_code(snapshot: dict[str, object]) -> int:
    if snapshot["phase"] == "complete":
        return 0
    if snapshot["phase"] == "waiting_for_owner" or snapshot["workerActive"] is True:
        return 3
    if snapshot["requiresHumanAction"] is True or snapshot["phase"] in {"awaiting_approval", "needs_action"}:
        return 2
    return 1


def _write_human(snapshot: dict[str, object], stream: TextIO) -> None:
    stream.write(
        "HOL Guard recovery\n"
        f"  Operation: {snapshot['operationId']}\n"
        f"  Phase: {snapshot['phase']}\n"
        f"  Service: {snapshot['service']}\n"
        f"  Protection: {snapshot['protection']}\n"
        f"  Result: {snapshot['outcome']} ({snapshot['reasonCode']})\n"
    )
    stream.flush()


def _recovery_lifecycle_context_matches(
    context: LifecycleGateContext,
    guard_home: Path,
) -> bool:
    try:
        authority_home = Path(context.authority_home).expanduser().resolve()
        expected_home = Path(guard_home).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    return (
        authority_home == expected_home
        and context.action == _RECOVERY_LIFECYCLE_ACTION
        and context.scope == _RECOVERY_LIFECYCLE_SCOPE
        and context.subject == _RECOVERY_LIFECYCLE_SUBJECT
    )


def dispatch_daemon_recovery(
    args: object,
    *,
    guard_home: Path,
    home_dir: Path | None,
    lifecycle_authorized: bool = False,
    lifecycle_context: LifecycleGateContext | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Dispatch the frozen recovery protocol without legacy fallbacks."""

    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    command = getattr(args, "daemon_recovery_command", None)
    try:
        if command == "inspect":
            snapshot = UserRecoveryCoordinator(guard_home, home_dir=home_dir).inspect()
            _write_json(snapshot, out)
            return 0
        if command == "status":
            operation_id = _uuid(getattr(args, "operation_id", None), field="operation_id")
            snapshot = _load_snapshot(guard_home, operation_id)
            _write_json(snapshot, out)
            return 0
        if command in {"diagnostics", "export"}:
            operation_id = _uuid(getattr(args, "operation_id", None), field="operation_id")
            report = _load_diagnostics(guard_home, operation_id)
            # Keep the export machine-readable and free of human/error text.
            _write_json(report, out)
            return 0
        if command == "restart":
            request_value = getattr(args, "request_id", None)
            request_id = _uuid(request_value, field="request_id") if request_value else uuid.uuid4()

            def authorize(_home: Path) -> AuthorizationDecision:
                if lifecycle_context is None or not _recovery_lifecycle_context_matches(
                    lifecycle_context,
                    guard_home,
                ):
                    return AuthorizationDecision(False, True, "approval_required")
                if validate_lifecycle_gate_context(lifecycle_context):
                    return AuthorizationDecision(True)
                return AuthorizationDecision(False, True, "approval_required")

            hooks = RecoveryHooks(
                authorize=authorize,
                load_snapshot=_load_latest_snapshot,
                load_receipt=_load_receipt,
                persist_snapshot=_persist_snapshot,
            )
            coordinator = UserRecoveryCoordinator(guard_home, home_dir=home_dir, hooks=hooks)
            emit = (lambda snapshot: _write_json(snapshot, out)) if getattr(args, "json_lines", False) else None
            snapshot = coordinator.restart(request_id=request_id, emit=emit)
            if emit is None:
                _write_human(snapshot, out)
            return _restart_exit_code(snapshot)
        raise ValueError("daemon_recovery_command_invalid")
    except (KeyError, OSError, RuntimeError, ValueError, RecoveryContractError, RecoveryDiagnosticsError) as error:
        err.write(f"HOL Guard recovery failed: {error}\n")
        err.flush()
        return 2


__all__ = ["dispatch_daemon_recovery"]
