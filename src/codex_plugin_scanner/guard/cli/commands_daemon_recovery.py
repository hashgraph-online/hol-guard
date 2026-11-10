"""Strict CLI adapter for user-requested daemon recovery."""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import TextIO

from ..daemon.user_recovery import AuthorizationDecision, RecoveryHooks, UserRecoveryCoordinator
from ..native_recovery_store import (
    RecoveryContractError,
    RecoveryDiagnosticsError,
    load_latest_recovery_snapshot,
    load_recovery_receipt,
    load_recovery_report,
    load_recovery_status,
    persist_recovery_snapshot,
)
from .commands_lifecycle_gate import LifecycleGateContext, validate_lifecycle_gate_context

_RECOVERY_LIFECYCLE_ACTION = "daemon.restart"
_RECOVERY_LIFECYCLE_SCOPE = "local-protection"
_RECOVERY_LIFECYCLE_SUBJECT = "local-daemon"


def _uuid(value: object, *, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError(f"{field}_invalid") from error


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
            snapshot = load_recovery_status(guard_home, operation_id)
            _write_json(snapshot, out)
            return 0
        if command in {"diagnostics", "export"}:
            operation_id = _uuid(getattr(args, "operation_id", None), field="operation_id")
            report = load_recovery_report(guard_home, operation_id)
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
                load_snapshot=load_latest_recovery_snapshot,
                load_receipt=load_recovery_receipt,
                persist_snapshot=persist_recovery_snapshot,
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
