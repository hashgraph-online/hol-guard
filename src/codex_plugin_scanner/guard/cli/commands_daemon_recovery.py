"""Strict CLI adapter for user-requested daemon recovery."""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO, cast

from ..native_daemon_manage import recovery_host_payload
from ..native_recovery_store import (
    RecoveryContractError,
    RecoveryDiagnosticsError,
    load_recovery_report,
    load_recovery_status,
    recovery_runtime_path,
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


def _protection_health(guard_home: Path, args: Mapping[str, object]) -> dict[str, str]:
    """Classify local protection for a verified daemon from the Guard store."""

    remaining = args.get("remaining")
    if not isinstance(remaining, (int, float)) or remaining <= 0:
        return {"state": "unknown", "reason_code": "deadline_exceeded"}
    if not isinstance(args.get("identity"), dict):
        return {"state": "unknown", "reason_code": "unknown"}
    from ..approvals import _canonical_managed_installs_for_health, _live_hook_verification
    from ..runtime.protection_health_runtime import build_runtime_protection_health
    from ..store import GuardStore

    store = GuardStore(guard_home, prime_policy_integrity=False)
    managed_installs = _canonical_managed_installs_for_health(store.list_managed_installs())
    health = build_runtime_protection_health(
        store=store,
        guard_home=guard_home,
        runtime_state=store.get_runtime_state(),
        managed_installs=managed_installs,
        hook_verification=_live_hook_verification(managed_installs, store),
        trust_status=store.get_cached_policy_trust_status(),
        now=datetime.now(timezone.utc),
    )
    state = health.get("state")
    if state == "protected":
        return {"state": "verified", "reason_code": "healthy"}
    if state in {"partial", "degraded"}:
        return {"state": "needs_attention", "reason_code": "unknown"}
    return {"state": "unknown", "reason_code": "unknown"}


def _raise_kind(error: Exception) -> str:
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, OSError):
        return "os"
    if isinstance(error, ImportError):
        return "import"
    if isinstance(error, ValueError):
        return "value"
    if isinstance(error, TypeError):
        return "type"
    if isinstance(error, RuntimeError):
        return "runtime"
    return "other"


def _native_recovery(
    guard_home: Path,
    home_dir: Path | None,
    mode: str,
    *,
    request_id: uuid.UUID | None = None,
    authorize: Callable[[], dict[str, object]] | None = None,
    emit: Callable[[dict[str, object]], None] | None = None,
) -> dict[str, object]:
    """Run one native recovery session.

    The runtime decides every phase and performs every daemon effect; this
    side answers only the lifecycle approval, the protection-health read and
    the output of each snapshot.
    """

    home = Path(guard_home).expanduser().resolve()
    request: dict[str, object] = {
        "schema": "daemon-recovery.v1",
        "mode": mode,
        "guard_home": str(home),
        "active_budget_seconds": 60.0,
        "lock_timeout_seconds": 0.0,
        "can_persist": True,
        "host": recovery_host_payload(home, home_dir=home_dir),
    }
    if request_id is not None:
        request["operation"] = {
            "operation_id": str(request_id),
            "request_id": str(request_id),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "started_monotonic": 0.0,
            "deadline_monotonic": 0.0,
            "sequence": -1,
        }

    def serve(need: str, args: Mapping[str, object]) -> object:
        if need == "authorize":
            if authorize is None:
                return {"allowed": False, "requires_human_action": True, "reason_code": "approval_required"}
            return authorize()
        if need == "protection_health":
            return _protection_health(home, args)
        if need in {"emit", "record"}:
            snapshot = args.get("snapshot")
            if emit is not None and isinstance(snapshot, dict):
                with suppress(Exception):
                    emit(dict(cast(dict[str, object], snapshot)))
            return None
        raise RuntimeError(f"Unknown recovery effect: {need}")

    process = subprocess.Popen(
        [recovery_runtime_path("daemon-recovery-v1"), "daemon-recovery", "--stdin"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
    )
    stdin, stdout = process.stdin, process.stdout
    assert stdin is not None and stdout is not None
    failure: Exception | None = None
    try:
        stdin.write(json.dumps(request) + "\n")
        stdin.flush()
        while True:
            line = stdout.readline()
            if not line:
                raise RuntimeError("Guard daemon recovery runtime stopped unexpectedly.")
            message = cast(object, json.loads(line))
            if not isinstance(message, dict):
                raise RuntimeError("Guard daemon recovery runtime sent an invalid message.")
            message = cast(dict[str, object], message)
            if "need" in message:
                raw_args = message.get("args")
                arguments = cast(Mapping[str, object], raw_args) if isinstance(raw_args, Mapping) else {}
                try:
                    answer: dict[str, object] = {"ok": serve(str(message["need"]), arguments)}
                except Exception as error:
                    failure = error
                    answer = {"raise": _raise_kind(error)}
                stdin.write(json.dumps(answer) + "\n")
                stdin.flush()
                continue
            if message.get("reraise") is True:
                raise failure or RuntimeError("Guard daemon recovery failed.")
            snapshot = message.get("done")
            if not isinstance(snapshot, dict):
                raise RuntimeError("Guard daemon recovery runtime sent no snapshot.")
            return cast(dict[str, object], snapshot)
    finally:
        with suppress(OSError):
            stdin.close()
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        stdout.close()


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
            snapshot = _native_recovery(guard_home, home_dir, "inspect")
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

            def authorize() -> dict[str, object]:
                allowed = (
                    lifecycle_context is not None
                    and _recovery_lifecycle_context_matches(lifecycle_context, guard_home)
                    and validate_lifecycle_gate_context(lifecycle_context)
                )
                if allowed:
                    return {"allowed": True, "requires_human_action": False, "reason_code": "healthy"}
                return {"allowed": False, "requires_human_action": True, "reason_code": "approval_required"}

            emit = (lambda snapshot: _write_json(snapshot, out)) if getattr(args, "json_lines", False) else None
            snapshot = _native_recovery(
                guard_home, home_dir, "run", request_id=request_id, authorize=authorize, emit=emit
            )
            if emit is None:
                _write_human(snapshot, out)
            return _restart_exit_code(snapshot)
        raise ValueError("daemon_recovery_command_invalid")
    except (KeyError, OSError, RuntimeError, ValueError, RecoveryContractError, RecoveryDiagnosticsError) as error:
        err.write(f"HOL Guard recovery failed: {error}\n")
        err.flush()
        return 2


__all__ = ["dispatch_daemon_recovery"]
