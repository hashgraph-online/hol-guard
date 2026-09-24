"""Narrow, user-requested Guard daemon recovery coordination.

This module owns the decision sequence for the new recovery operation.  It is
deliberately separate from hook recovery and runtime repair: inspection is
read-only, and a replacement is attempted only after the current process has
been identified and its exit has been confirmed.
"""

from __future__ import annotations

import inspect as _inspect
import os
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, cast

from .user_recovery_contract import (
    CAPABILITIES,
    CHECK_IDS,
    REASON_CODES,
    RecoveryContractError,
    validate_recovery_snapshot,
)

Clock = Callable[[], float]
WallClock = Callable[[], datetime]
Hook = Callable[..., object]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """Private identity evidence for one daemon generation.

    These fields never appear in a public snapshot.  A recovery target must
    retain the same PID, generation, runtime, and Guard home between the
    initial inspection and the stop decision.
    """

    pid: int
    generation: str
    runtime: str
    guard_home: Path
    user: str | None = None
    start_marker: str | None = None


@dataclass(frozen=True, slots=True)
class ServiceInspection:
    """Private result from the authenticated service/process probe."""

    service: str
    reason_code: str
    identity: ProcessIdentity | None = None
    process_running: bool = False
    authenticated: bool = False
    dashboard_ready: bool = False
    protection: str = "unknown"
    checks: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Result of the existing local administrative authorization policy."""

    allowed: bool
    requires_human_action: bool = False
    reason_code: str = "approval_required"


@dataclass(frozen=True, slots=True)
class StopResult:
    """Result of an ownership-checked stop attempt."""

    exit_confirmed: bool
    reason_code: str = "healthy"


@dataclass(frozen=True, slots=True)
class StartResult:
    """Result of launching the already-selected installed runtime."""

    started: bool
    identity: ProcessIdentity | None = None
    reason_code: str = "startup_failed"


@dataclass(frozen=True, slots=True)
class ReadyResult:
    """Authenticated readiness result after a reconnect or start."""

    ready: bool
    identity: ProcessIdentity | None = None
    reason_code: str = "startup_failed"


@dataclass(frozen=True, slots=True)
class ProtectionResult:
    """Fresh protection-health evidence, kept separate from connectivity."""

    state: str
    reason_code: str = "unknown"


@dataclass(frozen=True, slots=True)
class RecoveryHooks:
    """Deterministic seams for Core lifecycle and focused unit tests.

    ``None`` values use the narrow existing daemon helpers.  Hook callables
    may accept the arguments documented by their use below or fewer positional
    arguments; this keeps small test doubles readable without exposing extra
    state through the public DTO.
    """

    clock: Clock | None = None
    wall_clock: WallClock | None = None
    load_state: Hook | None = None
    inspect_service: Hook | None = None
    protection_posture: Hook | None = None
    update_busy: Hook | None = None
    authorize: Hook | None = None
    recovery_lock: Hook | None = None
    start_lock: Hook | None = None
    stop_process: Hook | None = None
    process_dead: Hook | None = None
    start_process: Hook | None = None
    verify_ready: Hook | None = None
    protection_health: Hook | None = None
    load_snapshot: Hook | None = None
    load_receipt: Hook | None = None
    persist_snapshot: Hook | None = None


@dataclass(slots=True)
class _Inspection:
    service: ServiceInspection
    protection_posture: str
    update_busy: bool


@dataclass(slots=True)
class _Operation:
    operation_id: uuid.UUID
    request_id: uuid.UUID
    started_monotonic: float
    deadline_monotonic: float
    started_at: str
    sequence: int = -1
    latest: dict[str, object] | None = None
    events: list[dict[str, object]] = field(default_factory=list)
    execution_active: bool = False
    unresolved_identity: ProcessIdentity | None = None
    unresolved_owner: bool = False


_OPERATIONS_LOCK = RLock()
_ACTIVE_BY_HOME: dict[str, _Operation] = {}
_ACTIVE_BY_ID: dict[tuple[str, str], _Operation] = {}
_COMPLETED_BY_ID: dict[tuple[str, str], _Operation] = {}
_MAX_COMPLETED_OPERATIONS = 64
# Persisted phases after an attempted mutation are only unresolved-work hints.
# A fresh inspected identity and a positive death/containment check are still
# required below. Read-only progress receipts are ignored after the lifecycle
# lock is acquired so a new authenticated request can re-inspect and proceed.
_UNRESOLVED_SNAPSHOT_PHASES = frozenset({"stopping", "starting", "verifying", "failed", "timed_out_waiting"})


class _RecoveryOwnershipTimeoutError(RuntimeError):
    """The cross-process recovery lock could not be acquired in time."""


class _RecoveryLockUnavailableError(RuntimeError):
    """The recovery lock could not be opened for a non-timeout reason."""


class _RecoveryReceiptUnavailableError(RuntimeError):
    """A persisted request receipt could not be trusted or read."""


def _operation_key(home_key: str, operation_id: uuid.UUID | str) -> tuple[str, str]:
    return (home_key, str(operation_id))


def _is_recovery_lock_timeout(error: BaseException) -> bool:
    return isinstance(error, TimeoutError) or (
        isinstance(error, RuntimeError) and str(error) == "Timed out waiting for Guard daemon recovery ownership."
    )


def _manager():
    from . import manager

    return manager


def _call_hook(hook: Hook, *args: object) -> object:
    """Call a seam with the largest positional prefix it accepts."""

    try:
        signature = _inspect.signature(hook)
    except (TypeError, ValueError):
        return hook(*args)
    for count in range(len(args), -1, -1):
        try:
            signature.bind(*args[:count])
        except TypeError:
            continue
        return hook(*args[:count])
    return hook(*args)


def _normal_reason(value: object, fallback: str = "unknown") -> str:
    return value if isinstance(value, str) and value in REASON_CODES else fallback


def _normal_service(value: object) -> str:
    return value if isinstance(value, str) and value in {"unknown", "unavailable", "ready"} else "unknown"


def _normal_protection(value: object) -> str:
    return value if isinstance(value, str) and value in {"unknown", "verified", "needs_attention", "off"} else "unknown"


def _normal_check_result(value: object) -> str:
    return value if isinstance(value, str) and value in {"pass", "fail", "unknown"} else "unknown"


def _safe_path(value: object) -> Path | None:
    if not isinstance(value, (str, Path)):
        return None
    try:
        return Path(value).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def _identity_from_value(value: object, guard_home: Path) -> ProcessIdentity | None:
    if isinstance(value, ProcessIdentity):
        return value
    if not isinstance(value, Mapping):
        return None
    pid = value.get("pid")
    if type(pid) is not int or pid <= 0:
        return None
    generation = value.get("generation", value.get("state_id"))
    runtime = value.get("runtime", value.get("runtime_fingerprint"))
    raw_home = value.get("guard_home")
    candidate_home = _safe_path(raw_home)
    if (
        candidate_home is None
        or not isinstance(generation, str)
        or not generation
        or not isinstance(runtime, str)
        or not runtime
    ):
        return None
    user = value.get("user", value.get("uid"))
    start_marker = value.get("start_marker", value.get("process_start_marker"))
    if not isinstance(user, str) or not user.strip() or not isinstance(start_marker, str) or not start_marker.strip():
        return None
    return ProcessIdentity(
        pid=pid,
        generation=generation,
        runtime=runtime,
        guard_home=candidate_home,
        user=user,
        start_marker=start_marker,
    )


def _current_user_marker() -> str | None:
    from ..live_process_identity import process_owner_marker

    return process_owner_marker(os.getpid())


def _identity_matches(left: ProcessIdentity | None, right: ProcessIdentity | None, guard_home: Path) -> bool:
    if left is None or right is None:
        return False
    try:
        homes_match = left.guard_home.resolve() == right.guard_home.resolve() == guard_home.resolve()
    except (OSError, RuntimeError):
        homes_match = left.guard_home == right.guard_home == guard_home
    if not homes_match or left.pid != right.pid or left.generation != right.generation or left.runtime != right.runtime:
        return False
    if left.start_marker is None or right.start_marker is None or left.start_marker != right.start_marker:
        return False
    if left.user is None or right.user is None or left.user != right.user:
        return False
    if right.user.startswith("sid:"):
        from ..live_process_identity import process_owner_marker

        if process_owner_marker(right.pid) != right.user:
            return False
    return left.user == _current_user_marker()


def _identity_os_evidence_matches(identity: ProcessIdentity) -> bool:
    """Confirm the selected PID still has the persisted generation and owner."""
    from ..live_process_identity import process_owner_marker, process_start_token

    if identity.start_marker is None or identity.user is None:
        return False
    return (
        process_start_token(identity.pid) == identity.start_marker
        and process_owner_marker(identity.pid) == identity.user
    )


def _coerce_service(value: object, guard_home: Path, state: Mapping[str, object] | None) -> ServiceInspection:
    if isinstance(value, ServiceInspection):
        return value
    if value is None:
        return ServiceInspection("unknown", "unknown")
    if isinstance(value, bool):
        return ServiceInspection(
            "ready" if value else "unavailable",
            "healthy" if value else "service_unresponsive",
            _identity_from_value(state, guard_home) if value else None,
            process_running=value,
            authenticated=value,
            dashboard_ready=value,
        )
    if not isinstance(value, Mapping):
        return ServiceInspection("unknown", "unknown")
    identity = _identity_from_value(value.get("identity", state), guard_home)
    service = _normal_service(value.get("service"))
    healthy = value.get("healthy") is True
    if service == "unknown" and healthy:
        service = "ready"
    if service == "unknown" and value.get("process_running") is False:
        service = "unavailable"
    reason = _normal_reason(value.get("reason_code", value.get("reasonCode")))
    if reason == "unknown" and service == "ready":
        reason = "healthy"
    if reason == "unknown" and service == "unavailable":
        reason = "service_unresponsive"
    raw_authenticated = value.get("authenticated")
    authenticated = raw_authenticated if isinstance(raw_authenticated, bool) else service == "ready"
    raw_dashboard_ready = value.get("dashboard_ready")
    dashboard_ready = raw_dashboard_ready if isinstance(raw_dashboard_ready, bool) else service == "ready"
    return ServiceInspection(
        service=service,
        reason_code=reason,
        identity=identity,
        process_running=value.get("process_running") is True or identity is not None,
        authenticated=authenticated,
        dashboard_ready=dashboard_ready,
        protection=_normal_protection(value.get("protection")),
        checks=tuple(_coerce_checks(value.get("checks"))),
    )


def _coerce_checks(value: object) -> list[dict[str, str]]:
    if not isinstance(value, (list, tuple)):
        return []
    checks: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping):
            continue
        check_id = item.get("id")
        if check_id not in CHECK_IDS or check_id in seen:
            continue
        seen.add(cast(str, check_id))
        checks.append(
            {
                "id": cast(str, check_id),
                "result": _normal_check_result(item.get("result")),
                "reasonCode": _normal_reason(item.get("reasonCode")),
            }
        )
    return checks


def _coerce_authorization(value: object) -> AuthorizationDecision:
    if isinstance(value, AuthorizationDecision):
        return value
    if value is True:
        return AuthorizationDecision(True)
    if isinstance(value, Mapping):
        allowed = value.get("allowed") is True
        required = value.get("requires_human_action") is True or value.get("requiresHumanAction") is True
        return AuthorizationDecision(
            allowed, required, _normal_reason(value.get("reason_code", value.get("reasonCode")), "approval_required")
        )
    return AuthorizationDecision(False, True, "approval_required")


def _coerce_stop(value: object) -> StopResult:
    if isinstance(value, StopResult):
        return value
    if value is True:
        return StopResult(True)
    if isinstance(value, Mapping):
        confirmed = value.get("exit_confirmed") is True or value.get("confirmed_exit") is True
        return StopResult(
            confirmed, _normal_reason(value.get("reason_code", value.get("reasonCode")), "worker_exit_unconfirmed")
        )
    return StopResult(False, "worker_exit_unconfirmed")


def _coerce_start(value: object) -> StartResult:
    if isinstance(value, StartResult):
        return value
    if isinstance(value, str) and value:
        return StartResult(True)
    if value is True:
        return StartResult(True)
    if isinstance(value, Mapping):
        started = value.get("started") is True
        return StartResult(
            started,
            _identity_from_value(value.get("identity"), Path.cwd()),
            _normal_reason(value.get("reason_code", value.get("reasonCode")), "startup_failed"),
        )
    return StartResult(False, None, "startup_failed")


def _coerce_ready(value: object) -> ReadyResult:
    if isinstance(value, ReadyResult):
        return value
    if value is True:
        return ReadyResult(True)
    if isinstance(value, Mapping):
        return ReadyResult(
            value.get("ready") is True,
            _identity_from_value(value.get("identity"), Path.cwd()),
            _normal_reason(
                value.get("reason_code", value.get("reasonCode")),
                "healthy" if value.get("ready") is True else "startup_failed",
            ),
        )
    return ReadyResult(False, None, "startup_failed")


def _coerce_protection(value: object) -> ProtectionResult:
    if isinstance(value, ProtectionResult):
        return value
    if value is True:
        return ProtectionResult("verified", "healthy")
    if value is False:
        return ProtectionResult("needs_attention", "unknown")
    if isinstance(value, str):
        return ProtectionResult(_normal_protection(value), "healthy" if value == "verified" else "unknown")
    if isinstance(value, Mapping):
        state = _normal_protection(value.get("state", value.get("protection")))
        return ProtectionResult(state, _normal_reason(value.get("reason_code", value.get("reasonCode"))))
    return ProtectionResult("unknown", "unknown")


def _timestamp(value: object) -> str:
    current = value if isinstance(value, datetime) else _utc_now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.isoformat()


class UserRecoveryCoordinator:
    """Coordinate one bounded, identity-safe user recovery attempt."""

    def __init__(
        self,
        guard_home: Path,
        *,
        home_dir: Path | None = None,
        hooks: RecoveryHooks | None = None,
        dependencies: RecoveryHooks | None = None,
        active_budget_seconds: float = 60.0,
        lock_timeout_seconds: float = 0.0,
    ) -> None:
        self.guard_home = Path(guard_home).expanduser().resolve()
        self.home_dir = Path(home_dir).expanduser().resolve() if home_dir is not None else None
        self.hooks = hooks or dependencies or RecoveryHooks()
        self.active_budget_seconds = max(0.0, float(active_budget_seconds))
        self.lock_timeout_seconds = max(0.0, float(lock_timeout_seconds))

    # Public aliases keep the facade useful to the future CLI/native adapters
    # without moving lifecycle decisions into either adapter.
    def inspect_recovery(self) -> dict[str, object]:
        return self.inspect()

    def begin(self, request_id: str | uuid.UUID | None = None, *, emit: Hook | None = None) -> dict[str, object]:
        return self.restart(request_id=request_id, emit=emit)

    def recover(self, request_id: str | uuid.UUID | None = None, *, emit: Hook | None = None) -> dict[str, object]:
        return self.restart(request_id=request_id, emit=emit)

    def inspect(self) -> dict[str, object]:
        """Return read-only classification without creating files or processes."""

        with _OPERATIONS_LOCK:
            active = _ACTIVE_BY_HOME.get(str(self.guard_home))
            if active is not None:
                return self._active_snapshot(active)
        inspection = self._inspect()
        return self._snapshot(
            operation_id=None,
            sequence=0,
            started_at=self._now_timestamp(),
            phase="checking",
            active_elapsed_ms=0,
            worker_active=False,
            retry_allowed=not inspection.update_busy and inspection.protection_posture == "on",
            outcome="pending",
            reason_code=self._inspection_reason(inspection),
            service=inspection.service.service,
            protection=self._inspection_protection(inspection),
            requires_human_action=inspection.protection_posture == "off"
            or inspection.service.reason_code
            in {"identity_unverified", "runtime_mismatch", "endpoint_conflict", "multiple_instances"},
            checks=self._checks(inspection),
        )

    def status(self, operation_id: str | uuid.UUID) -> dict[str, object]:
        parsed = self._parse_uuid(operation_id, field="operation_id")
        home_key = str(self.guard_home)
        with _OPERATIONS_LOCK:
            operation = _ACTIVE_BY_ID.get(_operation_key(home_key, parsed)) or _COMPLETED_BY_ID.get(
                _operation_key(home_key, parsed)
            )
            latest = operation.latest if operation is not None else None
            if latest is None:
                operation = None
        if operation is None:
            snapshot = self._load_request_receipt(parsed)
            if snapshot is None:
                raise KeyError(str(parsed))
            return dict(snapshot)
        assert latest is not None
        return dict(latest)

    def diagnostics(self, operation_id: str | uuid.UUID) -> dict[str, object]:
        """Return a bounded privacy-safe report for one known operation."""

        parsed = self._parse_uuid(operation_id, field="operation_id")
        home_key = str(self.guard_home)
        with _OPERATIONS_LOCK:
            operation = _ACTIVE_BY_ID.get(_operation_key(home_key, parsed)) or _COMPLETED_BY_ID.get(
                _operation_key(home_key, parsed)
            )
            latest = operation.latest if operation is not None else None
            if latest is None:
                operation = None
            events = list(operation.events) if operation is not None else []
            if operation is not None and not events:
                assert latest is not None
                events = [dict(latest)]
        if not events:
            snapshot = self._load_request_receipt(parsed)
            if snapshot is None:
                raise KeyError(str(parsed))
            events = [dict(snapshot)]
        from .recovery_diagnostics import build_recovery_diagnostics

        return build_recovery_diagnostics(events)

    export_diagnostics = diagnostics

    def restart(self, request_id: str | uuid.UUID | None = None, *, emit: Hook | None = None) -> dict[str, object]:
        parsed_request = self._parse_uuid(request_id, field="request_id") if request_id is not None else uuid.uuid4()
        home_key = str(self.guard_home)
        operation_key = _operation_key(home_key, parsed_request)
        with _OPERATIONS_LOCK:
            active_for_request = _ACTIVE_BY_ID.get(operation_key)
            completed = _COMPLETED_BY_ID.get(operation_key)
            if completed is not None and completed.latest is not None and completed.latest.get("phase") == "complete":
                return self._return_cached(completed.latest, emit)
            if active_for_request is not None and not active_for_request.unresolved_owner:
                return self._return_cached(self._active_snapshot(active_for_request), emit)
        while True:
            with _OPERATIONS_LOCK:
                active = _ACTIVE_BY_HOME.get(home_key)
                unresolved_identity = (
                    active.unresolved_identity if active is not None and active.unresolved_owner else None
                )
                if active is None:
                    break
                if active.execution_active:
                    return self._return_cached(self._active_snapshot(active), emit)
                if not active.unresolved_owner:
                    return self._return_cached(self._active_snapshot(active), emit)
                if unresolved_identity is None:
                    try:
                        inspection = self._inspect()
                    except Exception:
                        inspection = None
                    if inspection is None or not self._missing_inventory_proves_no_owner(inspection):
                        return self._return_cached(self._active_snapshot(active), emit)
                    with _OPERATIONS_LOCK:
                        if _ACTIVE_BY_HOME.get(home_key) is not active:
                            continue
                        self._complete_operation_locked(home_key, active)
                    continue
            try:
                reconciled = bool(self._process_dead(unresolved_identity))
            except (OSError, RuntimeError, TimeoutError):
                reconciled = False
            with _OPERATIONS_LOCK:
                if _ACTIVE_BY_HOME.get(home_key) is not active:
                    continue
                if not reconciled:
                    return self._return_cached(self._active_snapshot(active), emit)
                self._complete_operation_locked(home_key, active)
                break
        with _OPERATIONS_LOCK:
            completed = _COMPLETED_BY_ID.get(operation_key)
            if completed is not None and completed.latest is not None and completed.latest.get("phase") == "complete":
                return self._return_cached(completed.latest, emit)
        started_monotonic = self._clock()
        operation = _Operation(
            operation_id=parsed_request,
            request_id=parsed_request,
            started_monotonic=started_monotonic,
            # The active recovery budget starts only after authorization.  The
            # initial value keeps the operation structurally complete while
            # inspection and approval are still in progress.
            deadline_monotonic=started_monotonic,
            started_at=self._now_timestamp(),
            execution_active=True,
        )
        with _OPERATIONS_LOCK:
            completed = _COMPLETED_BY_ID.get(operation_key)
            if completed is not None and completed.latest is not None and completed.latest.get("phase") == "complete":
                return self._return_cached(completed.latest, emit)
            active = _ACTIVE_BY_HOME.get(home_key)
            if active is not None:
                return self._return_cached(self._active_snapshot(active), emit)
            _ACTIVE_BY_HOME[home_key] = operation
            _ACTIVE_BY_ID[operation_key] = operation
        try:
            return self._run(operation, emit)
        finally:
            with _OPERATIONS_LOCK:
                operation.execution_active = False
                if not operation.unresolved_owner:
                    self._complete_operation_locked(home_key, operation)

    def _complete_operation_locked(self, home_key: str, operation: _Operation) -> None:
        if _ACTIVE_BY_HOME.get(home_key) is operation:
            _ACTIVE_BY_HOME.pop(home_key, None)
        operation_key = _operation_key(home_key, operation.operation_id)
        if _ACTIVE_BY_ID.get(operation_key) is operation:
            _ACTIVE_BY_ID.pop(operation_key, None)
        _COMPLETED_BY_ID[operation_key] = operation
        while len(_COMPLETED_BY_ID) > _MAX_COMPLETED_OPERATIONS:
            _COMPLETED_BY_ID.pop(next(iter(_COMPLETED_BY_ID)))

    def _return_cached(self, snapshot: dict[str, object], emit: Hook | None) -> dict[str, object]:
        result = dict(snapshot)
        if emit is not None:
            with suppress(Exception):
                _call_hook(emit, result)
        return result

    def _active_snapshot(self, operation: _Operation) -> dict[str, object]:
        if operation.latest is not None:
            return operation.latest
        snapshot = self._snapshot(
            operation_id=operation.operation_id,
            sequence=max(0, operation.sequence + 1),
            started_at=operation.started_at,
            phase="waiting_for_owner",
            active_elapsed_ms=int(max(0.0, self._clock() - operation.started_monotonic) * 1000),
            worker_active=True,
            retry_allowed=False,
            outcome="pending",
            reason_code="operation_busy",
            service="unknown",
            protection="unknown",
            requires_human_action=False,
            checks=[],
        )
        sequence = snapshot["sequence"]
        assert isinstance(sequence, int)
        operation.sequence = sequence
        operation.latest = snapshot
        operation.events.append(snapshot)
        return snapshot

    def _replay_receipt(
        self,
        operation: _Operation,
        receipt: dict[str, object],
        emit: Hook | None,
    ) -> dict[str, object]:
        sequence = receipt.get("sequence")
        operation.sequence = sequence if isinstance(sequence, int) else 0
        operation.latest = dict(receipt)
        operation.events.append(dict(receipt))
        return self._return_cached(receipt, emit)

    def _run(self, operation: _Operation, emit: Hook | None) -> dict[str, object]:
        initial = self._inspect()
        self._emit(
            operation,
            emit,
            phase="checking",
            inspection=initial,
            worker_active=True,
            retry_allowed=False,
            persist_snapshot=False,
        )
        if initial.protection_posture != "on":
            return self._finish_action(
                operation,
                emit,
                phase="needs_action",
                inspection=initial,
                reason_code="protection_off" if initial.protection_posture == "off" else "unknown",
                requires_human_action=True,
            )
        if initial.update_busy:
            return self._finish_action(
                operation,
                emit,
                phase="waiting_for_owner",
                inspection=initial,
                reason_code="update_busy",
                worker_active=False,
                retry_allowed=False,
            )
        decision = self._authorize()
        if decision.requires_human_action and not decision.allowed:
            return self._finish_action(
                operation,
                emit,
                phase="awaiting_approval",
                inspection=initial,
                reason_code=decision.reason_code,
                worker_active=False,
                retry_allowed=False,
                requires_human_action=True,
            )
        if not decision.allowed:
            return self._finish_action(
                operation,
                emit,
                phase="needs_action",
                inspection=initial,
                reason_code=decision.reason_code,
                worker_active=False,
                retry_allowed=False,
                requires_human_action=True,
            )
        # Approval and all preflight inspection happen before the active
        # recovery budget.  Reset the single monotonic deadline immediately
        # before waiting on lifecycle ownership.
        self._begin_budget(operation)
        remaining = self._remaining(operation)
        if remaining <= 0.0:
            return self._deadline_exceeded(operation, emit, initial)
        try:
            with self._recovery_lock(operation):
                if self._remaining(operation) <= 0.0:
                    return self._deadline_exceeded(operation, emit, initial)
                try:
                    receipt = self._load_request_receipt(operation.request_id)
                except _RecoveryReceiptUnavailableError:
                    return self._finish_action(
                        operation,
                        emit,
                        phase="failed",
                        inspection=initial,
                        reason_code="unknown",
                        worker_active=True,
                        retry_allowed=False,
                        requires_human_action=True,
                        persist_snapshot=False,
                    )
                if receipt is not None and receipt.get("phase") == "complete":
                    return self._replay_receipt(operation, receipt, emit)
                if receipt is not None and receipt.get("phase") in _UNRESOLVED_SNAPSHOT_PHASES:
                    # A prior mutating request with this UUID is resumable only
                    # for observation/reconciliation.  Even when a fresh
                    # probe proves its old generation inactive, the same UUID
                    # cannot start a new lifecycle mutation; callers must send
                    # a new request ID for intentional retry.
                    current = self._inspect(timeout=self._remaining(operation))
                    if current.service.identity is not None:
                        with suppress(OSError, RuntimeError, TimeoutError):
                            self._process_dead(current.service.identity)
                    sequence = receipt.get("sequence")
                    operation.sequence = sequence if isinstance(sequence, int) else 0
                    operation.latest = dict(receipt)
                    operation.events.append(dict(receipt))
                    return self._return_cached(receipt, emit)
                authorization_failure = self._authorization_failure(operation, emit, initial)
                if authorization_failure is not None:
                    return authorization_failure
                current = self._inspect(timeout=self._remaining(operation))
                pending_snapshot = self._pending_snapshot_state()
                if pending_snapshot == "unavailable":
                    return self._finish_action(
                        operation,
                        emit,
                        phase="failed",
                        inspection=current,
                        reason_code="unknown",
                        worker_active=True,
                        retry_allowed=False,
                        requires_human_action=True,
                        persist_snapshot=False,
                    )
                fresh_ready_identity = current.service.service == "ready" and current.service.identity is not None
                if pending_snapshot == "pending" and not fresh_ready_identity:
                    identity = current.service.identity
                    if identity is None:
                        if self._missing_inventory_proves_no_owner(current):
                            if not self._expire_pending_snapshot(operation):
                                operation.unresolved_owner = True
                                return self._finish_action(
                                    operation,
                                    emit,
                                    phase="failed",
                                    inspection=current,
                                    reason_code="unknown",
                                    worker_active=True,
                                    retry_allowed=False,
                                    requires_human_action=True,
                                    persist_snapshot=False,
                                )
                            pending_snapshot = "none"
                        else:
                            return self._finish_action(
                                operation,
                                emit,
                                phase="waiting_for_owner",
                                inspection=current,
                                reason_code="operation_busy",
                                worker_active=True,
                                retry_allowed=False,
                                persist_snapshot=False,
                            )
                    if pending_snapshot == "pending" and identity is not None:
                        try:
                            reconciled = bool(self._process_dead(identity))
                        except (OSError, RuntimeError, TimeoutError):
                            reconciled = False
                        if not reconciled:
                            return self._finish_action(
                                operation,
                                emit,
                                phase="waiting_for_owner",
                                inspection=current,
                                reason_code="operation_busy",
                                worker_active=True,
                                retry_allowed=False,
                                persist_snapshot=False,
                            )
                        if self._remaining(operation) <= 0.0:
                            return self._deadline_exceeded(operation, emit, current)
                        current = self._inspect(timeout=self._remaining(operation))
                        if not self._missing_inventory_proves_no_owner(current):
                            return self._finish_action(
                                operation,
                                emit,
                                phase="waiting_for_owner",
                                inspection=current,
                                reason_code="operation_busy",
                                worker_active=True,
                                retry_allowed=False,
                                persist_snapshot=False,
                            )
                        if not self._expire_pending_snapshot(operation):
                            operation.unresolved_owner = True
                            return self._finish_action(
                                operation,
                                emit,
                                phase="failed",
                                inspection=current,
                                reason_code="unknown",
                                worker_active=True,
                                retry_allowed=False,
                                requires_human_action=True,
                                persist_snapshot=False,
                            )
                        pending_snapshot = "none"
                self._emit(
                    operation, emit, phase="checking", inspection=current, worker_active=True, retry_allowed=False
                )
                if current.protection_posture != "on":
                    return self._finish_action(
                        operation,
                        emit,
                        phase="needs_action",
                        inspection=current,
                        reason_code="protection_off" if current.protection_posture == "off" else "unknown",
                        requires_human_action=True,
                    )
                if current.update_busy:
                    return self._finish_action(
                        operation,
                        emit,
                        phase="waiting_for_owner",
                        inspection=current,
                        reason_code="update_busy",
                        worker_active=False,
                        retry_allowed=False,
                    )
                if current.service.service == "ready":
                    return self._reconnect(operation, emit, current)
                if current.service.reason_code not in {"service_missing", "service_unresponsive"}:
                    return self._finish_action(
                        operation,
                        emit,
                        phase="needs_action",
                        inspection=current,
                        reason_code=current.service.reason_code,
                        requires_human_action=True,
                    )
                if current.service.reason_code == "service_unresponsive":
                    return self._replace(operation, emit, current)
                return self._start_missing(operation, emit, current)
        except _RecoveryOwnershipTimeoutError:
            return self._finish_action(
                operation,
                emit,
                phase="waiting_for_owner",
                inspection=initial,
                reason_code="operation_busy",
                worker_active=False,
                retry_allowed=False,
                persist_snapshot=False,
            )
        except _RecoveryLockUnavailableError:
            return self._finish_action(
                operation,
                emit,
                phase="failed",
                inspection=initial,
                reason_code="unknown",
                worker_active=False,
                retry_allowed=False,
                requires_human_action=True,
                persist_snapshot=False,
            )
        except Exception:
            return self._finish_action(
                operation,
                emit,
                phase="failed",
                inspection=initial,
                reason_code="unknown",
                worker_active=operation.unresolved_owner,
                retry_allowed=False,
                requires_human_action=True,
                persist_snapshot=False,
            )

    def _reconnect(self, operation: _Operation, emit: Hook | None, inspection: _Inspection) -> dict[str, object]:
        if self._remaining(operation) <= 0.0:
            return self._deadline_exceeded(operation, emit, inspection, worker_active=True)
        self._emit(
            operation,
            emit,
            phase="reconnecting",
            inspection=inspection,
            protection=self._protection_without_fresh_evidence(inspection),
            checks=self._checks_without_fresh_protection(inspection, "unknown"),
            worker_active=True,
            retry_allowed=False,
        )
        ready = self._verify_ready(inspection.service.identity, self._remaining(operation))
        if not ready.ready:
            if ready.reason_code == "deadline_exceeded" or self._remaining(operation) <= 0.0:
                return self._deadline_exceeded(operation, emit, inspection, worker_active=True)
            return self._finish_action(
                operation,
                emit,
                phase="needs_action",
                inspection=inspection,
                reason_code=ready.reason_code,
                protection=self._protection_without_fresh_evidence(inspection),
                checks=self._checks_without_fresh_protection(inspection, ready.reason_code),
                requires_human_action=ready.reason_code in {"session_invalid", "approval_required"},
            )
        if self._remaining(operation) <= 0.0:
            return self._deadline_exceeded(operation, emit, inspection, worker_active=True)
        expected_identity = inspection.service.identity
        ready_identity = ready.identity
        if (
            expected_identity is None
            or ready_identity is None
            or not _identity_matches(expected_identity, ready_identity, self.guard_home)
        ):
            return self._finish_action(
                operation,
                emit,
                phase="needs_action",
                inspection=inspection,
                reason_code="identity_unverified",
                service="ready",
                protection=self._protection_without_fresh_evidence(inspection),
                worker_active=False,
                retry_allowed=True,
                requires_human_action=True,
                checks=self._checks_without_fresh_protection(inspection, "identity_unverified"),
            )
        return self._verify_protection(
            operation,
            emit,
            inspection,
            ready_identity,
            outcome="reconnected",
        )

    def _replace(self, operation: _Operation, emit: Hook | None, inspection: _Inspection) -> dict[str, object]:
        if self._remaining(operation) <= 0.0:
            return self._deadline_exceeded(operation, emit, inspection)
        with self._start_lock_scope(operation, already_held=False):
            if self._remaining(operation) <= 0.0:
                return self._deadline_exceeded(operation, emit, inspection)
            target = inspection.service.identity
            if target is None:
                return self._finish_action(
                    operation,
                    emit,
                    phase="needs_action",
                    inspection=inspection,
                    reason_code="identity_unverified",
                    requires_human_action=True,
                )
            rechecked = self._inspect(timeout=self._remaining(operation))
            if not _identity_matches(target, rechecked.service.identity, self.guard_home):
                return self._finish_action(
                    operation,
                    emit,
                    phase="needs_action",
                    inspection=rechecked,
                    reason_code="identity_unverified",
                    requires_human_action=True,
                )
            precondition_failure = self._mutation_precondition_failure(operation, emit, rechecked)
            if precondition_failure is not None:
                return precondition_failure
            authorization_failure = self._authorization_failure(operation, emit, rechecked)
            if authorization_failure is not None:
                return authorization_failure
            # A final read immediately before the stop protects against PID
            # reuse or generation changes while the progress event is emitted.
            before_stop = self._inspect(timeout=self._remaining(operation))
            if not _identity_matches(target, before_stop.service.identity, self.guard_home):
                return self._finish_action(
                    operation,
                    emit,
                    phase="needs_action",
                    inspection=before_stop,
                    reason_code="identity_unverified",
                    requires_human_action=True,
                )
            precondition_failure = self._mutation_precondition_failure(operation, emit, before_stop)
            if precondition_failure is not None:
                return precondition_failure
            self._emit(
                operation, emit, phase="stopping", inspection=before_stop, worker_active=True, retry_allowed=False
            )
            if self._remaining(operation) <= 0.0:
                return self._deadline_exceeded(operation, emit, before_stop)
            last_before_stop = _Inspection(
                before_stop.service,
                self._protection_posture(),
                self._update_busy(),
            )
            precondition_failure = self._mutation_precondition_failure(operation, emit, last_before_stop)
            if precondition_failure is not None:
                return precondition_failure
            authorization_failure = self._authorization_failure(operation, emit, last_before_stop)
            if authorization_failure is not None:
                return authorization_failure
            operation.unresolved_owner = True
            operation.unresolved_identity = target
            try:
                stop = _coerce_stop(self._stop_process(target, self._remaining(operation)))
            except (OSError, RuntimeError, TimeoutError):
                stop = StopResult(False, "worker_exit_unconfirmed")
            stop_deadline_exceeded = stop.reason_code == "deadline_exceeded"
            if stop_deadline_exceeded or not stop.exit_confirmed:
                try:
                    exited = bool(_call_hook(self._process_dead, target))
                except (OSError, RuntimeError, TimeoutError):
                    exited = False
                if not exited:
                    return self._timeout(operation, emit, before_stop)
            operation.unresolved_owner = False
            operation.unresolved_identity = None
            if stop_deadline_exceeded:
                return self._deadline_exceeded(operation, emit, before_stop)
            if self._remaining(operation) <= 0.0:
                return self._deadline_exceeded(operation, emit, before_stop)
            after_stop = self._inspect(timeout=self._remaining(operation))
            if after_stop.service.identity is not None and not _identity_matches(
                target,
                after_stop.service.identity,
                self.guard_home,
            ):
                return self._finish_action(
                    operation,
                    emit,
                    phase="needs_action",
                    inspection=after_stop,
                    reason_code="identity_unverified",
                    requires_human_action=True,
                )
            if after_stop.service.reason_code != "service_missing":
                return self._finish_action(
                    operation,
                    emit,
                    phase="needs_action",
                    inspection=after_stop,
                    reason_code=after_stop.service.reason_code,
                    requires_human_action=True,
                )
            return self._start_after_stop(operation, emit, after_stop, outcome="restarted")

    def _start_missing(self, operation: _Operation, emit: Hook | None, inspection: _Inspection) -> dict[str, object]:
        if self._remaining(operation) <= 0.0:
            return self._deadline_exceeded(operation, emit, inspection)
        with self._start_lock_scope(operation, already_held=False):
            if self._remaining(operation) <= 0.0:
                return self._deadline_exceeded(operation, emit, inspection)
            rechecked = self._inspect(timeout=self._remaining(operation))
            if rechecked.service.service == "ready":
                return self._reconnect(operation, emit, rechecked)
            if rechecked.service.reason_code != "service_missing":
                return self._finish_action(
                    operation,
                    emit,
                    phase="needs_action",
                    inspection=rechecked,
                    reason_code=rechecked.service.reason_code,
                    requires_human_action=True,
                )
            precondition_failure = self._mutation_precondition_failure(operation, emit, rechecked)
            if precondition_failure is not None:
                return precondition_failure
            authorization_failure = self._authorization_failure(operation, emit, rechecked)
            if authorization_failure is not None:
                return authorization_failure
            self._emit(operation, emit, phase="starting", inspection=rechecked, worker_active=True, retry_allowed=False)
            if self._remaining(operation) <= 0.0:
                return self._deadline_exceeded(operation, emit, rechecked)
            last_before_start = _Inspection(
                rechecked.service,
                self._protection_posture(),
                self._update_busy(),
            )
            precondition_failure = self._mutation_precondition_failure(operation, emit, last_before_start)
            if precondition_failure is not None:
                return precondition_failure
            authorization_failure = self._authorization_failure(operation, emit, last_before_start)
            if authorization_failure is not None:
                return authorization_failure
            operation.unresolved_owner = True
            operation.unresolved_identity = None
            try:
                started = _coerce_start(self._start_process(self._remaining(operation)))
            except (OSError, RuntimeError, TimeoutError):
                return self._finish_action(
                    operation,
                    emit,
                    phase="failed",
                    inspection=last_before_start,
                    reason_code="startup_failed",
                    service="unknown",
                    protection=self._protection_without_fresh_evidence(last_before_start),
                    worker_active=True,
                    retry_allowed=False,
                    requires_human_action=True,
                    checks=self._checks_without_fresh_protection(last_before_start, "startup_failed"),
                )
            if not started.started:
                operation.unresolved_owner = False
                operation.unresolved_identity = None
                return self._finish_action(
                    operation,
                    emit,
                    phase="failed",
                    inspection=last_before_start,
                    reason_code=started.reason_code,
                    protection=self._protection_without_fresh_evidence(last_before_start),
                    checks=self._checks_without_fresh_protection(last_before_start, started.reason_code),
                    requires_human_action=True,
                )
            if self._remaining(operation) <= 0.0:
                return self._deadline_exceeded(operation, emit, rechecked, worker_active=started.started)
            return self._start_after_stop(operation, emit, rechecked, outcome="started", started=started)

    def _start_after_stop(
        self,
        operation: _Operation,
        emit: Hook | None,
        inspection: _Inspection,
        *,
        outcome: str,
        started: StartResult | None = None,
    ) -> dict[str, object]:
        if started is None:
            if self._remaining(operation) <= 0.0:
                return self._deadline_exceeded(operation, emit, inspection)
            current = _Inspection(
                inspection.service,
                self._protection_posture(),
                self._update_busy(),
            )
            precondition_failure = self._mutation_precondition_failure(operation, emit, current)
            if precondition_failure is not None:
                return precondition_failure
            authorization_failure = self._authorization_failure(operation, emit, current)
            if authorization_failure is not None:
                return authorization_failure
            self._emit(
                operation, emit, phase="starting", inspection=inspection, worker_active=True, retry_allowed=False
            )
            if self._remaining(operation) <= 0.0:
                return self._deadline_exceeded(operation, emit, inspection)
            last_before_start = _Inspection(
                inspection.service,
                self._protection_posture(),
                self._update_busy(),
            )
            precondition_failure = self._mutation_precondition_failure(operation, emit, last_before_start)
            if precondition_failure is not None:
                return precondition_failure
            authorization_failure = self._authorization_failure(operation, emit, last_before_start)
            if authorization_failure is not None:
                return authorization_failure
            operation.unresolved_owner = True
            operation.unresolved_identity = None
            try:
                started = _coerce_start(self._start_process(self._remaining(operation)))
            except (OSError, RuntimeError, TimeoutError):
                return self._finish_action(
                    operation,
                    emit,
                    phase="failed",
                    inspection=last_before_start,
                    reason_code="startup_failed",
                    service="unknown",
                    protection=self._protection_without_fresh_evidence(last_before_start),
                    worker_active=True,
                    retry_allowed=False,
                    requires_human_action=True,
                    checks=self._checks_without_fresh_protection(last_before_start, "startup_failed"),
                )
            if not started.started:
                operation.unresolved_owner = False
                operation.unresolved_identity = None
                return self._finish_action(
                    operation,
                    emit,
                    phase="failed",
                    inspection=last_before_start,
                    reason_code=started.reason_code,
                    protection=self._protection_without_fresh_evidence(last_before_start),
                    checks=self._checks_without_fresh_protection(last_before_start, started.reason_code),
                    requires_human_action=True,
                )
            if self._remaining(operation) <= 0.0:
                return self._deadline_exceeded(operation, emit, inspection, worker_active=started.started)
        elif self._remaining(operation) <= 0.0:
            return self._deadline_exceeded(operation, emit, inspection, worker_active=started.started)
        if started is not None and started.started:
            operation.unresolved_owner = True
            operation.unresolved_identity = started.identity
        if self._remaining(operation) <= 0.0:
            return self._deadline_exceeded(operation, emit, inspection, worker_active=True)
        self._emit(
            operation,
            emit,
            phase="reconnecting",
            inspection=inspection,
            protection=self._protection_without_fresh_evidence(inspection),
            checks=self._checks_without_fresh_protection(inspection, "unknown"),
            worker_active=True,
            retry_allowed=False,
            # After a successful start, retain the persisted ``starting``
            # receipt until readiness is proven.  ``reconnecting`` is a
            # read-only receipt and cannot prove ownership if final timeout
            # persistence fails or the worker crashes at this point.
            persist_snapshot=False,
        )
        if self._remaining(operation) <= 0.0:
            return self._deadline_exceeded(operation, emit, inspection, worker_active=True)
        identity = started.identity if started is not None else None
        try:
            ready = self._verify_ready(identity, self._remaining(operation))
        except (ImportError, OSError, RuntimeError, TimeoutError, TypeError, ValueError):
            ready = ReadyResult(False, None, "startup_failed")
        if not ready.ready:
            if ready.reason_code == "deadline_exceeded" or self._remaining(operation) <= 0.0:
                return self._deadline_exceeded(operation, emit, inspection, worker_active=True)
            return self._finish_action(
                operation,
                emit,
                phase="failed",
                inspection=inspection,
                reason_code=ready.reason_code,
                service="unknown",
                protection=self._protection_without_fresh_evidence(inspection),
                worker_active=True,
                retry_allowed=False,
                requires_human_action=True,
                checks=self._checks_without_fresh_protection(inspection, ready.reason_code),
            )
        if self._remaining(operation) <= 0.0:
            return self._deadline_exceeded(operation, emit, inspection, worker_active=True)
        expected_identity = identity
        ready_identity = ready.identity
        if (
            expected_identity is None
            or ready_identity is None
            or not _identity_matches(expected_identity, ready_identity, self.guard_home)
        ):
            operation.unresolved_owner = True
            # Keep ownership bound to the generation this request actually
            # launched. A different readiness identity is evidence of an
            # unverifiable handoff, never a target to adopt or terminate.
            operation.unresolved_identity = expected_identity
            return self._finish_action(
                operation,
                emit,
                phase="needs_action",
                inspection=inspection,
                reason_code="identity_unverified",
                service="unknown",
                protection=self._protection_without_fresh_evidence(inspection),
                worker_active=True,
                retry_allowed=False,
                requires_human_action=True,
                checks=self._checks_without_fresh_protection(inspection, "identity_unverified"),
            )
        return self._verify_protection(
            operation,
            emit,
            inspection,
            ready_identity,
            outcome=outcome,
        )

    def _verify_protection(
        self,
        operation: _Operation,
        emit: Hook | None,
        inspection: _Inspection,
        identity: ProcessIdentity | None,
        *,
        outcome: str,
    ) -> dict[str, object]:
        if self._remaining(operation) <= 0.0:
            return self._deadline_exceeded(operation, emit, inspection, worker_active=True)
        self._emit(
            operation,
            emit,
            phase="verifying",
            inspection=inspection,
            protection=self._protection_without_fresh_evidence(inspection),
            checks=self._checks_without_fresh_protection(inspection, "unknown"),
            worker_active=True,
            retry_allowed=False,
        )
        if self._remaining(operation) <= 0.0:
            return self._deadline_exceeded(operation, emit, inspection, worker_active=True)
        try:
            protection = _coerce_protection(self._protection_health(identity, self._remaining(operation)))
        except (OSError, RuntimeError, TimeoutError):
            protection = ProtectionResult("unknown", "unknown")
        if self._remaining(operation) <= 0.0:
            return self._deadline_exceeded(
                operation,
                emit,
                inspection,
                worker_active=True,
                fresh_protection=protection,
            )
        checks = self._checks(inspection)
        self._set_check(checks, "authenticated_service", "pass", "healthy")
        self._set_check(checks, "dashboard_ready", "pass", "healthy")
        self._set_check(
            checks,
            "protection_health",
            "pass"
            if protection.state == "verified"
            else ("fail" if protection.state == "needs_attention" else "unknown"),
            protection.reason_code,
        )
        if protection.state != "verified":
            operation.unresolved_owner = False
            operation.unresolved_identity = None
            return self._finish_action(
                operation,
                emit,
                phase="needs_action",
                inspection=inspection,
                reason_code=_normal_reason(protection.reason_code),
                service="ready",
                protection=protection.state,
                worker_active=False,
                retry_allowed=True,
                requires_human_action=True,
                checks=checks,
            )
        operation.unresolved_owner = False
        operation.unresolved_identity = None
        final = self._emit(
            operation,
            emit,
            phase="complete",
            inspection=inspection,
            reason_code="healthy",
            service="ready",
            protection=protection.state,
            outcome=outcome,
            worker_active=False,
            retry_allowed=True,
            requires_human_action=protection.state == "needs_attention",
            checks=checks,
        )
        return final

    def _finish_action(
        self,
        operation: _Operation,
        emit: Hook | None,
        *,
        phase: str,
        inspection: _Inspection,
        reason_code: str,
        worker_active: bool = False,
        retry_allowed: bool = True,
        requires_human_action: bool = False,
        service: str | None = None,
        protection: str | None = None,
        outcome: str = "not_recovered",
        checks: list[dict[str, str]] | None = None,
        persist_snapshot: bool = True,
    ) -> dict[str, object]:
        return self._emit(
            operation,
            emit,
            phase=phase,
            inspection=inspection,
            reason_code=reason_code,
            service=service or inspection.service.service,
            protection=protection or self._inspection_protection(inspection),
            outcome=outcome,
            worker_active=worker_active,
            retry_allowed=retry_allowed,
            requires_human_action=requires_human_action,
            checks=checks,
            persist_snapshot=persist_snapshot,
        )

    def _timeout(self, operation: _Operation, emit: Hook | None, inspection: _Inspection) -> dict[str, object]:
        operation.unresolved_owner = True
        return self._finish_action(
            operation,
            emit,
            phase="timed_out_waiting",
            inspection=inspection,
            reason_code="worker_exit_unconfirmed",
            service="unknown",
            protection="unknown",
            worker_active=True,
            retry_allowed=False,
            requires_human_action=True,
        )

    def _deadline_exceeded(
        self,
        operation: _Operation,
        emit: Hook | None,
        inspection: _Inspection,
        *,
        worker_active: bool = False,
        fresh_protection: ProtectionResult | None = None,
    ) -> dict[str, object]:
        if worker_active:
            operation.unresolved_owner = True
            if operation.unresolved_identity is None:
                operation.unresolved_identity = inspection.service.identity
        checks = self._checks(inspection)
        if fresh_protection is None:
            protection = self._protection_without_fresh_evidence(inspection)
            self._set_check(checks, "protection_health", "unknown", "deadline_exceeded")
        else:
            protection = _normal_protection(fresh_protection.state)
            if protection == "verified":
                health_result = "pass"
            elif protection == "needs_attention":
                health_result = "fail"
            else:
                health_result = "unknown"
            self._set_check(checks, "protection_health", health_result, fresh_protection.reason_code)
        return self._finish_action(
            operation,
            emit,
            phase="failed",
            inspection=inspection,
            reason_code="deadline_exceeded",
            service="unknown" if not worker_active else inspection.service.service,
            protection=protection,
            worker_active=worker_active,
            retry_allowed=False,
            requires_human_action=True,
            checks=checks,
        )

    def _emit(
        self,
        operation: _Operation,
        emit: Hook | None,
        *,
        phase: str,
        inspection: _Inspection,
        worker_active: bool,
        retry_allowed: bool,
        reason_code: str | None = None,
        service: str | None = None,
        protection: str | None = None,
        outcome: str = "pending",
        requires_human_action: bool = False,
        checks: list[dict[str, str]] | None = None,
        persist_snapshot: bool = True,
    ) -> dict[str, object]:
        operation.sequence += 1
        snapshot = self._snapshot(
            operation_id=operation.operation_id,
            sequence=operation.sequence,
            started_at=operation.started_at,
            phase=phase,
            active_elapsed_ms=int(max(0.0, self._clock() - operation.started_monotonic) * 1000),
            worker_active=worker_active,
            retry_allowed=retry_allowed,
            outcome=outcome,
            reason_code=reason_code or self._inspection_reason(inspection),
            service=service or inspection.service.service,
            protection=protection or self._inspection_protection(inspection),
            requires_human_action=requires_human_action,
            checks=checks if checks is not None else self._checks(inspection),
        )
        operation.latest = snapshot
        operation.events.append(snapshot)
        if persist_snapshot and self.hooks.persist_snapshot is not None:
            _call_hook(self.hooks.persist_snapshot, self.guard_home, snapshot)
        if emit is not None:
            with suppress(Exception):
                _call_hook(emit, snapshot)
        return snapshot

    def _snapshot(
        self,
        *,
        operation_id: uuid.UUID | None,
        sequence: int,
        started_at: str,
        phase: str,
        active_elapsed_ms: int,
        worker_active: bool,
        retry_allowed: bool,
        outcome: str,
        reason_code: str,
        service: str,
        protection: str,
        requires_human_action: bool,
        checks: list[dict[str, str]],
    ) -> dict[str, object]:
        now = self._now_timestamp()
        payload: dict[str, object] = {
            "schema": "hol-guard-recovery.v1",
            "capabilities": sorted(CAPABILITIES),
            "operationId": str(operation_id) if operation_id is not None else None,
            "sequence": max(0, int(sequence)),
            "startedAt": started_at,
            "updatedAt": now,
            "phase": phase,
            "activeElapsedMs": max(0, int(active_elapsed_ms)),
            "workerActive": bool(worker_active),
            "retryAllowed": bool(retry_allowed),
            "outcome": outcome,
            "reasonCode": _normal_reason(reason_code),
            "service": _normal_service(service),
            "protection": _normal_protection(protection),
            "requiresHumanAction": bool(requires_human_action),
            "checks": _coerce_checks(checks),
        }
        try:
            return validate_recovery_snapshot(payload, allow_inspection=operation_id is None)
        except RecoveryContractError:
            # Internal callers should never expose an invalid event.  Fall back
            # to a conservative, contract-valid unknown snapshot if a test hook
            # supplied an unsupported value.
            payload["phase"] = "needs_action"
            payload["outcome"] = "not_recovered"
            payload["service"] = "unknown"
            payload["protection"] = "unknown"
            payload["reasonCode"] = "unknown"
            payload["workerActive"] = False
            payload["retryAllowed"] = False
            payload["requiresHumanAction"] = True
            payload["checks"] = []
            return validate_recovery_snapshot(payload, allow_inspection=operation_id is None)

    def _inspect(self, *, timeout: float | None = None) -> _Inspection:
        state = self._load_state()
        posture = self._protection_posture()
        update_busy = self._update_busy()
        service = self._inspect_service(state, timeout=timeout)
        return _Inspection(service, posture, update_busy)

    def _load_state(self) -> Mapping[str, object] | None:
        hook = self.hooks.load_state
        if hook is not None:
            value = _call_hook(hook, self.guard_home)
            return value if isinstance(value, Mapping) else None
        try:
            value = _manager().load_authenticated_daemon_state(self.guard_home)
        except (OSError, RuntimeError, ValueError):
            return None
        return value if isinstance(value, Mapping) else None

    def _inspect_service(
        self,
        state: Mapping[str, object] | None,
        *,
        timeout: float | None = None,
    ) -> ServiceInspection:
        if self.hooks.inspect_service is not None:
            return _coerce_service(
                _call_hook(self.hooks.inspect_service, self.guard_home, state, timeout), self.guard_home, state
            )
        return _default_inspect_service(
            self.guard_home,
            state,
            timeout=1.0 if timeout is None else max(0.0, timeout),
        )

    def _protection_posture(self) -> str:
        if self.hooks.protection_posture is not None:
            value = _call_hook(self.hooks.protection_posture, self.guard_home)
            return value if isinstance(value, str) and value in {"on", "off", "unknown"} else "unknown"
        try:
            from .recovery_lifecycle import guard_recovery_is_disabled

            return "off" if guard_recovery_is_disabled(self.guard_home) else "on"
        except (OSError, RuntimeError, ValueError):
            return "unknown"

    def _update_busy(self) -> bool:
        if self.hooks.update_busy is not None:
            return _call_hook(self.hooks.update_busy, self.guard_home) is True
        try:
            from .dashboard_update import dashboard_update_in_progress

            return bool(dashboard_update_in_progress(self.guard_home))
        except (OSError, RuntimeError, ValueError):
            return True

    def _authorize(self) -> AuthorizationDecision:
        if self.hooks.authorize is None:
            # T02 does not own the proof transport. A trusted CLI/native
            # caller must provide the existing lifecycle authorization.
            return AuthorizationDecision(False, True, "approval_required")
        return _coerce_authorization(_call_hook(self.hooks.authorize, self.guard_home))

    def _authorization_failure(
        self,
        operation: _Operation,
        emit: Hook | None,
        inspection: _Inspection,
    ) -> dict[str, object] | None:
        decision = self._authorize()
        if decision.allowed:
            return None
        return self._finish_action(
            operation,
            emit,
            phase="awaiting_approval" if decision.requires_human_action else "needs_action",
            inspection=inspection,
            reason_code=decision.reason_code,
            worker_active=False,
            retry_allowed=False,
            requires_human_action=True,
        )

    def _mutation_precondition_failure(
        self,
        operation: _Operation,
        emit: Hook | None,
        inspection: _Inspection,
    ) -> dict[str, object] | None:
        if self._remaining(operation) <= 0.0:
            return self._deadline_exceeded(operation, emit, inspection)
        if inspection.protection_posture != "on":
            return self._finish_action(
                operation,
                emit,
                phase="needs_action",
                inspection=inspection,
                reason_code="protection_off" if inspection.protection_posture == "off" else "unknown",
                requires_human_action=True,
            )
        if inspection.update_busy:
            return self._finish_action(
                operation,
                emit,
                phase="waiting_for_owner",
                inspection=inspection,
                reason_code="update_busy",
                worker_active=False,
                retry_allowed=False,
            )
        return None

    @contextmanager
    def _recovery_lock(self, operation: _Operation):
        timeout = min(self._remaining(operation), self.lock_timeout_seconds)
        if self.hooks.recovery_lock is not None:
            try:
                lock = _call_hook(self.hooks.recovery_lock, self.guard_home, timeout)
            except (OSError, TimeoutError, RuntimeError) as error:
                if _is_recovery_lock_timeout(error):
                    raise _RecoveryOwnershipTimeoutError from error
                raise _RecoveryLockUnavailableError from error
            entered = False
            try:
                with cast(Any, lock):
                    entered = True
                    yield
            except (OSError, TimeoutError, RuntimeError) as error:
                if not entered and _is_recovery_lock_timeout(error):
                    raise _RecoveryOwnershipTimeoutError from error
                if not entered:
                    raise _RecoveryLockUnavailableError from error
                raise
            return
        entered = False
        try:
            with _manager()._guard_daemon_recovery_lock(
                self.guard_home,
                timeout_seconds=timeout,
            ):
                entered = True
                yield
        except (OSError, TimeoutError, RuntimeError) as error:
            if not entered and _is_recovery_lock_timeout(error):
                raise _RecoveryOwnershipTimeoutError from error
            if not entered:
                raise _RecoveryLockUnavailableError from error
            raise

    @contextmanager
    def _start_lock(self, operation: _Operation):
        remaining = self._remaining(operation)
        if self.hooks.start_lock is not None:
            lock = _call_hook(self.hooks.start_lock, self.guard_home, remaining)
            with cast(Any, lock):
                yield
            return
        with _manager()._guard_daemon_start_lock(self.guard_home, deadline=operation.deadline_monotonic):
            yield

    @contextmanager
    def _start_lock_scope(self, operation: _Operation, *, already_held: bool):
        if already_held:
            with nullcontext():
                yield
            return
        with self._start_lock(operation):
            yield

    def _stop_process(self, identity: ProcessIdentity, remaining: float) -> object:
        if remaining <= 0.0:
            return StopResult(False, "deadline_exceeded")
        if (
            identity.start_marker is None
            or not identity.start_marker
            or identity.user is None
            or identity.user != _current_user_marker()
        ):
            return False
        if self.hooks.stop_process is not None:
            return _call_hook(self.hooks.stop_process, identity, remaining)
        manager = _manager()
        from ..live_process_identity import process_owner_marker, process_start_token

        if process_start_token(identity.pid) != identity.start_marker:
            return False
        if process_owner_marker(identity.pid) != identity.user:
            return False
        expected_creation_time = None
        if identity.start_marker.startswith("windows:"):
            try:
                expected_creation_time = int(identity.start_marker.removeprefix("windows:"))
            except ValueError:
                return False
        return manager._retire_guard_daemon_pid(
            identity.pid,
            expected_guard_home=self.guard_home,
            expected_creation_time=expected_creation_time,
            expected_start_marker=identity.start_marker,
            timeout=remaining,
        )

    def _process_dead(self, identity: ProcessIdentity) -> object:
        if self.hooks.process_dead is not None:
            return _call_hook(self.hooks.process_dead, identity)
        return _manager()._guard_daemon_pid_is_proven_dead(identity.pid)

    def _start_process(self, remaining: float) -> object:
        if remaining <= 0.0:
            return StartResult(False, None, "deadline_exceeded")
        if self.hooks.start_process is not None:
            return _call_hook(self.hooks.start_process, self.guard_home, remaining)
        manager = _manager()
        # A verified dead generation may leave a signed tombstone.  Clearing
        # that one record is the narrow state transition needed before a fresh
        # start; no runtime selector or hook configuration is changed.
        if self._load_state() is not None:
            manager.clear_guard_daemon_state(self.guard_home)
        daemon_url = manager.ensure_guard_daemon(
            self.guard_home,
            home_dir=self.home_dir,
            start_timeout=max(0.0, remaining),
        )
        if not isinstance(daemon_url, str) or not daemon_url:
            return StartResult(False, None, "startup_failed")
        try:
            authenticated_state = manager.load_authenticated_daemon_state(self.guard_home)
        except (AttributeError, OSError, RuntimeError, ValueError):
            # The launch succeeded, but its authenticated generation is not
            # available. Retain ownership of the attempted start; the caller
            # must not adopt or terminate a process by URL alone.
            return StartResult(True, None, "identity_unverified")
        identity = _identity_from_value(authenticated_state, self.guard_home)
        if identity is None:
            return StartResult(True, None, "identity_unverified")
        try:
            if identity.guard_home.resolve() != self.guard_home.resolve():
                return StartResult(True, None, "identity_unverified")
        except (OSError, RuntimeError, ValueError):
            return StartResult(True, None, "identity_unverified")
        return StartResult(True, identity)

    def _verify_ready(self, identity: ProcessIdentity | None, remaining: float) -> ReadyResult:
        if remaining <= 0.0:
            return ReadyResult(False, None, "deadline_exceeded")
        if self.hooks.verify_ready is not None:
            return _coerce_ready(_call_hook(self.hooks.verify_ready, self.guard_home, identity, remaining))
        service = _default_inspect_service(
            self.guard_home,
            self._load_state(),
            timeout=max(0.0, remaining),
        )
        ready = service.service == "ready" and service.authenticated and service.dashboard_ready
        return ReadyResult(
            ready,
            service.identity,
            "healthy" if ready else service.reason_code,
        )

    def _protection_health(self, identity: ProcessIdentity | None, remaining: float) -> object:
        if remaining <= 0.0:
            return ProtectionResult("unknown", "deadline_exceeded")
        if self.hooks.protection_health is not None:
            return _call_hook(self.hooks.protection_health, self.guard_home, identity, remaining)
        if identity is None or remaining <= 0:
            return ProtectionResult("unknown", "unknown")
        from ..approvals import _canonical_managed_installs_for_health, _live_hook_verification
        from ..runtime.protection_health_runtime import build_runtime_protection_health
        from ..store import GuardStore

        store = GuardStore(self.guard_home, prime_policy_integrity=False)
        managed_installs = _canonical_managed_installs_for_health(store.list_managed_installs())
        runtime_state = store.get_runtime_state()
        health = build_runtime_protection_health(
            store=store,
            runtime_state=runtime_state,
            managed_installs=managed_installs,
            hook_verification=_live_hook_verification(managed_installs, store),
            trust_status=store.get_cached_policy_trust_status(),
            now=_utc_now(),
        )
        state = health.get("state")
        if state == "protected":
            return ProtectionResult("verified", "healthy")
        if state in {"partial", "degraded"}:
            return ProtectionResult("needs_attention", "unknown")
        return ProtectionResult("unknown", "unknown")

    def _clock(self) -> float:
        return (self.hooks.clock or time.monotonic)()

    def _begin_budget(self, operation: _Operation) -> None:
        operation.started_monotonic = self._clock()
        operation.deadline_monotonic = operation.started_monotonic + self.active_budget_seconds

    def _pending_snapshot_state(self) -> str:
        if self.hooks.load_snapshot is None:
            return "none"
        try:
            snapshot = _call_hook(self.hooks.load_snapshot, self.guard_home)
        except (OSError, RuntimeError, ValueError, TypeError):
            return "unavailable"
        if snapshot is None:
            return "none"
        if not isinstance(snapshot, Mapping):
            return "unavailable"
        try:
            snapshot = validate_recovery_snapshot(snapshot, allow_inspection=False)
        except RecoveryContractError:
            return "unavailable"
        if snapshot.get("workerActive") is True and snapshot.get("retryAllowed") is False:
            phase = snapshot.get("phase")
            if phase in _UNRESOLVED_SNAPSHOT_PHASES:
                return "pending"
        return "none"

    @staticmethod
    def _missing_inventory_proves_no_owner(inspection: _Inspection) -> bool:
        service = inspection.service
        return (
            service.service == "unavailable"
            and service.reason_code == "service_missing"
            and service.identity is None
            and not service.process_running
        )

    def _expire_pending_snapshot(self, operation: _Operation) -> bool:
        if self.hooks.persist_snapshot is None:
            return False
        snapshot = self._snapshot(
            operation_id=operation.operation_id,
            sequence=max(0, operation.sequence + 1),
            started_at=operation.started_at,
            phase="needs_action",
            active_elapsed_ms=int(max(0.0, self._clock() - operation.started_monotonic) * 1000),
            worker_active=False,
            retry_allowed=False,
            outcome="not_recovered",
            reason_code="unknown",
            service="unknown",
            protection="unknown",
            requires_human_action=True,
            checks=[],
        )
        try:
            _call_hook(self.hooks.persist_snapshot, self.guard_home, snapshot)
        except Exception:
            return False
        sequence = snapshot["sequence"]
        assert isinstance(sequence, int)
        operation.sequence = sequence
        operation.latest = snapshot
        operation.events.append(snapshot)
        return True

    def _load_request_receipt(self, operation_id: uuid.UUID) -> dict[str, object] | None:
        """Load one validated durable record as a replay hint.

        The receipt is intentionally limited to a public DTO.  It is consulted
        only after fresh authorization and lifecycle ownership are held; it
        cannot establish process identity, protection, or approval.
        """

        if self.hooks.load_receipt is None:
            return None
        try:
            raw = _call_hook(self.hooks.load_receipt, self.guard_home, operation_id)
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            raise _RecoveryReceiptUnavailableError("recovery_receipt_unavailable") from error
        if raw is None:
            return None
        if not isinstance(raw, Mapping):
            raise _RecoveryReceiptUnavailableError("recovery_receipt_invalid")
        candidate = raw.get("snapshot", raw)
        if not isinstance(candidate, Mapping):
            raise _RecoveryReceiptUnavailableError("recovery_receipt_invalid")
        try:
            snapshot = validate_recovery_snapshot(candidate, allow_inspection=False)
        except RecoveryContractError as error:
            raise _RecoveryReceiptUnavailableError("recovery_receipt_invalid") from error
        if snapshot.get("operationId") != str(operation_id):
            raise _RecoveryReceiptUnavailableError("recovery_receipt_mismatch")
        return snapshot

    def _now_timestamp(self) -> str:
        return _timestamp((self.hooks.wall_clock or _utc_now)())

    def _remaining(self, operation: _Operation) -> float:
        return max(0.0, operation.deadline_monotonic - self._clock())

    def _inspection_reason(self, inspection: _Inspection) -> str:
        if inspection.protection_posture == "off":
            return "protection_off"
        if inspection.update_busy:
            return "update_busy"
        return _normal_reason(inspection.service.reason_code)

    def _inspection_protection(self, inspection: _Inspection) -> str:
        if inspection.protection_posture == "off":
            return "off"
        return _normal_protection(inspection.service.protection)

    def _checks(self, inspection: _Inspection) -> list[dict[str, str]]:
        checks = _coerce_checks(inspection.service.checks)
        self._set_check(
            checks,
            "update_idle",
            "fail" if inspection.update_busy else "pass",
            "update_busy" if inspection.update_busy else "healthy",
        )
        posture_result = (
            "fail"
            if inspection.protection_posture == "off"
            else ("pass" if inspection.protection_posture == "on" else "unknown")
        )
        self._set_check(
            checks, "protection_posture", posture_result, "protection_off" if posture_result == "fail" else "healthy"
        )
        identity_result = "pass" if inspection.service.identity is not None else "unknown"
        self._set_check(checks, "process_identity", identity_result, inspection.service.reason_code)
        self._set_check(checks, "runtime_identity", identity_result, inspection.service.reason_code)
        self._set_check(
            checks,
            "authenticated_service",
            "pass" if inspection.service.authenticated else "unknown",
            inspection.service.reason_code,
        )
        self._set_check(
            checks,
            "dashboard_ready",
            "pass" if inspection.service.dashboard_ready else "unknown",
            inspection.service.reason_code,
        )
        protection = self._inspection_protection(inspection)
        self._set_check(
            checks,
            "protection_health",
            "pass" if protection == "verified" else ("fail" if protection == "needs_attention" else "unknown"),
            inspection.service.reason_code,
        )
        return checks

    def _checks_without_fresh_protection(self, inspection: _Inspection, reason_code: str) -> list[dict[str, str]]:
        checks = self._checks(inspection)
        self._set_check(checks, "protection_health", "unknown", reason_code)
        return checks

    def _protection_without_fresh_evidence(self, inspection: _Inspection) -> str:
        observed = self._inspection_protection(inspection)
        return observed if observed in {"off", "needs_attention"} else "unknown"

    @staticmethod
    def _set_check(checks: list[dict[str, str]], check_id: str, result: str, reason_code: str) -> None:
        entry = {"id": check_id, "result": _normal_check_result(result), "reasonCode": _normal_reason(reason_code)}
        for index, check in enumerate(checks):
            if check["id"] == check_id:
                checks[index] = entry
                return
        checks.append(entry)

    @staticmethod
    def _parse_uuid(value: str | uuid.UUID, *, field: str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        if isinstance(value, str):
            try:
                parsed = uuid.UUID(value)
            except ValueError as error:
                raise ValueError(f"{field} must be a UUID") from error
            if str(parsed) != value.lower():
                raise ValueError(f"{field} must be a canonical UUID")
            return parsed
        raise ValueError(f"{field} must be a UUID")


def _default_inspect_service(
    guard_home: Path,
    state: Mapping[str, object] | None,
    *,
    timeout: float = 1.0,
) -> ServiceInspection:
    manager = _manager()
    if state is None:
        try:
            inventory = manager._running_guard_daemon_processes_for_guard_home(guard_home)
        except (OSError, RuntimeError, ValueError):
            inventory = []
        if len(inventory) > 1:
            return ServiceInspection("unavailable", "multiple_instances")
        if inventory:
            return ServiceInspection("unavailable", "identity_unverified")
        return ServiceInspection("unavailable", "service_missing")
    identity = _identity_from_value(state, guard_home)
    if identity is None:
        return ServiceInspection("unavailable", "identity_unverified")
    if _safe_path(state.get("guard_home")) not in {None, guard_home.resolve()}:
        return ServiceInspection("unavailable", "identity_unverified", identity, process_running=True)
    try:
        if not manager._guard_daemon_state_matches_current_runtime(dict(state)):
            return ServiceInspection("unavailable", "runtime_mismatch", identity, process_running=True)
        if not manager._guard_daemon_pid_is_running(identity.pid):
            return ServiceInspection("unavailable", "service_missing", identity)
        command_identity = manager._guard_daemon_pid_command_identity(identity.pid, expected_guard_home=guard_home)
        if command_identity is False:
            return ServiceInspection("unavailable", "endpoint_conflict", identity, process_running=True)
        if command_identity is not True:
            return ServiceInspection("unavailable", "identity_unverified", identity, process_running=True)
        if not _identity_os_evidence_matches(identity):
            return ServiceInspection("unavailable", "identity_unverified", identity, process_running=True)
        from .live_identity import probe_live_guard_daemon_identity

        live, live_reason = probe_live_guard_daemon_identity(
            guard_home,
            session_timeout=min(1.0, max(0.0, timeout)),
        )
    except (OSError, RuntimeError, ValueError):
        live, live_reason = None, "service_unresponsive"
    if live is None:
        return ServiceInspection("unavailable", "service_unresponsive", identity, process_running=True)
    live_identity = _identity_from_value(live, guard_home) or identity
    if not _identity_os_evidence_matches(live_identity):
        return ServiceInspection("unavailable", "identity_unverified", live_identity, process_running=True)
    if live_reason != "healthy":
        return ServiceInspection(
            "ready",
            live_reason,
            live_identity,
            process_running=True,
            authenticated=True,
            dashboard_ready=False,
        )
    return ServiceInspection(
        "ready",
        "healthy",
        live_identity,
        process_running=True,
        authenticated=True,
        dashboard_ready=True,
    )


def inspect_recovery(guard_home: Path, **kwargs: object) -> dict[str, object]:
    """Functional facade for read-only capability inspection."""

    return UserRecoveryCoordinator(guard_home, **cast(dict[str, Any], kwargs)).inspect()


def restart_guard(guard_home: Path, request_id: str | uuid.UUID | None = None, **kwargs: object) -> dict[str, object]:
    """Functional facade for one bounded user recovery attempt."""

    return UserRecoveryCoordinator(guard_home, **cast(dict[str, Any], kwargs)).restart(request_id=request_id)


RecoveryCoordinator = UserRecoveryCoordinator
CoordinatorHooks = RecoveryHooks

__all__ = [
    "AuthorizationDecision",
    "CoordinatorHooks",
    "ProcessIdentity",
    "ProtectionResult",
    "ReadyResult",
    "RecoveryCoordinator",
    "RecoveryHooks",
    "ServiceInspection",
    "StartResult",
    "StopResult",
    "UserRecoveryCoordinator",
    "inspect_recovery",
    "restart_guard",
]
