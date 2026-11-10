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
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, cast

from .user_recovery_contract import (
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
        return self._native_session("inspect")

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
        snapshot = self._native_session(
            "snapshot",
            fields={
                "operation_id": str(operation.operation_id),
                "sequence": max(0, operation.sequence + 1),
                "started_at": operation.started_at,
                "phase": "waiting_for_owner",
                "active_elapsed_ms": int(max(0.0, self._clock() - operation.started_monotonic) * 1000),
                "worker_active": True,
                "retry_allowed": False,
                "outcome": "pending",
                "reason_code": "operation_busy",
                "service": "unknown",
                "protection": "unknown",
                "requires_human_action": False,
                "checks": [],
            },
        )
        sequence = snapshot["sequence"]
        assert isinstance(sequence, int)
        operation.sequence = sequence
        operation.latest = snapshot
        operation.events.append(snapshot)
        return snapshot

    def _run(self, operation: _Operation, emit: Hook | None) -> dict[str, object]:
        return self._native_session("run", operation=operation, emit=emit)

    def _native_session(
        self,
        mode: str,
        *,
        operation: _Operation | None = None,
        emit: Hook | None = None,
        fields: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        """Run one native recovery session, serving the effects it asks for.

        The native runtime decides every phase, deadline and snapshot; this
        process only performs hooks, holds locks and keeps the registry.
        """

        session = _EffectServer(self, operation, emit)
        request: dict[str, object] = {
            "schema": "daemon-recovery.v1",
            "mode": mode,
            "guard_home": str(self.guard_home),
            "active_budget_seconds": self.active_budget_seconds,
            "lock_timeout_seconds": self.lock_timeout_seconds,
            "can_persist": self.hooks.persist_snapshot is not None,
        }
        if operation is not None:
            request["operation"] = session.operation_payload()
        if fields is not None:
            request["fields"] = dict(fields)
        return session.run(request)

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
            from .manager import guard_recovery_posture

            return guard_recovery_posture(self.guard_home)
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

    @contextmanager
    def _recovery_lock(self, timeout: float):
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
    def _start_lock(self, operation: _Operation, remaining: float):
        if self.hooks.start_lock is not None:
            lock = _call_hook(self.hooks.start_lock, self.guard_home, remaining)
            with cast(Any, lock):
                yield
            return
        with _manager()._guard_daemon_start_lock(self.guard_home, deadline=operation.deadline_monotonic):
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
            guard_home=self.guard_home,
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

    def _durable_snapshot(self) -> dict[str, object]:
        """The persisted snapshot, validated, for the runtime's pending check."""

        if self.hooks.load_snapshot is None:
            return {"kind": "none"}
        try:
            snapshot = _call_hook(self.hooks.load_snapshot, self.guard_home)
        except (OSError, RuntimeError, ValueError, TypeError):
            return {"kind": "unavailable"}
        if snapshot is None:
            return {"kind": "none"}
        if not isinstance(snapshot, Mapping):
            return {"kind": "unavailable"}
        try:
            validated = validate_recovery_snapshot(snapshot, allow_inspection=False)
        except RecoveryContractError:
            return {"kind": "unavailable"}
        return {"kind": "snapshot", "snapshot": validated}

    @staticmethod
    def _missing_inventory_proves_no_owner(inspection: _Inspection) -> bool:
        service = inspection.service
        return (
            service.service == "unavailable"
            and service.reason_code == "service_missing"
            and service.identity is None
            and not service.process_running
        )

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


__all__ = [
    "AuthorizationDecision",
    "ProcessIdentity",
    "ProtectionResult",
    "ReadyResult",
    "RecoveryHooks",
    "ServiceInspection",
    "StartResult",
    "StopResult",
    "UserRecoveryCoordinator",
]


_RECOVERY_FEATURE = "daemon-recovery-v1"
_RAISE_KINDS: tuple[tuple[type[BaseException], str], ...] = (
    (_RecoveryOwnershipTimeoutError, "lock_timeout"),
    (_RecoveryLockUnavailableError, "lock_unavailable"),
    (_RecoveryReceiptUnavailableError, "receipt_unavailable"),
    (TimeoutError, "timeout"),
    (OSError, "os"),
    (ImportError, "import"),
    (ValueError, "value"),
    (TypeError, "type"),
    (RuntimeError, "runtime"),
)


def _raise_kind(error: Exception) -> str:
    for kind, name in _RAISE_KINDS:
        if isinstance(error, kind):
            return name
    return "other"


def _recovery_runtime_path() -> str:
    from ..native_runtime import native_runtime_status

    status = native_runtime_status(deadline_monotonic=time.monotonic() + 10.0)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _RECOVERY_FEATURE not in status.capabilities.features
    ):
        raise RuntimeError("Guard daemon recovery needs the native runtime.")
    return str(status.identity.path)


class _EffectServer:
    """Serve one native recovery session's effect requests.

    Every decision is the runtime's. This side only calls the coordinator's
    hooks, holds the locks it is told to take, and mirrors the operation
    state the runtime reports back.
    """

    def __init__(self, coordinator: UserRecoveryCoordinator, operation: _Operation | None, emit: Hook | None) -> None:
        self._coordinator = coordinator
        self._operation = operation
        self._emit_hook = emit
        self._identities: dict[int, ProcessIdentity] = {}
        self._locks: dict[str, ExitStack] = {}
        self._error: Exception | None = None

    def operation_payload(self) -> dict[str, object]:
        operation = self._operation
        assert operation is not None
        return {
            "operation_id": str(operation.operation_id),
            "request_id": str(operation.request_id),
            "started_at": operation.started_at,
            "started_monotonic": operation.started_monotonic,
            "deadline_monotonic": operation.deadline_monotonic,
            "sequence": operation.sequence,
            "unresolved_owner": operation.unresolved_owner,
            "unresolved_identity": self._identity_payload(operation.unresolved_identity),
        }

    def run(self, request: Mapping[str, object]) -> dict[str, object]:
        import json
        import subprocess

        process = subprocess.Popen(
            [_recovery_runtime_path(), "daemon-recovery", "--stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
        )
        stdin = process.stdin
        stdout = process.stdout
        assert stdin is not None and stdout is not None
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
                self._sync(message.get("state"))
                if "need" in message:
                    answer = self._answer(str(message["need"]), message.get("args"))
                    stdin.write(json.dumps(answer) + "\n")
                    stdin.flush()
                    continue
                if message.get("reraise") is True:
                    if self._error is not None:
                        raise self._error
                    raise RuntimeError("Guard daemon recovery failed.")
                snapshot = message.get("done")
                if not isinstance(snapshot, dict):
                    raise RuntimeError("Guard daemon recovery runtime sent no snapshot.")
                return cast(dict[str, object], snapshot)
        finally:
            for name in list(self._locks):
                self._release(name)
            with suppress(OSError):
                stdin.close()
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            stdout.close()

    def _answer(self, need: str, args: object) -> dict[str, object]:
        arguments = cast(Mapping[str, object], args) if isinstance(args, Mapping) else {}
        try:
            return {"ok": self._serve(need, arguments)}
        except Exception as error:
            self._error = error
            return {"raise": _raise_kind(error)}

    def _serve(self, need: str, args: Mapping[str, object]) -> object:
        coordinator = self._coordinator
        operation = self._operation
        if need == "clock":
            return coordinator._clock()
        if need == "wall":
            return coordinator._now_timestamp()
        if need == "inspect":
            timeout = args.get("timeout")
            inspection = coordinator._inspect(timeout=float(timeout) if isinstance(timeout, (int, float)) else None)
            return self._inspection_payload(inspection)
        if need == "posture":
            return coordinator._protection_posture()
        if need == "update_busy":
            return coordinator._update_busy()
        if need == "authorize":
            decision = coordinator._authorize()
            return {
                "allowed": decision.allowed,
                "requires_human_action": decision.requires_human_action,
                "reason_code": decision.reason_code,
            }
        if need == "user_marker":
            return _current_user_marker()
        if need == "owner_marker":
            from ..live_process_identity import process_owner_marker

            pid = args.get("pid")
            return process_owner_marker(pid) if isinstance(pid, int) else None
        if need == "lock":
            self._lock(str(args.get("name")), float(cast(float, args.get("timeout") or 0.0)))
            return None
        if need == "release":
            self._release(str(args.get("name")))
            return None
        if need == "process_dead":
            return bool(coordinator._process_dead(self._identity(args.get("identity"))))
        if need == "stop":
            identity = self._identity(args.get("identity"))
            stop = _coerce_stop(coordinator._stop_process(identity, self._remaining(args)))
            return {"exit_confirmed": stop.exit_confirmed, "reason_code": stop.reason_code}
        if need == "start":
            start = _coerce_start(coordinator._start_process(self._remaining(args)))
            return {
                "started": start.started,
                "identity": self._identity_payload(start.identity),
                "reason_code": start.reason_code,
            }
        if need == "verify_ready":
            ready = coordinator._verify_ready(self._optional_identity(args.get("identity")), self._remaining(args))
            return {
                "ready": ready.ready,
                "identity": self._identity_payload(ready.identity),
                "reason_code": ready.reason_code,
            }
        if need == "protection_health":
            health = _coerce_protection(
                coordinator._protection_health(self._optional_identity(args.get("identity")), self._remaining(args))
            )
            return {"state": health.state, "reason_code": health.reason_code}
        if need == "load_snapshot":
            return coordinator._durable_snapshot()
        if need == "load_receipt":
            assert operation is not None
            return coordinator._load_request_receipt(operation.request_id)
        snapshot = cast(dict[str, object], args.get("snapshot"))
        if need == "emit":
            assert operation is not None
            operation.latest = snapshot
            operation.events.append(snapshot)
            persist = coordinator.hooks.persist_snapshot
            if args.get("persist") is True and persist is not None:
                _call_hook(persist, coordinator.guard_home, snapshot)
            if self._emit_hook is not None:
                with suppress(Exception):
                    _call_hook(self._emit_hook, dict(snapshot))
            return None
        if need == "record":
            assert operation is not None
            operation.latest = snapshot
            operation.events.append(snapshot)
            coordinator._return_cached(snapshot, self._emit_hook)
            return None
        if need == "expire":
            assert operation is not None
            persist = coordinator.hooks.persist_snapshot
            if persist is None:
                return False
            try:
                _call_hook(persist, coordinator.guard_home, snapshot)
            except Exception:
                return False
            operation.latest = snapshot
            operation.events.append(snapshot)
            return True
        raise RuntimeError(f"Unknown recovery effect: {need}")

    def _lock(self, name: str, timeout: float) -> None:
        stack = ExitStack()
        try:
            if name == "recovery":
                stack.enter_context(self._coordinator._recovery_lock(timeout))
            else:
                assert self._operation is not None
                stack.enter_context(self._coordinator._start_lock(self._operation, timeout))
        except BaseException:
            stack.close()
            raise
        self._locks[name] = stack

    def _release(self, name: str) -> None:
        stack = self._locks.pop(name, None)
        if stack is not None:
            stack.close()

    @staticmethod
    def _remaining(args: Mapping[str, object]) -> float:
        value = args.get("remaining")
        return float(value) if isinstance(value, (int, float)) else 0.0

    def _sync(self, state: object) -> None:
        operation = self._operation
        if operation is None or not isinstance(state, Mapping):
            return
        state = cast(Mapping[str, object], state)
        sequence = state.get("sequence")
        if isinstance(sequence, int):
            operation.sequence = sequence
        for key in ("started_monotonic", "deadline_monotonic"):
            value = state.get(key)
            if isinstance(value, (int, float)):
                setattr(operation, key, float(value))
        operation.unresolved_owner = state.get("unresolved_owner") is True
        operation.unresolved_identity = self._optional_identity(state.get("unresolved_identity"))

    def _identity_payload(self, identity: ProcessIdentity | None) -> dict[str, object] | None:
        if identity is None:
            return None
        handle = id(identity)
        self._identities[handle] = identity
        return {
            "pid": identity.pid,
            "generation": identity.generation,
            "runtime": identity.runtime,
            "guard_home": str(_safe_path(identity.guard_home) or identity.guard_home),
            "user": identity.user,
            "start_marker": identity.start_marker,
            "handle": handle,
        }

    def _optional_identity(self, value: object) -> ProcessIdentity | None:
        if not isinstance(value, Mapping):
            return None
        value = cast(Mapping[str, object], value)
        handle = value.get("handle")
        if isinstance(handle, int) and handle in self._identities:
            return self._identities[handle]
        return _identity_from_value(value, self._coordinator.guard_home)

    def _identity(self, value: object) -> ProcessIdentity:
        identity = self._optional_identity(value)
        if identity is None:
            raise ValueError("Guard daemon recovery identity is missing.")
        return identity

    def _inspection_payload(self, inspection: _Inspection) -> dict[str, object]:
        service = inspection.service
        return {
            "service": {
                "service": service.service,
                "reason_code": service.reason_code,
                "identity": self._identity_payload(service.identity),
                "process_running": service.process_running,
                "authenticated": service.authenticated,
                "dashboard_ready": service.dashboard_ready,
                "protection": service.protection,
                "checks": list(service.checks),
            },
            "posture": inspection.protection_posture,
            "update_busy": inspection.update_busy,
        }
