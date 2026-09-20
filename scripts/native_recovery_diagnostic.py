"""Bounded observations of actual calls during installed resident recovery."""

from __future__ import annotations

import json
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from math import isfinite
from time import perf_counter as _clock
from typing import Any

from scripts.native_slo_adapter import Observation
from scripts.native_slo_contract import MAX_INSTALLED_ADAPTER_P95_MS, SAFE_ROUTE_NAMES, assert_privacy_safe

_PHASES = (
    "authenticated_adapter",
    "identity_read",
    "identity_challenge",
    "identity_verification",
    "workspace_readiness",
    "worker_dispatch",
    "worker_round_trip",
    "publisher_attempt",
    "publisher_context",
    "publisher_controls",
)
_COUNTERS = ("workers", "ready", "busy", "target", "timeouts", "failures", "restarts")
_ERRORS = frozenset(
    {
        "native_policy_authority_changed_during_publish",
        "native_policy_snapshot_resident_changed",
        "native_cloud_policy_changed_during_publish",
        "native_command_control_binding_changed",
        "native_policy_snapshot_inputs_changed",
        "native_policy_snapshot_ack_invalid",
        "native_client_deadline_exceeded",
        "native_client_timed_out",
        "native_resident_start_in_progress",
        "native_resident_start_timeout",
    }
)
_MAX_COUNT = 999
_MAX_MS = 999_999.0


def _milliseconds(seconds: object) -> float | None:
    if (type(seconds) is not float and type(seconds) is not int) or not isfinite(seconds) or seconds < 0:
        return None
    return round(min(_MAX_MS, float(seconds) * 1_000), 3)


def _sample_clock() -> float | None:
    with suppress(BaseException):
        value = _clock()
        if type(value) in {float, int} and isfinite(value):
            return float(value)
    return None


def _bounded_count(value: object) -> int | None:
    return min(_MAX_COUNT, max(0, value)) if type(value) is int else None


def _publisher_state(publisher: object) -> dict[str, object]:
    result: dict[str, object] = {"available": False}
    with suppress(BaseException):
        values = vars(publisher)
        error = values.get("_last_error")
        result = {
            "available": True,
            "acked": values.get("_acked") if type(values.get("_acked")) is bool else None,
            "epoch": _bounded_count(values.get("_epoch")),
            "failures": _bounded_count(values.get("_failure_count")),
            "error": "missing" if error is None else error if type(error) is str and error in _ERRORS else "other",
        }
    return result


def _worker_state(runner: object) -> dict[str, object]:
    result: dict[str, object] = {"available": False}
    with suppress(BaseException):
        stats = getattr(runner, "stats", None)
        values = stats() if callable(stats) else None
        if type(values) is dict:
            result = {"available": True, **{key: _bounded_count(values.get(key)) for key in _COUNTERS}}
    return result


class RecoveryObservation:
    """Record only finite counters and timings, never arguments or results."""

    def __init__(self, session: object) -> None:
        self._lock = threading.Lock()
        self._active = False
        self._owner = threading.get_ident()
        self._worker_local = threading.local()
        self._phases: dict[str, dict[str, int | float]] = {
            phase: {"started": 0, "completed": 0, "raised": 0, "elapsed_ms": 0.0, "max_ms": 0.0, "invalid_clock": 0}
            for phase in _PHASES
        }
        daemon = getattr(session, "daemon", None)
        server = getattr(daemon, "_server", None)
        self._worker = getattr(server, "hook_worker", None)
        self._runner = getattr(server, "hook_process_runner", None)
        self._publisher = getattr(self._worker, "policy_snapshot_publisher", None)
        self._worker_before: dict[str, object] = {"available": False}
        self._publisher_before: dict[str, object] = {"available": False}

    def begin(self) -> None:
        """Begin after the original measurement clock, including this overhead."""
        with suppress(BaseException):
            self._worker_before = _worker_state(self._runner)
            self._publisher_before = _publisher_state(self._publisher)
            with self._lock:
                self._active = True

    def _wrap(self, phase: str, original: Callable[..., Any], allowed: Callable[[], bool]) -> Callable[..., Any]:
        def observed(*args: Any, **kwargs: Any) -> Any:
            __tracebackhide__ = True
            measured = False
            started = None
            with suppress(BaseException):
                with self._lock:
                    measured = self._active and allowed()
                    if measured:
                        self._phases[phase]["started"] = min(_MAX_COUNT, self._phases[phase]["started"] + 1)
                if measured:
                    started = _sample_clock()
            previous_depth = getattr(self._worker_local, "depth", 0)
            if phase == "worker_dispatch":
                self._worker_local.depth = previous_depth + 1
            raised = False
            try:
                return original(*args, **kwargs)
            except BaseException:
                raised = True
                raise
            finally:
                if phase == "worker_dispatch":
                    self._worker_local.depth = previous_depth
                if measured:
                    with suppress(BaseException):
                        ended = _sample_clock()
                        elapsed = _milliseconds(ended - started) if ended is not None and started is not None else None
                        with self._lock:
                            values = self._phases[phase]
                            values["completed"] = min(_MAX_COUNT, values["completed"] + 1)
                            values["raised"] = min(_MAX_COUNT, values["raised"] + int(raised))
                            values["invalid_clock"] = min(_MAX_COUNT, values["invalid_clock"] + int(elapsed is None))
                            if elapsed is not None:
                                values["elapsed_ms"] = min(_MAX_MS, values["elapsed_ms"] + elapsed)
                                values["max_ms"] = max(values["max_ms"], elapsed)

        return observed

    @contextmanager
    def attach(self) -> Iterator[None]:
        """Observe existing scoped calls and restore exact prior bindings."""
        from codex_plugin_scanner.guard.adapters import claude_daemon_hook_transport as transport
        from codex_plugin_scanner.guard.daemon import hook_process_slot_review as slots
        from scripts import native_slo_session

        def owner_thread() -> bool:
            return threading.get_ident() == self._owner

        def worker_thread() -> bool:
            return getattr(self._worker_local, "depth", 0) > 0

        targets = (
            (native_slo_session, "authenticated_claude_hook_response", "authenticated_adapter", owner_thread),
            (transport, "_authenticated_state", "identity_read", owner_thread),
            (transport, "_request_identity_challenge", "identity_challenge", owner_thread),
            (transport, "_verify_challenge_response", "identity_verification", owner_thread),
            (self._worker, "prepare_workspace_policy", "workspace_readiness", lambda: True),
            (self._runner, "review", "worker_dispatch", lambda: True),
            (slots, "_send_review_to_slot", "worker_round_trip", worker_thread),
            (self._publisher, "_publish_once", "publisher_attempt", lambda: True),
            (self._publisher, "_publication_context", "publisher_context", lambda: True),
            (self._publisher, "_compiled_command_extensions", "publisher_controls", lambda: True),
        )
        missing = object()
        installed: list[tuple[Any, str, object, object]] = []
        try:
            for target, name, phase, allowed in targets:
                with suppress(BaseException):
                    original = getattr(target, name, None)
                    if not callable(original):
                        continue
                    previous = vars(target).get(name, missing)
                    wrapped = self._wrap(phase, original, allowed)
                    setattr(target, name, wrapped)
                    installed.append((target, name, previous, wrapped))
            yield
        finally:
            with self._lock:
                self._active = False
            for target, name, previous, wrapped in reversed(installed):
                with suppress(BaseException):
                    if vars(target).get(name) is wrapped:
                        if previous is missing:
                            delattr(target, name)
                        else:
                            setattr(target, name, previous)

    def finish(
        self, *, index: int, rearmed: bool, elapsed_ms: float, response: Observation | None
    ) -> dict[str, object]:
        """Read bounded observations after the unchanged measurement ends."""
        with self._lock:
            self._active = False
            phases = {key: dict(value) for key, value in self._phases.items()}
        report = assert_privacy_safe(
            {
                "schema": "guard.native-recovery-observation.v1",
                "mode": "explicitly_rearmed" if rearmed else "autonomous",
                "sample": min(_MAX_COUNT, max(0, index)),
                "elapsed_ms": _milliseconds(elapsed_ms / 1_000),
                "outcome": "raised" if response is None else "returned",
                "allowed": None if response is None else response.allowed is True,
                "route": "unavailable"
                if response is None
                else response.route
                if response.route in SAFE_ROUTE_NAMES
                else "other",
                "phases": phases,
                "worker_before": self._worker_before,
                "worker_after": _worker_state(self._runner),
                "publisher_before": self._publisher_before,
                "publisher_after": _publisher_state(self._publisher),
                "intervals": "nested_and_concurrent_not_additive",
                "coverage": "calls_started_during_sample_only",
                "worker_boundary": "admission_and_child_round_trip_not_native_phase_attribution",
            }
        )
        if (
            response is None
            or elapsed_ms > MAX_INSTALLED_ADAPTER_P95_MS
            or not response.allowed
            or response.route != "native_resident"
        ):
            with suppress(BaseException):
                print("native_recovery_observation: " + json.dumps(report, sort_keys=True), file=sys.stderr)
        return report


__all__ = ["RecoveryObservation"]
