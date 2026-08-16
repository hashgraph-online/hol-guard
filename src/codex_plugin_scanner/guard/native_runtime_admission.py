"""Bounded, privacy-safe admission and retry policy for resident native requests."""

from __future__ import annotations

import errno
import os
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import wraps
from typing import ParamSpec, TypeVar, cast

P = ParamSpec("P")
R = TypeVar("R")

_DATA_CAPACITY = 60
_LIFECYCLE_CAPACITY = 4
_DATA_WAIT_SECONDS = 0.004
_LIFECYCLE_WAIT_SECONDS = 0.050
_RETRY_DELAY_MIN_SECONDS = 0.004
_RETRY_DELAY_SPAN_MILLISECONDS = 17
_MAX_REQUEST_SECONDS = 4.0
_RESUME_GAP_SECONDS = 5.0

_TRANSIENT_ERRNOS = frozenset(
    value
    for value in (
        getattr(errno, "EAGAIN", None),
        getattr(errno, "EWOULDBLOCK", None),
        getattr(errno, "EINTR", None),
        getattr(errno, "EPIPE", None),
        getattr(errno, "ECONNABORTED", None),
        getattr(errno, "ECONNRESET", None),
        getattr(errno, "ECONNREFUSED", None),
        getattr(errno, "ETIMEDOUT", None),
        getattr(errno, "ENETDOWN", None),
        getattr(errno, "ENETRESET", None),
        getattr(errno, "ENETUNREACH", None),
        getattr(errno, "EHOSTDOWN", None),
        getattr(errno, "EHOSTUNREACH", None),
        getattr(errno, "ENOBUFS", None),
        getattr(errno, "EMFILE", None),
        getattr(errno, "ENFILE", None),
    )
    if value is not None
)
_NON_RETRYABLE_TOKENS = (
    "auth",
    "digest",
    "integrity",
    "manifest",
    "permission",
    "protocol_version",
    "rule_digest",
    "signature",
    "untrusted",
)


class NativeResidentAdmissionError(RuntimeError):
    """Raised when bounded resident admission cannot accept more work."""


@dataclass(frozen=True, slots=True)
class NativeAdmissionSnapshot:
    active_data: int
    active_lifecycle: int
    high_water_data: int
    high_water_lifecycle: int
    rejected_data: int
    rejected_lifecycle: int
    transient_retries: int
    client_aborts: int
    resume_events: int

    def to_dict(self) -> dict[str, int]:
        return {
            "active_data": self.active_data,
            "active_lifecycle": self.active_lifecycle,
            "high_water_data": self.high_water_data,
            "high_water_lifecycle": self.high_water_lifecycle,
            "rejected_data": self.rejected_data,
            "rejected_lifecycle": self.rejected_lifecycle,
            "transient_retries": self.transient_retries,
            "client_aborts": self.client_aborts,
            "resume_events": self.resume_events,
        }


class _AdmissionState:
    def __init__(self) -> None:
        self.data = threading.BoundedSemaphore(_DATA_CAPACITY)
        self.lifecycle = threading.BoundedSemaphore(_LIFECYCLE_CAPACITY)
        self.lock = threading.Lock()
        self.active_data = 0
        self.active_lifecycle = 0
        self.high_water_data = 0
        self.high_water_lifecycle = 0
        self.rejected_data = 0
        self.rejected_lifecycle = 0
        self.transient_retries = 0
        self.client_aborts = 0
        self.resume_events = 0
        self.wall = time.time()
        self.monotonic = time.monotonic()

    def observe_clock(self) -> bool:
        wall = time.time()
        monotonic = time.monotonic()
        with self.lock:
            wall_delta = max(0.0, wall - self.wall)
            monotonic_delta = max(0.0, monotonic - self.monotonic)
            self.wall = wall
            self.monotonic = monotonic
            resumed = wall_delta - monotonic_delta >= _RESUME_GAP_SECONDS
            if resumed:
                self.resume_events += 1
            return resumed

    def acquire(self, *, lifecycle: bool) -> bool:
        semaphore = self.lifecycle if lifecycle else self.data
        wait = _LIFECYCLE_WAIT_SECONDS if lifecycle else _DATA_WAIT_SECONDS
        acquired = semaphore.acquire(timeout=wait)
        with self.lock:
            if not acquired:
                if lifecycle:
                    self.rejected_lifecycle += 1
                else:
                    self.rejected_data += 1
                return False
            if lifecycle:
                self.active_lifecycle += 1
                self.high_water_lifecycle = max(self.high_water_lifecycle, self.active_lifecycle)
            else:
                self.active_data += 1
                self.high_water_data = max(self.high_water_data, self.active_data)
        return True

    def release(self, *, lifecycle: bool) -> None:
        with self.lock:
            if lifecycle:
                self.active_lifecycle -= 1
            else:
                self.active_data -= 1
        (self.lifecycle if lifecycle else self.data).release()

    def record_retry(self) -> None:
        with self.lock:
            self.transient_retries += 1

    def record_abort(self) -> None:
        with self.lock:
            self.client_aborts += 1

    def snapshot(self) -> NativeAdmissionSnapshot:
        with self.lock:
            return NativeAdmissionSnapshot(
                active_data=self.active_data,
                active_lifecycle=self.active_lifecycle,
                high_water_data=self.high_water_data,
                high_water_lifecycle=self.high_water_lifecycle,
                rejected_data=self.rejected_data,
                rejected_lifecycle=self.rejected_lifecycle,
                transient_retries=self.transient_retries,
                client_aborts=self.client_aborts,
                resume_events=self.resume_events,
            )


_STATE = _AdmissionState()


def _request_payload(args: tuple[object, ...], kwargs: Mapping[str, object]) -> object:
    for key in ("request", "payload", "message"):
        if key in kwargs:
            return kwargs[key]
    for value in args:
        if isinstance(value, Mapping) and ("operation" in value or "request" in value):
            return value
    return None


def _operation(args: tuple[object, ...], kwargs: Mapping[str, object]) -> str:
    explicit = kwargs.get("operation")
    if isinstance(explicit, str):
        return explicit.lower()
    payload = _request_payload(args, kwargs)
    if isinstance(payload, Mapping):
        operation = payload.get("operation")
        if isinstance(operation, str):
            return operation.lower()
    return "evaluation"


def _deadline(args: tuple[object, ...], kwargs: Mapping[str, object]) -> float:
    for key in ("deadline", "deadline_monotonic"):
        value = kwargs.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return min(float(value), time.monotonic() + _MAX_REQUEST_SECONDS)
    return time.monotonic() + _MAX_REQUEST_SECONDS


def _retryable(error: BaseException) -> bool:
    text = str(error).lower()
    if any(token in text for token in _NON_RETRYABLE_TOKENS):
        return False
    if isinstance(error, (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, TimeoutError)):
        return True
    return isinstance(error, OSError) and error.errno in _TRANSIENT_ERRNOS


def _client_abort(error: BaseException) -> bool:
    return isinstance(error, (BrokenPipeError, ConnectionAbortedError, ConnectionResetError)) or (
        isinstance(error, OSError)
        and error.errno
        in {
            getattr(errno, "EPIPE", -1),
            getattr(errno, "ECONNABORTED", -1),
            getattr(errno, "ECONNRESET", -1),
        }
    )


def _retry_delay() -> float:
    return _RETRY_DELAY_MIN_SECONDS + secrets.randbelow(_RETRY_DELAY_SPAN_MILLISECONDS) / 1000.0


def native_resident_admission(function: Callable[P, R]) -> Callable[P, R]:
    """Bound concurrency and retry one transient local transport failure.

    Resident requests are deterministic reads and evaluations, so one bounded
    retry is safe. Authentication, integrity, manifest, and protocol failures
    are never retried. The wrapper stores counters only and never stores request
    payloads, commands, paths, endpoints, credentials, or exception text.
    """

    @wraps(function)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        args_tuple = cast(tuple[object, ...], args)
        kwargs_map = cast(Mapping[str, object], kwargs)
        operation = _operation(args_tuple, kwargs_map)
        lifecycle = operation in {"health", "shutdown", "rotate", "status"}
        if not _STATE.acquire(lifecycle=lifecycle):
            raise NativeResidentAdmissionError(
                "native_resident_lifecycle_saturated" if lifecycle else "native_resident_admission_saturated"
            )
        try:
            deadline = _deadline(args_tuple, kwargs_map)
            resumed = _STATE.observe_clock()
            attempts = 2
            last_error: BaseException | None = None
            for attempt in range(attempts):
                if time.monotonic() >= deadline:
                    raise TimeoutError("native_resident_total_deadline_exceeded")
                if resumed and attempt == 0:
                    time.sleep(min(_retry_delay(), max(0.0, deadline - time.monotonic())))
                try:
                    return function(*args, **kwargs)
                except BaseException as error:
                    last_error = error
                    if _client_abort(error):
                        _STATE.record_abort()
                    if attempt + 1 >= attempts or not _retryable(error):
                        raise
                    delay = _retry_delay()
                    if time.monotonic() + delay >= deadline:
                        raise
                    _STATE.record_retry()
                    time.sleep(delay)
            assert last_error is not None
            raise last_error
        finally:
            _STATE.release(lifecycle=lifecycle)

    return wrapped


def native_resident_admission_snapshot() -> dict[str, int]:
    """Return aggregate-only admission state for doctor and support bundles."""

    return _STATE.snapshot().to_dict()


__all__ = [
    "NativeAdmissionSnapshot",
    "NativeResidentAdmissionError",
    "native_resident_admission",
    "native_resident_admission_snapshot",
]
