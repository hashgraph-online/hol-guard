"""Runtime-hook scheduler ownership and health contracts."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol, TypedDict, final

from .runtime_hook_deadline import RuntimeHookDeadline
from .runtime_hook_scheduler_types import RuntimeHookAdmissionReason, RuntimeHookLane


class RuntimeHookSchedulerStats(TypedDict):
    active: int
    active_limit: int
    queued: int
    queued_limit: int
    retained_bytes: int
    retained_bytes_limit: int
    admitted: int
    completed: int
    expired: int
    cancelled: int
    retries: int
    rejected: dict[str, int]
    per_harness_active: dict[str, int]
    per_harness_queued: dict[str, int]
    queue_wait_p95_ms: float
    service_time_p95_ms: float
    queue_wait_p99_ms: float
    service_time_p99_ms: float
    oldest_queued_ms: float
    queue_wait_by_lane_p95_ms: dict[str, float]
    service_time_by_lane_p95_ms: dict[str, float]
    queue_wait_by_lane_p99_ms: dict[str, float]
    service_time_by_lane_p99_ms: dict[str, float]


@dataclass(slots=True)
class QueuedRuntimeHook:
    sequence: int
    harness: str
    client_key: str
    lane: RuntimeHookLane
    payload_bytes: int
    deadline: RuntimeHookDeadline
    queued_at: float
    cancellation: threading.Event | None = None
    admitted_at: float | None = None
    admitted: bool = False
    rejection_reason: RuntimeHookAdmissionReason | None = None


class RuntimeHookSchedulerOwner(Protocol):
    def release_permit(self, item: QueuedRuntimeHook) -> None: ...

    def grow_reserved_bytes(
        self,
        *,
        current_bytes: int,
        payload_bytes: int,
        deadline: float,
    ) -> RuntimeHookAdmissionReason | None: ...

    def release_reserved_bytes(self, payload_bytes: int) -> None: ...


@final
class RuntimeHookPermit:
    """An acquired scheduler slot that must be released exactly once."""

    def __init__(self, scheduler: RuntimeHookSchedulerOwner, item: QueuedRuntimeHook):
        self._scheduler = scheduler
        self._item = item
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._scheduler.release_permit(self._item)

    def __enter__(self) -> RuntimeHookPermit:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.release()


@final
class RuntimeHookByteReservation:
    """A bounded payload-byte reservation that can transfer to queued work."""

    def __init__(self, scheduler: RuntimeHookSchedulerOwner, payload_bytes: int):
        self._scheduler = scheduler
        self.payload_bytes = payload_bytes
        self._transferred = False
        self._released = False

    def transfer(self) -> None:
        if self._released or self._transferred:
            raise RuntimeError("runtime hook byte reservation is no longer transferable")
        self._transferred = True

    def is_owned_by(self, scheduler: RuntimeHookSchedulerOwner) -> bool:
        return self._scheduler is scheduler

    def resize(self, payload_bytes: int, *, deadline: float) -> RuntimeHookAdmissionReason | None:
        if self._released or self._transferred:
            raise RuntimeError("runtime hook byte reservation is no longer resizable")
        if payload_bytes < 0:
            raise ValueError("runtime hook byte reservation cannot be negative")
        if payload_bytes > self.payload_bytes:
            reason = self._scheduler.grow_reserved_bytes(
                current_bytes=self.payload_bytes,
                payload_bytes=payload_bytes,
                deadline=deadline,
            )
            if reason is not None:
                return reason
        released_bytes = self.payload_bytes - payload_bytes
        self.payload_bytes = payload_bytes
        if released_bytes > 0:
            self._scheduler.release_reserved_bytes(released_bytes)
        return None

    def release(self) -> None:
        if self._released or self._transferred:
            return
        self._released = True
        self._scheduler.release_reserved_bytes(self.payload_bytes)

    def __enter__(self) -> RuntimeHookByteReservation:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.release()


@dataclass(frozen=True, slots=True)
class RuntimeHookAdmission:
    permit: RuntimeHookPermit | None
    reason_code: RuntimeHookAdmissionReason | None


__all__ = [
    "QueuedRuntimeHook",
    "RuntimeHookAdmission",
    "RuntimeHookByteReservation",
    "RuntimeHookPermit",
    "RuntimeHookSchedulerStats",
]
