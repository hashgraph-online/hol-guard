"""Optional aggregate observations of actual evidence deque residence time."""

from __future__ import annotations

import threading
import time
import weakref
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, Literal

from .runtime_hook_evidence_journal import _CommandActivityRecord, _NativeDecisionReceiptRecord

if TYPE_CHECKING:
    from .runtime_hook_evidence_journal import _EvidenceRecord
    from .runtime_hook_evidence_writer import RuntimeHookEvidenceWriter

_Origin = Literal["admission", "retry", "recovery", "preexisting", "untracked"]
_ORIGINS: Final = ("admission", "retry", "recovery", "preexisting", "untracked")
_KINDS: Final = ("native_receipt", "command_activity")
_MAX_COUNTER: Final = (1 << 63) - 1
_UPPER_BOUNDS_NS: Final = tuple(1 << shift for shift in range(10, 41, 2))


@dataclass
class _Aggregate:
    queued: int = 0
    dequeued: int = 0
    measured: int = 0
    missing_age: int = 0
    total_ns: int = 0
    minimum_ns: int | None = None
    maximum_ns: int | None = None
    bins: list[int] = field(default_factory=lambda: [0] * (len(_UPPER_BOUNDS_NS) + 1))

    def snapshot(self) -> dict[str, object]:
        return {
            "queued": self.queued,
            "dequeued": self.dequeued,
            "measured": self.measured,
            "missing_age": self.missing_age,
            "total_ns": self.total_ns,
            "minimum_ns": self.minimum_ns,
            "maximum_ns": self.maximum_ns,
            "histogram_counts": list(self.bins),
        }


@dataclass
class _Pending:
    record: _EvidenceRecord
    kind: str
    origin: _Origin
    enqueued_ns: int | None


class EvidenceQueueObservation:
    """Measure enqueue to dequeue, without changing evidence or persistence.

    One observer belongs to one writer. Reattachment starts another cumulative
    observation window; already queued records have explicitly unknown ages.
    The histogram contains upper bounds, not exact percentile measurements.
    Reports and aggregate fields contain no receipt identifiers, commands,
    paths, journal timestamps or payload copies. Original records remain in the
    bounded pending table until dequeue, detach or a diagnostic fault.
    Attach and detach must be paired; abandoned-writer garbage collection has
    no automatic pending-record cleanup.
    """

    def __init__(self, *, max_pending: int = 4096, clock_ns: Callable[[], int] = time.monotonic_ns) -> None:
        if type(max_pending) is not int or not 1 <= max_pending <= 65536:
            raise ValueError("queue observation capacity is invalid")
        if not callable(clock_ns):
            raise TypeError("queue observation clock must be callable")
        self._max_pending = max_pending
        self._clock_ns = clock_ns
        self._lock = threading.RLock()
        self._writer_ref: weakref.ReferenceType[RuntimeHookEvidenceWriter] | None = None
        self._attached = False
        self._pending: dict[int, _Pending] = {}
        self._groups = {(kind, origin): _Aggregate() for kind in _KINDS for origin in _ORIGINS}
        self._queued_now = 0
        self._writer_max_records = 0
        self._writer_max_batch = 0
        self._windows = 0
        self._detachments = 0
        self._detached_pending = 0
        self._preexisting = 0
        self._overflow = 0
        self._errors = 0
        self._invalidations = 0
        self._attachment_conflicts = 0
        self._saturated = False

    def _count(self, value: int, increment: int = 1) -> int:
        result = value + increment
        if result > _MAX_COUNTER:
            self._saturated = True
            return _MAX_COUNTER
        return result

    @staticmethod
    def _kind(record: _EvidenceRecord) -> str:
        if type(record) is _NativeDecisionReceiptRecord:
            return "native_receipt"
        if type(record) is _CommandActivityRecord:
            return "command_activity"
        raise TypeError("unsupported evidence queue record")

    def _now(self) -> int | None:
        try:
            value = self._clock_ns()
            if type(value) is int and 0 <= value <= _MAX_COUNTER:
                return value
        except BaseException:
            pass
        self._errors = self._count(self._errors)
        return None

    def _owns(self, writer: RuntimeHookEvidenceWriter) -> bool:
        return self._attached and self._writer_ref is not None and self._writer_ref() is writer

    def attach(self, writer: RuntimeHookEvidenceWriter) -> bool:
        """Attach under the actual writer lock, with no clock call for backlog."""

        with writer._condition, self._lock:
            if self._owns(writer) and writer._queue_observation is self:
                return True
            if writer._queue_observation is not None or (
                self._writer_ref is not None and self._writer_ref() is not writer
            ):
                self._attachment_conflicts = self._count(self._attachment_conflicts)
                return False
            self._writer_ref = weakref.ref(writer)
            self._writer_max_records = writer._max_records
            self._writer_max_batch = writer._max_batch
            self._attached = True
            writer._queue_observation = self
            self._windows = self._count(self._windows)
            try:
                for record in writer._records:
                    self._remember(record, "preexisting", None)
                    self._preexisting = self._count(self._preexisting)
            except BaseException:
                self._hook_failed(writer)
            return True

    def detach(self, writer: RuntimeHookEvidenceWriter) -> dict[str, object]:
        """Release retained records under the same lock used for deque removal."""

        with writer._condition, self._lock:
            if self._owns(writer):
                if writer._queue_observation is self:
                    writer._queue_observation = None
                self._attached = False
                self._detachments = self._count(self._detachments)
                self._detached_pending = self._count(self._detached_pending, len(writer._records))
                self._pending.clear()
                self._queued_now = 0
            return self.report()

    def _remember(self, record: _EvidenceRecord, origin: _Origin, now: int | None) -> None:
        kind = self._kind(record)
        group = self._groups[kind, origin]
        group.queued = self._count(group.queued)
        self._queued_now = self._count(self._queued_now)
        if id(record) in self._pending:
            raise RuntimeError("evidence queue identity was admitted twice")
        if len(self._pending) >= self._max_pending:
            self._overflow = self._count(self._overflow)
            return
        self._pending[id(record)] = _Pending(record, kind, origin, now)

    def _enqueued(self, writer: RuntimeHookEvidenceWriter, record: _EvidenceRecord, origin: str) -> None:
        with self._lock:
            if not self._owns(writer):
                return
            if origin not in {"admission", "retry", "recovery"}:
                raise ValueError("invalid evidence queue origin")
            window = self._windows
            now = self._now()
            if not self._owns(writer) or self._windows != window:
                return
            # Literal branches preserve the narrow stored origin type.
            if origin == "admission":
                self._remember(record, "admission", now)
            elif origin == "retry":
                self._remember(record, "retry", now)
            else:
                self._remember(record, "recovery", now)

    def _dequeued(self, writer: RuntimeHookEvidenceWriter, record: _EvidenceRecord) -> None:
        with self._lock:
            if not self._owns(writer):
                return
            pending = self._pending.pop(id(record), None)
            self._queued_now = max(0, self._queued_now - 1)
            kind = self._kind(record)
            if pending is not None and pending.record is not record:
                raise RuntimeError("evidence queue identity mismatch")
            group = self._groups[kind, pending.origin if pending is not None else "untracked"]
            group.dequeued = self._count(group.dequeued)
            # Remove the strong reference before invoking even the diagnostic clock.
            start = pending.enqueued_ns if pending is not None else None
            del pending
            group.missing_age = self._count(group.missing_age)
            if start is None:
                return
            window = self._windows
            end = self._now()
            if not self._owns(writer) or self._windows != window:
                return
            if end is None or end < start:
                if end is not None:
                    self._errors = self._count(self._errors)
                return
            group.missing_age -= 1
            elapsed = end - start
            group.measured = self._count(group.measured)
            group.total_ns = self._count(group.total_ns, elapsed)
            group.minimum_ns = elapsed if group.minimum_ns is None else min(group.minimum_ns, elapsed)
            group.maximum_ns = elapsed if group.maximum_ns is None else max(group.maximum_ns, elapsed)
            index = next((i for i, upper in enumerate(_UPPER_BOUNDS_NS) if elapsed <= upper), len(_UPPER_BOUNDS_NS))
            group.bins[index] = self._count(group.bins[index])

    def _hook_failed(self, writer: RuntimeHookEvidenceWriter) -> None:
        """Abandon diagnostic ages after a fault; never retain a removed record."""

        with self._lock:
            if self._owns(writer):
                self._errors = self._count(self._errors)
                self._invalidations = self._count(self._invalidations)
                self._pending.clear()
                self._queued_now = len(writer._records)

    def report(self) -> dict[str, object]:
        with self._lock:
            missing = sum(group.missing_age for group in self._groups.values())
            unknown_pending = self._queued_now - sum(
                pending.enqueued_ns is not None for pending in self._pending.values()
            )
            complete = not (self._overflow or self._errors or self._saturated)
            return {
                "schema": "guard-evidence-queue-observation.v1",
                "measurement": "actual-enqueue-to-dequeue",
                "units": "nanoseconds",
                "attached": self._attached,
                "windows": self._windows,
                "detachments": self._detachments,
                "queued": self._queued_now,
                "dequeued": sum(group.dequeued for group in self._groups.values()),
                "measured": sum(group.measured for group in self._groups.values()),
                "missing_age": missing,
                "tracked_pending": len(self._pending),
                "untracked_pending": max(0, self._queued_now - len(self._pending)),
                "pending_unknown_age": max(0, unknown_pending),
                "detached_pending": self._detached_pending,
                "preexisting_unknown_age": self._preexisting,
                "overflow": self._overflow,
                "diagnostic_errors": self._errors,
                "tracking_invalidations": self._invalidations,
                "attachment_conflicts": self._attachment_conflicts,
                "counter_saturated": self._saturated,
                "max_pending": self._max_pending,
                "writer_max_records": self._writer_max_records,
                "writer_max_batch": self._writer_max_batch,
                "capacity_covers_admission_and_inflight": (
                    self._max_pending >= self._writer_max_records + self._writer_max_batch
                ),
                "tracking_complete": complete,
                "age_coverage_complete": (
                    complete and self._windows > 0 and not (missing or unknown_pending or self._detached_pending)
                ),
                "histogram_upper_bounds_ns": list(_UPPER_BOUNDS_NS),
                "histogram_final_bucket": "greater-than-last-upper-bound",
                "groups": {
                    kind: {origin: self._groups[kind, origin].snapshot() for origin in _ORIGINS} for kind in _KINDS
                },
                "qualification_complete": False,
            }


__all__ = ["EvidenceQueueObservation"]
