"""Async receipt/evidence enrichment queue for fast hook review.

This queue allows the synchronous enforcement path to return quickly
while receipt/evidence enrichment happens opportunistically after the
response is sent.

Security rules:
- Queue payloads must be redacted — no raw tool output, prompts,
  decrypted payload bodies, or secret samples.
- Block/reapproval paths must synchronously preserve enough approval
  request state; do not rely only on the async queue.
- Allow path may drop enrichment on queue overflow, but must increment
  a metric.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from ..store import GuardStore


HookEnrichmentTaskType = Literal["receipt_enrichment", "metrics_flush"]


@dataclass(frozen=True, slots=True)
class HookEnrichmentTask:
    """A single enrichment task for the async queue."""

    task_id: str
    task_type: HookEnrichmentTaskType
    payload: dict[str, object]
    created_at: str


class HookEnrichmentQueue:
    """In-memory queue for async receipt/evidence enrichment.

    The queue is drained opportunistically after the response is sent.
    A daemon thread may be used after unit tests pass, but the first PR
    uses a simple in-memory queue drained by calling ``drain_once()``.

    Thread-safe via a single lock.
    """

    def __init__(self, store: GuardStore | None = None, max_items: int = 1000) -> None:
        self._store = store
        self._max_items = max_items
        self._items: list[HookEnrichmentTask] = []
        self._lock = threading.Lock()
        self._dropped_count = 0

    def enqueue(self, task: HookEnrichmentTask) -> bool:
        """Enqueue an enrichment task.

        Returns ``True`` if the task was enqueued, ``False`` if the queue
        is full (caller should increment a metric).
        """
        with self._lock:
            if len(self._items) >= self._max_items:
                self._dropped_count += 1
                return False
            self._items.append(task)
            return True

    def drain_once(self, max_items: int = 25) -> int:
        """Drain up to ``max_items`` tasks from the queue.

        Returns the number of tasks drained. Tasks are removed from the
        queue regardless of whether their processing succeeds — enforcement
        already happened synchronously, so enrichment is best-effort.

        The actual receipt/evidence writing is deferred to a future PR
        that integrates with the store's ``GuardReceipt`` API. For now,
        the queue tracks that tasks were drained.
        """
        with self._lock:
            to_drain = self._items[:max_items]
            self._items = self._items[max_items:]

        return len(to_drain)

    @property
    def pending_count(self) -> int:
        """Number of pending tasks in the queue."""
        with self._lock:
            return len(self._items)

    @property
    def dropped_count(self) -> int:
        """Number of tasks dropped due to queue overflow."""
        with self._lock:
            return self._dropped_count

    def make_receipt_task(
        self,
        *,
        task_id: str,
        harness: str,
        event_name: str,
        decision: str,
        reason_code: str,
        reason: str | None = None,
        workspace: str | None = None,
    ) -> HookEnrichmentTask:
        """Create a redacted receipt enrichment task."""
        return HookEnrichmentTask(
            task_id=task_id,
            task_type="receipt_enrichment",
            payload={
                "harness": harness,
                "event_name": event_name,
                "decision": decision,
                "reason_code": reason_code,
                "reason": reason,
                "workspace": workspace,
                # No raw output, prompts, or secrets.
            },
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )


__all__ = ["HookEnrichmentTask", "HookEnrichmentQueue"]
