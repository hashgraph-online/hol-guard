"""Journal and stats helpers for runtime hook evidence persistence."""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from collections.abc import Mapping
from pathlib import Path
from threading import Condition
from typing import TYPE_CHECKING, TypedDict

from ..store import GuardStore
from .runtime_hook_evidence_diagnostics import EvidenceFailurePhase, evidence_failure_code
from .runtime_hook_evidence_journal import (
    _EvidenceRecord,
    _NativeDecisionReceiptRecord,
)

if TYPE_CHECKING:
    from abc import ABC, abstractmethod

    from .runtime_hook_evidence_queue_observation import EvidenceQueueObservation

    _WriterJournalHost = ABC
else:
    _WriterJournalHost = object


def persist_native_decision_receipt(*, store: GuardStore, receipt: Mapping[str, object]) -> bool:
    """Persist a validated receipt through the control-plane store only."""

    recorder = getattr(store, "record_native_decision_receipt", None)
    if not callable(recorder):
        raise RuntimeError("native receipt persistence is unavailable")
    result = recorder(receipt)
    return result is not False


class RuntimeHookEvidenceWriterStats(TypedDict):
    queued: int
    queued_bytes: int
    accepted: int
    processed: int
    dropped: int
    failures: int
    recovered: int
    durable_pending: int
    degraded: bool
    running: bool
    receipt_accepted: int
    receipt_processed: int
    receipt_deduped: int
    receipt_dropped: int
    receipt_failures: int
    failure_diagnostics: dict[str, int]
    receipt_failure_diagnostics: dict[str, int]
    receipt_durable_pending: int
    journal_durable: int
    journal_checkpoints: int
    receipt_transactions: int
    checkpoint_pending: int


class RuntimeHookEvidenceWriterJournalMixin(_WriterJournalHost):
    """Bounded queue and durable-journal operations shared by the writer."""

    if TYPE_CHECKING:
        # The concrete writer initializes this state and implements both hooks.
        _condition: Condition
        _records: deque[_EvidenceRecord]
        _stopping: bool
        _checkpoint_pending: set[str]
        _batch_wait_seconds: float
        _max_batch: int
        _queue_observation: EvidenceQueueObservation | None
        _queued_bytes: int
        _drain_deadline: float | None
        _journal_path: Path
        _max_bytes: int
        _degraded: bool
        _failures: int
        _max_records: int
        _receipt_seen: OrderedDict[str, None]
        _durable: OrderedDict[str, _EvidenceRecord]
        _recovered: int

        @abstractmethod
        def _observe_queue(self, record: _EvidenceRecord, origin: str | None = None) -> None: ...

        @abstractmethod
        def _record_failure_diagnostics(
            self, phase: EvidenceFailurePhase, code: str, records: int, receipts: int = 0
        ) -> None: ...

    def _next_batch(self) -> list[_EvidenceRecord]:
        with self._condition:
            while not self._records and not self._stopping:
                if self._checkpoint_pending:
                    self._condition.wait(timeout=0.1)
                    break
                self._condition.wait()
            if not self._records:
                return []
            if not self._stopping and self._batch_wait_seconds:
                _ = self._condition.wait(timeout=self._batch_wait_seconds)
            batch: list[_EvidenceRecord] = []
            while self._records and len(batch) < self._max_batch:
                record = self._records.popleft()
                if self._queue_observation is not None:
                    self._observe_queue(record)
                self._queued_bytes -= record.payload_bytes
                batch.append(record)
            return batch

    def _drain_expired(self) -> bool:
        return self._stopping and self._drain_deadline is not None and time.monotonic() >= self._drain_deadline

    def _recover_journal(self) -> None:
        try:
            records, invalid_records = _writer.recover_journal_records(self._journal_path, max_bytes=self._max_bytes)
        except FileNotFoundError:
            return
        except OSError as error:
            self._degraded = True
            self._failures += 1
            self._record_failure_diagnostics("journal_recovery", evidence_failure_code(error), 1)
            return
        if invalid_records:
            self._degraded = True
            self._failures += invalid_records
            self._record_failure_diagnostics("journal_recovery", "invalid_record", invalid_records)
        for record in records:
            if len(self._records) >= self._max_records or self._queued_bytes + record.payload_bytes > self._max_bytes:
                self._degraded = True
                self._failures += 1
                self._record_failure_diagnostics("journal_recovery", "recovery_capacity", 1)
                continue
            if isinstance(record, _NativeDecisionReceiptRecord):
                if record.record_id in self._receipt_seen:
                    self._degraded = True
                    self._failures += 1
                    self._record_failure_diagnostics("journal_recovery", "recovery_duplicate", 1)
                    continue
                self._receipt_seen[record.record_id] = None
            self._durable[record.record_id] = record
            self._records.append(record)
            if self._queue_observation is not None:
                self._observe_queue(record, "recovery")
            self._queued_bytes += record.payload_bytes
            self._recovered += 1

    def _append_journal(self, record: _EvidenceRecord) -> None:
        _writer.append_journal(self._journal_path, record)

    def _rewrite_journal(self, *, remove_record_id: str) -> None:
        invalid_records = _writer.rewrite_journal(
            self._journal_path,
            remove_record_id=remove_record_id,
            max_bytes=self._max_bytes,
        )
        if invalid_records:
            self._degraded = True
            self._failures += invalid_records
            self._record_failure_diagnostics("journal_rewrite", "invalid_record", invalid_records)


# Bind after every declaration so either module can be imported first.
from . import runtime_hook_evidence_writer as _writer  # noqa: E402
