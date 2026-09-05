"""Bounded asynchronous persistence for non-authoritative hook evidence."""

from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import TypedDict, final
from uuid import uuid4

from ..cli.commands_support_command_activity import persist_deferred_post_hook_command_activity
from ..native_decision_receipt import validate_native_decision_receipt
from ..runtime.command_activity_contract import CorrelationHandle
from ..runtime.command_activity_correlation import (
    derive_proven_request_correlation,
    load_or_create_installation_correlation_key,
)
from ..runtime.command_activity_privacy import InstallationCorrelationKey
from ..sqlite_tuning import sqlite_connect_timeout_override
from ..store import GuardStore
from .runtime_hook_evidence_journal import (
    _CommandActivityRecord,
    _EvidenceRecord,
    _NativeDecisionReceiptRecord,
    _payload_has_command,
    append_journal,
    recover_journal_records,
    rewrite_journal,
)


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
    receipt_durable_pending: int


@final
class RuntimeHookEvidenceWriter:
    """Keeps best-effort activity writes outside security-decision workers."""

    def __init__(
        self,
        *,
        store: GuardStore,
        max_records: int = 2_000,
        max_bytes: int = 16 * 1024 * 1024,
        max_batch: int = 50,
        batch_wait_seconds: float = 0.025,
        journal_path: Path | None = None,
    ) -> None:
        if min(max_records, max_bytes, max_batch) < 1 or batch_wait_seconds < 0:
            raise ValueError("runtime hook evidence writer limits are invalid")
        self._store = store
        self._guard_home = store.guard_home
        self._max_records = max_records
        self._max_bytes = max_bytes
        self._max_batch = max_batch
        self._batch_wait_seconds = batch_wait_seconds
        self._condition = threading.Condition()
        self._records: deque[_EvidenceRecord] = deque()
        self._durable: OrderedDict[str, _EvidenceRecord] = OrderedDict()
        self._receipt_seen: OrderedDict[str, None] = OrderedDict()
        self._retry_attempts: dict[str, int] = {}
        self._in_flight = False
        self._queued_bytes = 0
        self._accepted = 0
        self._processed = 0
        self._dropped = 0
        self._failures = 0
        self._recovered = 0
        self._degraded = False
        self._receipt_accepted = 0
        self._receipt_processed = 0
        self._receipt_deduped = 0
        self._receipt_dropped = 0
        self._receipt_failures = 0
        self._stopping = False
        self._drain_deadline: float | None = None
        self._sqlite_timeout_seconds = 0.05
        self._journal_path = journal_path or self._guard_home / "runtime-hook-evidence.jsonl"
        try:
            self._correlation_key: InstallationCorrelationKey | None = load_or_create_installation_correlation_key(
                self._guard_home
            )
        except (OSError, ValueError):
            self._correlation_key = None
        self._recover_journal()
        self._thread = threading.Thread(
            target=self._run,
            name="hol-guard-hook-evidence",
            daemon=True,
        )
        self._thread.start()

    def submit_command_activity(
        self,
        *,
        harness: str,
        event: str,
        payload: Mapping[str, object],
        succeeded: bool,
    ) -> bool:
        try:
            snapshot = deepcopy(dict(payload))
            encoded = json.dumps(snapshot, separators=(",", ":"), sort_keys=True).encode("utf-8")
            correlation = self._derive_correlation(harness=harness, event=event, payload=snapshot)
        except Exception:
            with self._condition:
                self._dropped += 1
            return False
        record = _CommandActivityRecord(
            record_id=uuid4().hex,
            harness=harness,
            event=event,
            correlation=correlation,
            has_command=_payload_has_command(snapshot),
            succeeded=succeeded,
            payload_bytes=len(encoded),
        )
        with self._condition:
            if (
                self._stopping
                or len(self._records) >= self._max_records
                or self._queued_bytes + record.payload_bytes > self._max_bytes
            ):
                self._dropped += 1
                self._degraded = True
                return False
            self._records.append(record)
            self._queued_bytes += record.payload_bytes
            self._accepted += 1
            self._condition.notify()
        return True

    def submit_native_decision_receipt(self, receipt: Mapping[str, object]) -> bool:
        """Queue one Rust receipt without touching SQLite or waiting on I/O."""

        validated = validate_native_decision_receipt(receipt)
        if validated is None:
            with self._condition:
                self._receipt_dropped += 1
                self._dropped += 1
                self._degraded = True
            return False
        record = _NativeDecisionReceiptRecord(receipt=validated, payload_bytes=0)
        record = _NativeDecisionReceiptRecord(receipt=validated, payload_bytes=len(record.serialized()))
        receipt_id = record.record_id
        with self._condition:
            if receipt_id in self._receipt_seen:
                self._receipt_deduped += 1
                return True
            if (
                self._stopping
                or len(self._records) >= self._max_records
                or self._queued_bytes + record.payload_bytes > self._max_bytes
            ):
                self._receipt_dropped += 1
                self._dropped += 1
                self._degraded = True
                return False
            self._records.append(record)
            self._queued_bytes += record.payload_bytes
            self._receipt_seen[receipt_id] = None
            while len(self._receipt_seen) > self._max_records * 4:
                self._receipt_seen.popitem(last=False)
            self._accepted += 1
            self._receipt_accepted += 1
            self._condition.notify()
        return True

    def _derive_correlation(
        self,
        *,
        harness: str,
        event: str,
        payload: Mapping[str, object],
    ) -> CorrelationHandle | None:
        key = self._correlation_key
        if key is None:
            key = load_or_create_installation_correlation_key(self._guard_home)
            self._correlation_key = key
        try:
            return derive_proven_request_correlation(harness=harness, event=event, payload=payload, key=key)
        except (OSError, ValueError):
            key = load_or_create_installation_correlation_key(self._guard_home)
            self._correlation_key = key
            return derive_proven_request_correlation(harness=harness, event=event, payload=payload, key=key)

    def stats(self) -> RuntimeHookEvidenceWriterStats:
        with self._condition:
            return {
                "queued": len(self._records),
                "queued_bytes": self._queued_bytes,
                "accepted": self._accepted,
                "processed": self._processed,
                "dropped": self._dropped,
                "failures": self._failures,
                "recovered": self._recovered,
                "durable_pending": len(self._durable),
                "degraded": self._degraded or bool(self._durable and not self._records and not self._in_flight),
                "running": self._thread.is_alive() and not self._stopping,
                "receipt_accepted": self._receipt_accepted,
                "receipt_processed": self._receipt_processed,
                "receipt_deduped": self._receipt_deduped,
                "receipt_dropped": self._receipt_dropped,
                "receipt_failures": self._receipt_failures,
                "receipt_durable_pending": sum(
                    isinstance(record, _NativeDecisionReceiptRecord) for record in self._durable.values()
                ),
            }

    def stop(self, *, timeout_seconds: float = 1.0) -> bool:
        with self._condition:
            self._stopping = True
            self._drain_deadline = time.monotonic() + max(0.0, timeout_seconds)
            self._condition.notify_all()
        self._thread.join(timeout=max(0.0, timeout_seconds))
        with self._condition:
            if self._durable:
                self._degraded = True
        return not self._thread.is_alive()

    def _run(self) -> None:
        while True:
            batch = self._next_batch()
            if not batch:
                return
            for record in batch:
                with self._condition:
                    self._in_flight = True
                with self._condition:
                    already_durable = record.record_id in self._durable
                if not already_durable:
                    try:
                        self._append_journal(record)
                    except OSError:
                        with self._condition:
                            self._dropped += 1
                            self._failures += 1
                            if isinstance(record, _NativeDecisionReceiptRecord):
                                self._receipt_dropped += 1
                                self._receipt_failures += 1
                            self._degraded = True
                            self._in_flight = False
                        continue
                    with self._condition:
                        self._durable[record.record_id] = record
                # A bounded shutdown may expire while the journal append is in
                # flight. Keep the accepted record journal-durable, then leave
                # it pending for recovery rather than discarding it before the
                # append has completed.
                with self._condition:
                    if self._drain_expired():
                        self._degraded = True
                        self._in_flight = False
                        return
                try:
                    with sqlite_connect_timeout_override(self._sqlite_timeout_seconds):
                        if isinstance(record, _NativeDecisionReceiptRecord):
                            persisted = persist_native_decision_receipt(
                                store=self._store,
                                receipt=record.receipt,
                            )
                            if not persisted:
                                raise RuntimeError("native receipt persistence was not acknowledged")
                        else:
                            _ = persist_deferred_post_hook_command_activity(
                                store=self._store,
                                harness=record.harness,
                                correlation=record.correlation,
                                has_command=record.has_command,
                                succeeded=record.succeeded,
                            )
                except Exception:
                    with self._condition:
                        self._failures += 1
                        if isinstance(record, _NativeDecisionReceiptRecord):
                            self._receipt_failures += 1
                        self._degraded = True
                        if not self._stopping:
                            attempt = self._retry_attempts.get(record.record_id, 0) + 1
                            self._retry_attempts[record.record_id] = attempt
                            self._records.append(record)
                            self._queued_bytes += record.payload_bytes
                            _ = self._condition.wait(timeout=min(1.0, 0.05 * (2 ** min(attempt - 1, 5))))
                        self._in_flight = False
                else:
                    with self._condition:
                        self._processed += 1
                        if isinstance(record, _NativeDecisionReceiptRecord):
                            self._receipt_processed += 1
                        self._retry_attempts.pop(record.record_id, None)
                        _ = self._durable.pop(record.record_id, None)
                    try:
                        self._rewrite_journal(remove_record_id=record.record_id)
                    except OSError:
                        with self._condition:
                            self._failures += 1
                            self._degraded = True
                    finally:
                        with self._condition:
                            self._in_flight = False

    def _next_batch(self) -> list[_EvidenceRecord]:
        with self._condition:
            while not self._records and not self._stopping:
                _ = self._condition.wait()
            if not self._records:
                return []
            if not self._stopping and self._batch_wait_seconds:
                _ = self._condition.wait(timeout=self._batch_wait_seconds)
            batch: list[_EvidenceRecord] = []
            while self._records and len(batch) < self._max_batch:
                record = self._records.popleft()
                self._queued_bytes -= record.payload_bytes
                batch.append(record)
            return batch

    def _drain_expired(self) -> bool:
        return self._stopping and self._drain_deadline is not None and time.monotonic() >= self._drain_deadline

    def _recover_journal(self) -> None:
        try:
            records, invalid_records = recover_journal_records(self._journal_path, max_bytes=self._max_bytes)
        except FileNotFoundError:
            return
        except OSError:
            self._degraded = True
            self._failures += 1
            return
        if invalid_records:
            self._degraded = True
            self._failures += invalid_records
        for record in records:
            if len(self._records) >= self._max_records or self._queued_bytes + record.payload_bytes > self._max_bytes:
                self._degraded = True
                self._failures += 1
                continue
            if isinstance(record, _NativeDecisionReceiptRecord):
                if record.record_id in self._receipt_seen:
                    self._degraded = True
                    self._failures += 1
                    continue
                self._receipt_seen[record.record_id] = None
            self._durable[record.record_id] = record
            self._records.append(record)
            self._queued_bytes += record.payload_bytes
            self._recovered += 1

    def _append_journal(self, record: _EvidenceRecord) -> None:
        append_journal(self._journal_path, record)

    def _rewrite_journal(self, *, remove_record_id: str) -> None:
        invalid_records = rewrite_journal(
            self._journal_path,
            remove_record_id=remove_record_id,
            max_bytes=self._max_bytes,
        )
        if invalid_records:
            self._degraded = True
            self._failures += invalid_records


__all__ = [
    "RuntimeHookEvidenceWriter",
    "RuntimeHookEvidenceWriterStats",
    "persist_native_decision_receipt",
]
