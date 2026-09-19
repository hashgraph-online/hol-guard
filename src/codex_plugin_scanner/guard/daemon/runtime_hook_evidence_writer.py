"""Bounded asynchronous persistence for non-authoritative hook evidence."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import cast, final
from uuid import uuid4

from ..action_lattice import is_guard_action
from ..cli.commands_support_command_activity import persist_deferred_post_hook_command_activity
from ..models import GuardAction
from ..native_decision_receipt import validate_native_decision_receipt
from ..runtime.command_activity_contract import ActivityApprovalReuseStatus, CorrelationHandle
from ..runtime.command_activity_correlation import (
    derive_proven_request_correlation,
    load_or_create_installation_correlation_key,
)
from ..runtime.command_activity_display import build_invocation_preview_from_payload
from ..runtime.command_activity_lifecycle import build_native_pre_hook_evidence
from ..runtime.command_activity_privacy import InstallationCorrelationKey
from ..sqlite_tuning import sqlite_connect_timeout_override
from ..store import GuardStore
from .runtime_hook_evidence_diagnostics import EvidenceFailurePhase, evidence_failure_code
from .runtime_hook_evidence_journal import (
    _CommandActivityRecord,
    _EvidenceRecord,
    _NativeDecisionReceiptRecord,
    _payload_has_command,
    append_journal_batch,
    checkpoint_journal,
)
from .runtime_hook_evidence_writer_journal import (
    RuntimeHookEvidenceWriterJournalMixin,
    RuntimeHookEvidenceWriterStats,
    persist_native_decision_receipt,
)


@final
class RuntimeHookEvidenceWriter(RuntimeHookEvidenceWriterJournalMixin):
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
        self._max_batch = min(max_batch, 50)
        self._batch_wait_seconds = batch_wait_seconds
        self._condition = threading.Condition()
        self._records: deque[_EvidenceRecord] = deque()
        self._durable: OrderedDict[str, _EvidenceRecord] = OrderedDict()
        self._receipt_seen: OrderedDict[str, None] = OrderedDict()
        self._retry_attempts: dict[str, int] = {}
        self._checkpoint_pending: set[str] = set()
        self._journal_durable = 0
        self._journal_checkpoints = 0
        self._receipt_transactions = 0
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
        self._failure_diagnostics: dict[str, int] = {}
        self._receipt_failure_diagnostics: dict[str, int] = {}
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
        policy_action: str | None = None,
        receipt_id: str | None = None,
        prompted: bool = False,
        approval_reuse_status: str = "not-applicable",
    ) -> bool:
        if event == "PreToolUse" and not is_guard_action(policy_action):
            return False
        # Reject saturated work before touching the caller's payload. Only
        # compact immutable facts survive this call; output/metadata trees are
        # neither copied nor serialized on the response path.
        with self._condition:
            if self._stopping or len(self._records) >= self._max_records or self._queued_bytes >= self._max_bytes:
                self._dropped += 1
                self._degraded = True
                return False
        try:
            correlation = self._derive_correlation(harness=harness, event=event, payload=payload)
            invocation_preview = build_invocation_preview_from_payload(payload)
            has_command = _payload_has_command(payload)
        except Exception:
            with self._condition:
                self._dropped += 1
            return False
        record = _CommandActivityRecord(
            record_id=uuid4().hex,
            harness=harness,
            event=event,
            correlation=correlation,
            has_command=has_command,
            succeeded=succeeded,
            payload_bytes=0,
            policy_action=policy_action,
            occurred_at=datetime.now(timezone.utc).isoformat(),
            receipt_id=receipt_id,
            prompted=prompted,
            approval_reuse_status=approval_reuse_status,
            invocation_preview=invocation_preview,
        )
        serialized = record.serialized()
        if _CommandActivityRecord.from_json(json.loads(serialized)) is None:
            return False
        # Account for the retained preview as well as the aggregate journal
        # record, including multibyte Unicode. The original payload is absent.
        record = replace(
            record,
            payload_bytes=len(serialized) + len((invocation_preview or "").encode("utf-8")),
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
                "journal_durable": self._journal_durable,
                "journal_checkpoints": self._journal_checkpoints,
                "receipt_transactions": self._receipt_transactions,
                "checkpoint_pending": len(self._checkpoint_pending),
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
                "failure_diagnostics": dict(self._failure_diagnostics),
                "receipt_failure_diagnostics": dict(self._receipt_failure_diagnostics),
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
                self._checkpoint_completed_records()
                with self._condition:
                    if self._stopping:
                        return
                continue
            with self._condition:
                self._in_flight = True
                fresh = [record for record in batch if record.record_id not in self._durable]
            if fresh:
                try:
                    append_journal_batch(self._journal_path, fresh, max_bytes=self._max_bytes)
                except OSError as error:
                    with self._condition:
                        self._dropped += len(fresh)
                        self._failures += len(fresh)
                        receipts_dropped = sum(isinstance(record, _NativeDecisionReceiptRecord) for record in fresh)
                        self._receipt_dropped += receipts_dropped
                        self._receipt_failures += receipts_dropped
                        self._record_failure_diagnostics(
                            "journal_append", evidence_failure_code(error), len(fresh), receipts_dropped
                        )
                        for record in fresh:
                            if isinstance(record, _NativeDecisionReceiptRecord):
                                self._receipt_seen.pop(record.record_id, None)
                        self._degraded = True
                    fresh_ids = {record.record_id for record in fresh}
                    batch = [record for record in batch if record.record_id not in fresh_ids]
                else:
                    with self._condition:
                        self._durable.update((record.record_id, record) for record in fresh)
                        self._journal_durable += len(fresh)
            # Submission only accepts memory. Even when shutdown expires during
            # append, finish the durability boundary before abandoning DB work.
            with self._condition:
                if self._drain_expired():
                    self._degraded = bool(self._durable) or self._degraded
                    self._in_flight = False
                    return
            receipts = [record for record in batch if isinstance(record, _NativeDecisionReceiptRecord)]
            retry_delay = 0.0
            if receipts:
                failure_code: str | None = None
                try:
                    with sqlite_connect_timeout_override(self._sqlite_timeout_seconds):
                        if len(receipts) == 1:
                            if not persist_native_decision_receipt(store=self._store, receipt=receipts[0].receipt):
                                failure_code = "unacknowledged"
                                raise RuntimeError("native receipt persistence was not acknowledged")
                        else:
                            acknowledged = self._store.record_native_decision_receipts(
                                tuple(record.receipt for record in receipts)
                            )
                            if acknowledged != tuple(record.record_id for record in receipts):
                                failure_code = "unacknowledged"
                                raise RuntimeError("native receipt batch persistence was not acknowledged")
                    with self._condition:
                        self._receipt_transactions += 1
                except Exception as error:
                    retry_delay = self._record_persistence_failure(
                        receipts, phase="receipt_persistence", code=failure_code or evidence_failure_code(error)
                    )
                else:
                    self._record_committed(receipts)
            for record in batch:
                if isinstance(record, _NativeDecisionReceiptRecord):
                    continue
                try:
                    with sqlite_connect_timeout_override(self._sqlite_timeout_seconds):
                        self._persist_command_activity(record)
                except Exception as error:
                    retry_delay = max(
                        retry_delay,
                        self._record_persistence_failure(
                            [record], phase="command_activity_persistence", code=evidence_failure_code(error)
                        ),
                    )
                else:
                    self._record_committed([record])
            self._checkpoint_completed_records()
            with self._condition:
                self._in_flight = False
                if retry_delay and not self._stopping:
                    self._condition.wait(timeout=retry_delay)

    def _record_failure_diagnostics(
        self, phase: EvidenceFailurePhase, code: str, records: int, receipts: int = 0
    ) -> None:
        # Keep the synchronization and failed-attempt units of the existing
        # failure counters. Successful retry never clears diagnostics.
        key = f"{phase}/{code}"
        self._failure_diagnostics[key] = self._failure_diagnostics.get(key, 0) + records
        if receipts:
            self._receipt_failure_diagnostics[key] = self._receipt_failure_diagnostics.get(key, 0) + receipts

    def _record_persistence_failure(
        self, records: Sequence[_EvidenceRecord], *, phase: EvidenceFailurePhase, code: str
    ) -> float:
        retry_delay = 0.0
        with self._condition:
            self._failures += len(records)
            self._receipt_failures += sum(isinstance(record, _NativeDecisionReceiptRecord) for record in records)
            self._record_failure_diagnostics(
                phase, code, len(records), sum(isinstance(record, _NativeDecisionReceiptRecord) for record in records)
            )
            self._degraded = True
            for record in records:
                if not self._stopping:
                    attempt = self._retry_attempts.get(record.record_id, 0) + 1
                    self._retry_attempts[record.record_id] = attempt
                    # Retries have already passed admission and remain durable.
                    # Do not convert a SQLite outage into silent evidence loss.
                    self._records.append(record)
                    self._queued_bytes += record.payload_bytes
                    retry_delay = max(retry_delay, min(1.0, 0.05 * (2 ** min(attempt - 1, 5))))
        return retry_delay

    def _record_committed(self, records: Sequence[_EvidenceRecord]) -> None:
        with self._condition:
            self._processed += len(records)
            self._receipt_processed += sum(isinstance(record, _NativeDecisionReceiptRecord) for record in records)
            for record in records:
                self._retry_attempts.pop(record.record_id, None)
                self._checkpoint_pending.add(record.record_id)

    def _checkpoint_completed_records(self) -> None:
        with self._condition:
            completed = frozenset(self._checkpoint_pending)
        if not completed:
            return
        try:
            invalid_records = checkpoint_journal(
                self._journal_path, remove_record_ids=completed, max_bytes=self._max_bytes
            )
        except OSError as error:
            with self._condition:
                self._failures += 1
                self._record_failure_diagnostics("journal_checkpoint", evidence_failure_code(error), 1)
                self._degraded = True
        else:
            with self._condition:
                self._journal_checkpoints += 1
                if invalid_records:
                    self._failures += invalid_records
                    self._record_failure_diagnostics("journal_checkpoint", "invalid_record", invalid_records)
                    self._degraded = True
                self._checkpoint_pending.difference_update(completed)
                for record_id in completed:
                    self._durable.pop(record_id, None)

    def _persist_command_activity(self, record: _CommandActivityRecord) -> None:
        if record.event != "PreToolUse":
            persist_deferred_post_hook_command_activity(
                store=self._store,
                harness=record.harness,
                correlation=record.correlation,
                has_command=record.has_command,
                succeeded=record.succeeded,
                invocation_preview=record.invocation_preview,
                activity_id=record.record_id if record.occurred_at is not None else None,
                occurred_at=datetime.fromisoformat(record.occurred_at) if record.occurred_at is not None else None,
            )
            return
        if not record.has_command or record.policy_action is None or record.occurred_at is None:
            return
        correlation = record.correlation
        # A prevented attempt cannot produce a post event. Keep its evidence
        # separate from a later approved retry of the same call.
        if correlation is not None and record.policy_action not in ("allow", "warn"):
            digest = hashlib.sha256(
                json.dumps(
                    [
                        "native-prevented-attempt-v1",
                        correlation.digest,
                        record.policy_action,
                        record.receipt_id,
                        record.prompted,
                        record.approval_reuse_status,
                    ]
                ).encode("utf-8")
            ).hexdigest()
            correlation = replace(correlation, digest=digest)
        evidence = build_native_pre_hook_evidence(
            activity_id=record.record_id,
            occurred_at=datetime.fromisoformat(record.occurred_at),
            harness=record.harness,
            policy_action=cast(GuardAction, record.policy_action),
            request_correlation=correlation,
            receipt_id=record.receipt_id,
            prompted=record.prompted,
            approval_reuse_status=ActivityApprovalReuseStatus(record.approval_reuse_status),
        )
        if not self._store.is_exact_command_activity_pre_replay(evidence):
            self._store.record_command_activity(evidence, invocation_preview=record.invocation_preview)



__all__ = [
    "RuntimeHookEvidenceWriter",
    "RuntimeHookEvidenceWriterStats",
    "persist_native_decision_receipt",
]
