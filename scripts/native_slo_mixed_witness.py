"""Private, bounded observation of real native receipts and journal I/O.

Wrappers call production functions unchanged. They retain only correlation IDs
and authenticated receipt fields, never hook text. An explicitly supplied SQLite
observer adds separate VFS-level counters. Python journal counters never imply
kernel or physical SQLite I/O coverage.
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
import time
from collections import Counter
from collections.abc import Mapping
from contextlib import ExitStack, nullcontext
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

from scripts.native_slo_mixed_receipt_reader import InstalledReceiptReader
from scripts.native_slo_mixed_request import attempt_label, request_attempt

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_queue_observation import EvidenceQueueObservation
    from scripts.native_slo_sqlite_vfs import SQLiteVFSObservation

MAX_ATTEMPTS = 100_000
MAX_CONTROL_ACTIONS = 64
_RECEIPT_FIELDS = ("decision_id", "policy_generation", "policy_digest", "decision", "policy_action")


def writer_drained(stats: Mapping[str, Any]) -> bool:
    """Account for a batch removed from the queue but not yet journaled."""
    return (
        all(stats.get(key) == 0 for key in ("queued", "durable_pending", "receipt_durable_pending"))
        and stats.get("in_flight") is False
        and isinstance(stats.get("accepted"), int)
        and stats.get("accepted") == stats.get("processed")
    )


class _JournalOS:
    def __init__(self, original: Any, witness: ReceiptWitness) -> None:
        self.original, self.witness = original, witness

    def __getattr__(self, name: str) -> Any:
        return getattr(self.original, name)

    def write(self, descriptor: int, data: Any) -> int:
        try:
            size = self.original.write(descriptor, data)
        except OSError:
            self.witness.count("journal_write_failures")
            raise
        self.witness.count("journal_write_calls")
        self.witness.count("journal_written_bytes", size)
        return size

    def fsync(self, descriptor: int) -> None:
        try:
            self.original.fsync(descriptor)
        except OSError:
            self.witness.count("journal_file_fsync_failures")
            raise
        self.witness.count("journal_file_fsync_calls")


class ReceiptWitness:
    def __init__(
        self,
        session: Any,
        *,
        maximum: int,
        receipt_profile: str = "candidate",
        queue_observation: EvidenceQueueObservation | None = None,
        sqlite_observer: SQLiteVFSObservation | None = None,
        monotonic_origin: float | None = None,
    ) -> None:
        if not 1 <= maximum <= MAX_ATTEMPTS + MAX_CONTROL_ACTIONS:
            raise ValueError("mixed receipt bound invalid")
        self.session, self.maximum = session, maximum
        self.queue_observation = queue_observation
        self.sqlite_observer = sqlite_observer
        self.reader = InstalledReceiptReader(session.store, profile=receipt_profile)
        self.started = time.monotonic()
        if monotonic_origin is not None:
            if (
                type(monotonic_origin) not in (int, float)
                or not 0 <= monotonic_origin <= self.started
                or not math.isfinite(monotonic_origin)
            ):
                raise ValueError("mixed receipt clock origin invalid")
            self.started = monotonic_origin
        self._stack = ExitStack()
        self._lock = threading.Lock()
        self._rows: dict[str, dict[str, Any]] = {}
        self._ids: dict[str, str] = {}
        self._counts: Counter[str] = Counter()
        self._max_commit_age_ms = 0.0
        self._directory_sync_observable = False
        self._instrumented = False
        self._instrumentation_active = False

    def count(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counts[name] += value

    def observe(self, attempt: object, edge: object) -> None:
        attempt = attempt_label(attempt)
        if attempt is None:
            return
        receipt = edge.get("receipt") if isinstance(edge, Mapping) else None
        if not isinstance(receipt, Mapping):
            self.count("native_without_receipt")
            return
        identity = receipt.get("decision_id")
        if not isinstance(identity, str) or re.fullmatch("[0-9a-f]{64}", identity) is None:
            self.count("invalid_receipt_identity")
            return
        with self._lock:
            if attempt in self._rows or identity in self._ids:
                self._counts["duplicate_observations"] += 1
                return
            if len(self._rows) >= self.maximum:
                self._counts["witness_overflow"] += 1
                return
            self._rows[attempt] = {
                "attempt": attempt,
                **{key: receipt.get(key) for key in _RECEIPT_FIELDS},
                "event": receipt.get("event_name"),
                "program_binding_present": isinstance(receipt.get("command_extensions"), Mapping),
                "native_finished_ms": (time.monotonic() - self.started) * 1000,
                "writer_admitted": None,
                "committed": False,
                "commit_binding_valid": None,
            }
            self._ids[identity] = attempt

    def admitted(self, receipt: object, accepted: bool) -> None:
        identity = receipt.get("decision_id") if isinstance(receipt, Mapping) else None
        with self._lock:
            attempt = self._ids.get(str(identity))
            if attempt is not None:
                self._rows[attempt]["writer_admitted"] = accepted

    def __enter__(self) -> ReceiptWitness:
        from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal

        worker = self.session.daemon._server.hook_worker
        writer = self.session.daemon._server.runtime_hook_evidence_writer
        review, submit = worker._review_raw_hook_native, writer.submit_native_decision_receipt

        def observed_review(**kwargs: Any) -> Any:
            result = review(**kwargs)
            self.observe(request_attempt(kwargs.get("payload")), result)
            return result

        def observed_submit(*args: Any, **kwargs: Any) -> Any:
            result = submit(*args, **kwargs)
            self.admitted(kwargs.get("receipt", args[0] if args else None), result is True)
            return result

        directory_sync = getattr(journal, "fsync_directory", None)
        if not callable(directory_sync) and not self.reader.legacy:
            raise RuntimeError("candidate journal directory sync instrumentation unavailable")
        self._directory_sync_observable = callable(directory_sync)

        def observed_directory_sync(*args: Any, **kwargs: Any) -> Any:
            self.count("journal_directory_sync_attempts")
            assert callable(directory_sync)
            return directory_sync(*args, **kwargs)

        try:
            if self.sqlite_observer is not None:
                self._stack.enter_context(self.sqlite_observer)
                self.sqlite_observer.install(self.session.store, writer)
            if self.queue_observation is not None:
                if not self.queue_observation.attach(writer):
                    raise RuntimeError("writer queue observation admission failed")
                self._stack.callback(self.queue_observation.detach, writer)
            self._stack.enter_context(patch.object(worker, "_review_raw_hook_native", observed_review))
            self._stack.enter_context(patch.object(writer, "submit_native_decision_receipt", observed_submit))
            self._stack.enter_context(patch.object(journal, "os", _JournalOS(journal.os, self)))
            if self._directory_sync_observable:
                self._stack.enter_context(patch.object(journal, "fsync_directory", observed_directory_sync))
            self._instrumented = True
            self._instrumentation_active = True
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        try:
            self._stack.close()
        finally:
            self._instrumentation_active = False

    def reconcile(self, *, verify_all: bool = False) -> None:
        """Verify exact observed identities and bindings in committed SQLite rows."""
        scope = self.sqlite_observer.readback() if self.sqlite_observer is not None else nullcontext()
        with scope:
            with self._lock:
                pending = [dict(row) for row in self._rows.values() if verify_all or not row["committed"]]
            for offset in range(0, len(pending), 500):
                batch = pending[offset : offset + 500]
                marks = ",".join("?" for _ in batch)
                with self.session.store._connect() as connection:
                    persisted = connection.execute(
                        f"select {','.join(_RECEIPT_FIELDS)} from native_hook_decision_receipts "
                        f"where decision_id in ({marks})",
                        tuple(row["decision_id"] for row in batch),
                    ).fetchall()
                # The public store getter reconstructs and validates the complete
                # native identity, including its optional command-extension binding.
                verified = {stored["decision_id"]: self.reader.read(stored["decision_id"]) for stored in persisted}
                current = time.monotonic()
                with self._lock:
                    if verify_all:
                        for expected in batch:
                            self._rows[expected["attempt"]]["committed"] = False
                    for stored in persisted:
                        row = self._rows[self._ids[stored["decision_id"]]]
                        row["committed"] = True
                        row["commit_binding_valid"] = verified[stored["decision_id"]] is not None and all(
                            row[field] == stored[field] for field in _RECEIPT_FIELDS
                        )
                        row.setdefault("commit_observed_ms", (current - self.started) * 1000)
                        self._max_commit_age_ms = max(
                            self._max_commit_age_ms, row["commit_observed_ms"] - row["native_finished_ms"]
                        )

    def row(self, attempt: str) -> dict[str, Any] | None:
        with self._lock:
            result = self._rows.get(attempt)
            return dict(result) if result is not None else None

    def first_decision(self, binding: Mapping[str, Any], action: str, *, since: float) -> dict[str, Any] | None:
        with self._lock:
            rows = [
                row
                for row in self._rows.values()
                if row["policy_generation"] == binding["generation"]
                and row["policy_digest"] == binding["policy_digest"]
                and row["policy_action"] == action
                and row["decision"] == ("allow" if action == "allow" else "deny")
                and row["native_finished_ms"] >= (since - self.started) * 1000
            ]
            return dict(min(rows, key=lambda row: row["native_finished_ms"])) if rows else None

    def page(self, offset: int, limit: int) -> dict[str, object]:
        if not 0 <= offset <= self.maximum or not 1 <= limit <= 128:
            raise ValueError("mixed page outside bound")
        with self._lock:
            rows = list(self._rows.values())[offset : offset + limit]
            return {"rows": [dict(row) for row in rows], "total": len(self._rows)}

    def report(self) -> dict[str, object]:
        queue_report = self.queue_observation.report() if self.queue_observation is not None else None
        sqlite_report = self.sqlite_observer.report() if self.sqlite_observer is not None else None
        with self._lock:
            rows = list(self._rows.values())
            ids = sorted(row["decision_id"] for row in rows if row["committed"])
            pending_age = max(
                (
                    (time.monotonic() - self.started) * 1000 - row["native_finished_ms"]
                    for row in rows
                    if not row["committed"]
                ),
                default=0.0,
            )
            counts = dict(self._counts)
            return {
                "native_receipts": len(rows),
                "receipt_profile": self.reader.profile,
                "binding_aware_reader": not self.reader.legacy,
                "writer_admitted": sum(row["writer_admitted"] is True for row in rows),
                "writer_rejected": sum(row["writer_admitted"] is False for row in rows),
                "writer_admission_unobserved": sum(row["writer_admitted"] is None for row in rows),
                "pre_receipts_without_program_binding": sum(
                    self.reader.profile == "candidate"
                    and row["event"] == "PreToolUse"
                    and not row["program_binding_present"]
                    for row in rows
                ),
                "committed": len(ids),
                "missing": len(rows) - len(ids),
                "binding_mismatches": sum(row["commit_binding_valid"] is False for row in rows),
                "committed_identity_digest": hashlib.sha256("\n".join(ids).encode("ascii")).hexdigest(),
                "commit_age_upper_bound_ms": max(self._max_commit_age_ms, pending_age),
                "pending_commit_age_ms": pending_age,
                "commit_age_scope": "native_finish_to_sql_observation_including_poll_delay",
                "observations": counts,
                "journal_io": {
                    key: counts.get(key, 0)
                    if key != "journal_directory_sync_attempts" or self._directory_sync_observable
                    else None
                    for key in (
                        "journal_write_calls",
                        "journal_written_bytes",
                        "journal_write_failures",
                        "journal_file_fsync_calls",
                        "journal_file_fsync_failures",
                        "journal_directory_sync_attempts",
                    )
                },
                "journal_instrumentation_installed": self._instrumented,
                "writer_queue_observation": queue_report,
                "sqlite_vfs_observation": sqlite_report,
                "sqlite_fsync_calls": None,
                "sqlite_written_bytes": None,
                "full_persistence_metric_coverage": False,
                "unavailable": {
                    "sqlite_fsync_calls": "VFS_xSync_is_not_a_kernel_syscall_count"
                    if sqlite_report
                    else "sqlite_vfs_not_instrumented",
                    "sqlite_written_bytes": "VFS_xWrite_status_is_not_a_kernel_byte_count"
                    if sqlite_report
                    else "sqlite_vfs_not_instrumented",
                    "directory_fsync_calls": "production_helper_can_skip_unsupported_directory_sync",
                    "writer_queue_only_age_ms": "see_separate_bounded_queue_observation"
                    if queue_report
                    else "commit_age_includes_journal_sql_and_poll_delay",
                },
            }
