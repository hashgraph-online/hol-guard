"""Bounded asynchronous persistence for non-authoritative hook evidence."""

from __future__ import annotations

import json
import os
import re
import stat
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict, cast, final
from uuid import uuid4

from ..cli.commands_support_command_activity import persist_deferred_post_hook_command_activity
from ..runtime.command_activity_contract import CorrelationHandle, CorrelationKind
from ..runtime.command_activity_correlation import (
    derive_proven_request_correlation,
    load_or_create_installation_correlation_key,
)
from ..runtime.command_activity_privacy import InstallationCorrelationKey
from ..sqlite_tuning import sqlite_connect_timeout_override
from ..store import GuardStore

_EVIDENCE_SCHEMA = "hol-guard-native-hook-evidence.v1"
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _safe_identifier(value: str, fallback: str = "unknown") -> str:
    normalized = value.strip()
    return normalized if _SAFE_IDENTIFIER.fullmatch(normalized) else fallback


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


@dataclass(frozen=True, slots=True)
class _CommandActivityRecord:
    record_id: str
    harness: str
    event: str
    correlation: CorrelationHandle | None
    has_command: bool
    succeeded: bool
    payload_bytes: int
    attempts: int = 0

    def serialized(self) -> bytes:
        return (
            json.dumps(
                {
                    "schema": _EVIDENCE_SCHEMA,
                    "record_id": _safe_identifier(self.record_id, "redacted"),
                    "harness": _safe_identifier(self.harness),
                    "event": _safe_identifier(self.event),
                    "correlation": (
                        {
                            "kind": _safe_identifier(self.correlation.kind.value),
                            "harness": _safe_identifier(self.correlation.harness),
                            "key_id": _safe_identifier(self.correlation.key_id, "redacted"),
                            "digest": _safe_identifier(self.correlation.digest, "redacted"),
                        }
                        if self.correlation is not None
                        else None
                    ),
                    "has_command": self.has_command,
                    "succeeded": self.succeeded,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )

    @classmethod
    def from_json(cls, value: object) -> _CommandActivityRecord | None:
        if not isinstance(value, dict):
            return None
        fields = cast(dict[str, object], value)
        record_id = fields.get("record_id")
        harness = fields.get("harness")
        event = fields.get("event")
        correlation_value = fields.get("correlation")
        has_command = fields.get("has_command")
        succeeded = fields.get("succeeded")
        if (
            not isinstance(record_id, str)
            or not isinstance(harness, str)
            or not isinstance(event, str)
            or not isinstance(has_command, bool)
            or not isinstance(succeeded, bool)
        ):
            return None
        correlation: CorrelationHandle | None = None
        if correlation_value is not None:
            if not isinstance(correlation_value, dict):
                return None
            correlation_fields = cast(dict[str, object], correlation_value)
            try:
                correlation = CorrelationHandle(
                    kind=CorrelationKind(str(correlation_fields.get("kind"))),
                    harness=str(correlation_fields.get("harness")),
                    key_id=str(correlation_fields.get("key_id")),
                    digest=str(correlation_fields.get("digest")),
                )
            except (TypeError, ValueError):
                return None
        record = cls(record_id, harness, event, correlation, has_command, succeeded, 0)
        return cls(
            record.record_id,
            record.harness,
            record.event,
            record.correlation,
            record.has_command,
            record.succeeded,
            len(record.serialized()),
        )


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
        self._records: deque[_CommandActivityRecord] = deque()
        self._durable: OrderedDict[str, _CommandActivityRecord] = OrderedDict()
        self._retry_attempts: dict[str, int] = {}
        self._in_flight = False
        self._queued_bytes = 0
        self._accepted = 0
        self._processed = 0
        self._dropped = 0
        self._failures = 0
        self._recovered = 0
        self._degraded = False
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
                    if self._drain_expired():
                        self._degraded = True
                        return
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
                            self._degraded = True
                            self._in_flight = False
                        continue
                    with self._condition:
                        self._durable[record.record_id] = record
                try:
                    with sqlite_connect_timeout_override(self._sqlite_timeout_seconds):
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
                        self._retry_attempts.pop(record.record_id, None)
                        _ = self._durable.pop(record.record_id, None)
                        durable_records = tuple(self._durable.values())
                    try:
                        self._rewrite_journal(durable_records)
                    except OSError:
                        with self._condition:
                            self._failures += 1
                            self._degraded = True
                    finally:
                        with self._condition:
                            self._in_flight = False

    def _next_batch(self) -> list[_CommandActivityRecord]:
        with self._condition:
            while not self._records and not self._stopping:
                _ = self._condition.wait()
            if not self._records:
                return []
            if not self._stopping and self._batch_wait_seconds:
                _ = self._condition.wait(timeout=self._batch_wait_seconds)
            batch: list[_CommandActivityRecord] = []
            while self._records and len(batch) < self._max_batch:
                record = self._records.popleft()
                self._queued_bytes -= record.payload_bytes
                batch.append(record)
            return batch

    def _drain_expired(self) -> bool:
        return self._stopping and self._drain_deadline is not None and time.monotonic() >= self._drain_deadline

    def _recover_journal(self) -> None:
        try:
            descriptor = self._open_journal(os.O_RDONLY)
        except FileNotFoundError:
            return
        except OSError:
            self._degraded = True
            self._failures += 1
            return
        try:
            metadata = os.fstat(descriptor)
            if metadata.st_size > self._max_bytes:
                self._degraded = True
                self._failures += 1
                return
            raw_lines = os.read(descriptor, self._max_bytes + 1).splitlines()
        finally:
            os.close(descriptor)
        for raw_line in raw_lines:
            try:
                decoded = cast(object, json.loads(raw_line))
                record = _CommandActivityRecord.from_json(decoded)
            except (json.JSONDecodeError, UnicodeDecodeError):
                record = None
            if record is None:
                self._degraded = True
                self._failures += 1
                continue
            if len(self._records) >= self._max_records or self._queued_bytes + record.payload_bytes > self._max_bytes:
                self._degraded = True
                self._failures += 1
                continue
            self._durable[record.record_id] = record
            self._records.append(record)
            self._queued_bytes += record.payload_bytes
            self._recovered += 1

    def _append_journal(self, record: _CommandActivityRecord) -> None:
        self._journal_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = self._open_journal(os.O_APPEND | os.O_CREAT | os.O_WRONLY)
        original_size = os.fstat(descriptor).st_size
        try:
            os.fchmod(descriptor, 0o600)
            self._write_all(descriptor, record.serialized())
            os.fsync(descriptor)
        except OSError:
            os.ftruncate(descriptor, original_size)
            raise
        finally:
            os.close(descriptor)

    def _rewrite_journal(self, records: tuple[_CommandActivityRecord, ...]) -> None:
        temporary = self._journal_path.with_name(f".{self._journal_path.name}.{uuid4().hex}.tmp")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            try:
                for record in records:
                    self._write_all(descriptor, record.serialized())
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, self._journal_path)
        finally:
            temporary.unlink(missing_ok=True)

    def _open_journal(self, flags: int) -> int:
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self._journal_path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            os.close(descriptor)
            raise OSError("evidence journal is not a private regular file")
        return descriptor

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise OSError("evidence journal write made no progress")
            view = view[written:]


def _payload_has_command(payload: Mapping[str, object]) -> bool:
    arguments = payload.get("tool_input", payload.get("arguments"))
    if isinstance(arguments, Mapping):
        command_arguments = cast(Mapping[object, object], arguments)
        for key in ("command", "cmd", "shell_command", "shellCommand"):
            value = command_arguments.get(key)
            if isinstance(value, str) and value.strip():
                return True
    for key in ("command", "cmd"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return True
    return False


__all__ = ["RuntimeHookEvidenceWriter", "RuntimeHookEvidenceWriterStats"]
