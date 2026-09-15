"""Private, bounded journal primitives for hook evidence persistence."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import cast
from uuid import uuid4

from ..action_lattice import is_guard_action
from ..native_decision_receipt import (
    NATIVE_HOOK_DECISION_RECEIPT_SCHEMA,
    validate_native_decision_receipt,
)
from ..runtime.command_activity_contract import CorrelationHandle, CorrelationKind
from ..runtime.command_activity_display import INVOCATION_PREVIEW_MAX_CHARS

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised only on Windows
    fcntl = None  # type: ignore[assignment]

try:
    import msvcrt
except ImportError:  # pragma: no cover - exercised only on Unix
    msvcrt = None  # type: ignore[assignment]

_EVIDENCE_SCHEMA = "hol-guard-native-hook-evidence.v1"
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _safe_identifier(value: str, fallback: str = "unknown") -> str:
    normalized = value.strip()
    return normalized if _SAFE_IDENTIFIER.fullmatch(normalized) else fallback


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
    policy_action: str | None = None
    occurred_at: str | None = None
    receipt_id: str | None = None
    prompted: bool = False
    approval_reuse_status: str = "not-applicable"
    invocation_preview: str | None = None

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
                    "policy_action": self.policy_action,
                    "occurred_at": self.occurred_at,
                    "receipt_id": self.receipt_id,
                    "interaction_observed": self.prompted,
                    "approval_reuse_status": self.approval_reuse_status,
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
        policy_action = fields.get("policy_action")
        if policy_action is not None and not is_guard_action(policy_action):
            return None
        occurred_at = fields.get("occurred_at")
        if occurred_at is not None:
            try:
                if not isinstance(occurred_at, str) or datetime.fromisoformat(
                    occurred_at
                ).utcoffset() != timezone.utc.utcoffset(None):
                    return None
            except ValueError:
                return None
        if policy_action is not None and (event != "PreToolUse" or occurred_at is None):
            return None
        receipt_id = fields.get("receipt_id")
        prompted = fields.get("interaction_observed", False)
        reuse = fields.get("approval_reuse_status", "not-applicable")
        if receipt_id is not None and (not isinstance(receipt_id, str) or not _SAFE_IDENTIFIER.fullmatch(receipt_id)):
            return None
        if (
            type(prompted) is not bool
            or reuse not in ("not-applicable", "accepted", "rejected")
            or (prompted and reuse == "accepted")
        ):
            return None
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
        record = cls(
            record_id,
            harness,
            event,
            correlation,
            has_command,
            succeeded,
            0,
            policy_action=cast(str | None, policy_action),
            occurred_at=cast(str | None, occurred_at),
            receipt_id=cast(str | None, receipt_id),
            prompted=prompted,
            approval_reuse_status=cast(str, reuse),
        )
        return cls(
            record.record_id,
            record.harness,
            record.event,
            record.correlation,
            record.has_command,
            record.succeeded,
            len(record.serialized()),
            policy_action=cast(str | None, policy_action),
            occurred_at=cast(str | None, occurred_at),
            receipt_id=record.receipt_id,
            prompted=record.prompted,
            approval_reuse_status=record.approval_reuse_status,
        )


@dataclass(frozen=True, slots=True)
class _NativeDecisionReceiptRecord:
    """A validated aggregate-only receipt retained by the bounded writer."""

    receipt: dict[str, object]
    payload_bytes: int
    attempts: int = 0

    @property
    def record_id(self) -> str:
        return str(self.receipt["decision_id"])

    def serialized(self) -> bytes:
        return (
            json.dumps(
                self.receipt,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )

    @classmethod
    def from_json(cls, value: object) -> _NativeDecisionReceiptRecord | None:
        if not isinstance(value, Mapping) or value.get("schema") != NATIVE_HOOK_DECISION_RECEIPT_SCHEMA:
            return None
        receipt = validate_native_decision_receipt(value)
        if receipt is None:
            return None
        record = cls(receipt=receipt, payload_bytes=0)
        return cls(receipt=receipt, payload_bytes=len(record.serialized()))


_EvidenceRecord = _CommandActivityRecord | _NativeDecisionReceiptRecord


def _read_journal_records_locked(path: Path, *, max_bytes: int) -> tuple[list[_EvidenceRecord], int]:
    try:
        descriptor = _open_journal(path, os.O_RDONLY)
    except FileNotFoundError:
        return [], 0
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_size > max_bytes:
            raise OSError("evidence journal exceeds the configured size limit")
        raw_lines = os.read(descriptor, max_bytes + 1).splitlines()
    finally:
        os.close(descriptor)
    records: list[_EvidenceRecord] = []
    invalid_records = 0
    for raw_line in raw_lines:
        try:
            decoded = cast(object, json.loads(raw_line))
            record = _NativeDecisionReceiptRecord.from_json(decoded)
            if record is None:
                record = _CommandActivityRecord.from_json(decoded)
        except (json.JSONDecodeError, UnicodeDecodeError):
            record = None
        if record is None:
            invalid_records += 1
            continue
        records.append(record)
    return records, invalid_records


def recover_journal_records(path: Path, *, max_bytes: int) -> tuple[list[_EvidenceRecord], int]:
    with _journal_lock(path):
        records, invalid_records = _read_journal_records_locked(path, max_bytes=max_bytes)
        return _attach_invocation_previews(path, records), invalid_records


def _preview_sidecar_path(path: Path) -> Path:
    return path.with_name(f"{path.stem}.preview{path.suffix}")


def _validated_sidecar_preview(value: object) -> str | None:
    if not isinstance(value, str) or "\x00" in value:
        return None
    stripped = value.strip()
    if not stripped or len(stripped) > INVOCATION_PREVIEW_MAX_CHARS:
        return None
    return stripped


def _read_preview_sidecar(path: Path) -> dict[str, str]:
    sidecar = _preview_sidecar_path(path)
    try:
        raw_lines = sidecar.read_bytes().splitlines()
    except FileNotFoundError:
        return {}
    previews: dict[str, str] = {}
    for raw_line in raw_lines:
        try:
            decoded = json.loads(raw_line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(decoded, dict):
            continue
        record_id = decoded.get("record_id")
        preview = _validated_sidecar_preview(decoded.get("invocation_preview"))
        if isinstance(record_id, str) and preview is not None:
            previews[record_id] = preview
    return previews


def _append_preview_sidecar(path: Path, record: _EvidenceRecord) -> None:
    if not isinstance(record, _CommandActivityRecord):
        return
    preview = _validated_sidecar_preview(record.invocation_preview)
    if preview is None:
        return
    sidecar = _preview_sidecar_path(path)
    payload = (
        json.dumps(
            {"record_id": record.record_id, "invocation_preview": preview},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    descriptor = _open_journal(sidecar, os.O_APPEND | os.O_CREAT | os.O_WRONLY)
    try:
        _apply_private_file_mode(descriptor)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rewrite_preview_sidecar(path: Path, remaining: tuple[_EvidenceRecord, ...]) -> None:
    keep_ids = {record.record_id for record in remaining}
    kept = {record_id: preview for record_id, preview in _read_preview_sidecar(path).items() if record_id in keep_ids}
    sidecar = _preview_sidecar_path(path)
    if not kept:
        sidecar.unlink(missing_ok=True)
        return
    temporary = sidecar.with_name(f".{sidecar.name}.{uuid4().hex}.tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        try:
            for record_id, preview in kept.items():
                _write_all(
                    descriptor,
                    json.dumps(
                        {"record_id": record_id, "invocation_preview": preview},
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("utf-8")
                    + b"\n",
                )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, sidecar)
    finally:
        temporary.unlink(missing_ok=True)


def _attach_invocation_previews(path: Path, records: list[_EvidenceRecord]) -> list[_EvidenceRecord]:
    previews = _read_preview_sidecar(path)
    if not previews:
        return records
    attached: list[_EvidenceRecord] = []
    for record in records:
        if isinstance(record, _CommandActivityRecord):
            preview = previews.get(record.record_id)
            if preview is not None:
                record = replace(record, invocation_preview=preview)
        attached.append(record)
    return attached


def _apply_private_file_mode(descriptor: int) -> None:
    if os.name != "nt" and hasattr(os, "fchmod"):
        os.fchmod(descriptor, 0o600)


def append_journal(path: Path, record: _EvidenceRecord) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _journal_lock(path):
        descriptor = _open_journal(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY)
        original_size = os.fstat(descriptor).st_size
        try:
            _apply_private_file_mode(descriptor)
            _write_all(descriptor, record.serialized())
            os.fsync(descriptor)
            _append_preview_sidecar(path, record)
        except OSError:
            os.ftruncate(descriptor, original_size)
            raise
        finally:
            os.close(descriptor)


def rewrite_journal(path: Path, *, remove_record_id: str, max_bytes: int) -> int:
    """Remove one completed record without erasing another writer's records."""

    with _journal_lock(path):
        records, invalid_records = _read_journal_records_locked(path, max_bytes=max_bytes)
        remaining = tuple(record for record in records if record.record_id != remove_record_id)
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            try:
                for record in remaining:
                    _write_all(descriptor, record.serialized())
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
            _rewrite_preview_sidecar(path, remaining)
        finally:
            temporary.unlink(missing_ok=True)
    return invalid_records


@contextmanager
def _journal_lock(path: Path) -> Iterator[None]:
    """Serialize journal reads, appends, and rewrites across processes."""

    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    locked = False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError("evidence journal lock is not a private regular file")
        _apply_private_file_mode(descriptor)
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            locked = True
        elif msvcrt is not None:  # pragma: no cover - Windows CI is waived
            os.ftruncate(descriptor, 1)
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            locked = True
        else:  # pragma: no cover - no supported platform takes this path
            raise OSError("evidence journal locking is unavailable")
        yield
    finally:
        if locked and fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        elif locked and msvcrt is not None:  # pragma: no cover - Windows CI is waived
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        os.close(descriptor)


def _open_journal(path: Path, flags: int) -> int:
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        os.close(descriptor)
        raise OSError("evidence journal is not a private regular file")
    return descriptor


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written < 1:
            raise OSError("evidence journal write made no progress")
        view = view[written:]


def _payload_has_command(payload: Mapping[str, object]) -> bool:
    arguments = payload.get("tool_input", payload.get("toolInput", payload.get("arguments")))
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


__all__ = [
    "_CommandActivityRecord",
    "_EvidenceRecord",
    "_NativeDecisionReceiptRecord",
    "_payload_has_command",
    "append_journal",
    "recover_journal_records",
    "rewrite_journal",
]
