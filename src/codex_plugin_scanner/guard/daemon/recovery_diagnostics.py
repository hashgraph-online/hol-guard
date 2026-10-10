"""Bounded, local-only diagnostics for user-requested recovery."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from ..native_command_control_authority_io import (
    hold_owner_private_lock,
    read_private_state,
    write_private_state,
)
from .user_recovery_contract import (
    RecoveryContractError,
    validate_event_sequence,
    validate_recovery_snapshot,
)

DIAGNOSTICS_SCHEMA = "hol-guard-recovery-diagnostics.v1"
MAX_DIAGNOSTICS_BYTES = 64 * 1024
DIAGNOSTICS_STATE_NAME = "daemon-recovery-diagnostics.json"
DIAGNOSTICS_ARCHIVE_SCHEMA = "hol-guard-recovery-diagnostics-archive.v1"
MAX_RETAINED_INCIDENTS = 20
MAX_RETENTION_AGE = timedelta(days=7)
_MAX_REPORT_BYTES = 60 * 1024
_DIAGNOSTICS_LOCK_NAME = "daemon-recovery-diagnostics.lock"

_REPORT_FIELDS = frozenset(
    {
        "schema",
        "generatedAt",
        "operationId",
        "eventCount",
        "retainedEventCount",
        "truncated",
        "latest",
        "events",
    }
)
_SNAPSHOT_FIELDS = frozenset(
    {
        "schema",
        "capabilities",
        "operationId",
        "sequence",
        "startedAt",
        "updatedAt",
        "phase",
        "activeElapsedMs",
        "workerActive",
        "retryAllowed",
        "outcome",
        "reasonCode",
        "service",
        "protection",
        "requiresHumanAction",
        "checks",
    }
)
_CHECK_FIELDS = frozenset({"id", "result", "reasonCode"})


class RecoveryDiagnosticsError(ValueError):
    """Raised when a local diagnostics payload is not contract-safe."""


def _timestamp(value: object | None = None) -> str:
    current = value if isinstance(value, datetime) else datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.isoformat()


def _canonical_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise RecoveryDiagnosticsError("recovery_diagnostics_operation_id_invalid")
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise RecoveryDiagnosticsError("recovery_diagnostics_operation_id_invalid") from error
    if str(parsed) != value.lower():
        raise RecoveryDiagnosticsError("recovery_diagnostics_operation_id_invalid")
    return value.lower()


def _redact_snapshot(value: object) -> dict[str, object]:
    """Copy only the frozen public snapshot fields before validation.

    Recovery snapshots are already public DTOs.  Pruning before validation is
    intentional: a future private source field must be discarded rather than
    copied into a report or rejected after it has crossed the export boundary.
    """

    if not isinstance(value, Mapping):
        raise RecoveryDiagnosticsError("recovery_diagnostics_snapshot_invalid")
    candidate = {key: value[key] for key in _SNAPSHOT_FIELDS if key in value}
    raw_capabilities = candidate.get("capabilities")
    if isinstance(raw_capabilities, tuple):
        candidate["capabilities"] = list(raw_capabilities)
    raw_checks = candidate.get("checks")
    if isinstance(raw_checks, (tuple, list)):
        candidate["checks"] = [
            {key: check[key] for key in _CHECK_FIELDS if isinstance(check, Mapping) and key in check}
            for check in raw_checks
        ]
    try:
        return validate_recovery_snapshot(candidate, allow_inspection=False)
    except RecoveryContractError as error:
        raise RecoveryDiagnosticsError("recovery_diagnostics_snapshot_invalid") from error


def _read_events(value: object) -> list[dict[str, object]]:
    if isinstance(value, Mapping):
        sources: Iterable[object] = (value,)
    elif isinstance(value, (list, tuple)):
        sources = value
    else:
        raise RecoveryDiagnosticsError("recovery_diagnostics_events_invalid")
    events: list[dict[str, object]] = []
    previous: Mapping[str, object] | None = None
    for source in sources:
        snapshot = _redact_snapshot(source)
        try:
            snapshot = validate_event_sequence(previous, snapshot) if previous is not None else snapshot
        except RecoveryContractError as error:
            raise RecoveryDiagnosticsError("recovery_diagnostics_event_sequence_invalid") from error
        events.append(snapshot)
        previous = snapshot
    if not events:
        raise RecoveryDiagnosticsError("recovery_diagnostics_events_empty")
    return events


def _encode_report(report: Mapping[str, object]) -> bytes:
    payload = json.dumps(report, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(payload) > _MAX_REPORT_BYTES:
        raise RecoveryDiagnosticsError("recovery_diagnostics_too_large")
    return payload


def validate_recovery_diagnostics(value: object) -> dict[str, object]:
    """Validate a report while rejecting every field outside the allowlist."""

    if not isinstance(value, Mapping) or set(value) != _REPORT_FIELDS:
        raise RecoveryDiagnosticsError("recovery_diagnostics_fields_invalid")
    if value.get("schema") != DIAGNOSTICS_SCHEMA:
        raise RecoveryDiagnosticsError("recovery_diagnostics_schema_invalid")
    generated_at = value.get("generatedAt")
    if not isinstance(generated_at, str) or not generated_at:
        raise RecoveryDiagnosticsError("recovery_diagnostics_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise RecoveryDiagnosticsError("recovery_diagnostics_timestamp_invalid") from error
    if parsed.tzinfo is None:
        raise RecoveryDiagnosticsError("recovery_diagnostics_timestamp_invalid")
    operation_id = _canonical_uuid(value.get("operationId"))
    event_count = value.get("eventCount")
    retained_count = value.get("retainedEventCount")
    if type(event_count) is not int or event_count <= 0:
        raise RecoveryDiagnosticsError("recovery_diagnostics_event_count_invalid")
    if type(retained_count) is not int or retained_count <= 0 or retained_count > event_count:
        raise RecoveryDiagnosticsError("recovery_diagnostics_retained_count_invalid")
    if type(value.get("truncated")) is not bool or value["truncated"] != (retained_count < event_count):
        raise RecoveryDiagnosticsError("recovery_diagnostics_truncation_invalid")
    raw_events = value.get("events")
    if not isinstance(raw_events, list) or len(raw_events) != retained_count:
        raise RecoveryDiagnosticsError("recovery_diagnostics_events_invalid")
    events = _read_events(raw_events)
    if len(events) != retained_count:
        raise RecoveryDiagnosticsError("recovery_diagnostics_events_invalid")
    if any(event.get("operationId") != operation_id for event in events):
        raise RecoveryDiagnosticsError("recovery_diagnostics_operation_changed")
    latest = _redact_snapshot(value.get("latest"))
    if latest != events[-1]:
        raise RecoveryDiagnosticsError("recovery_diagnostics_latest_invalid")
    if latest.get("operationId") != operation_id:
        raise RecoveryDiagnosticsError("recovery_diagnostics_operation_changed")
    normalized = dict(value)
    normalized["operationId"] = operation_id
    normalized["events"] = events
    normalized["latest"] = latest
    _encode_report(normalized)
    return normalized


def build_recovery_diagnostics(
    snapshots: object,
    *,
    generated_at: datetime | None = None,
) -> dict[str, object]:
    """Build one bounded report from public recovery snapshots only."""

    events = _read_events(snapshots)
    operation_id = _canonical_uuid(events[-1]["operationId"])
    if any(event.get("operationId") != operation_id for event in events):
        raise RecoveryDiagnosticsError("recovery_diagnostics_operation_changed")
    report: dict[str, object] = {
        "schema": DIAGNOSTICS_SCHEMA,
        "generatedAt": _timestamp(generated_at),
        "operationId": operation_id,
        "eventCount": len(events),
        "retainedEventCount": len(events),
        "truncated": False,
        "latest": events[-1],
        "events": events,
    }
    try:
        validate_recovery_diagnostics(report)
        return report
    except RecoveryDiagnosticsError as error:
        if error.args != ("recovery_diagnostics_too_large",):
            raise

    original_count = len(events)
    for start in range(original_count):
        candidate = events[start:]
        report["events"] = candidate
        report["retainedEventCount"] = len(candidate)
        report["truncated"] = len(candidate) < original_count
        try:
            validate_recovery_diagnostics(report)
        except RecoveryDiagnosticsError as size_error:
            if size_error.args != ("recovery_diagnostics_too_large",):
                raise
            continue
        report["events"] = candidate
        report["retainedEventCount"] = len(candidate)
        report["truncated"] = len(candidate) < original_count
        return report
    raise RecoveryDiagnosticsError("recovery_diagnostics_too_large")


def encode_recovery_diagnostics(value: object) -> bytes:
    """Return compact UTF-8 JSON suitable for local persistence or export."""

    return _encode_report(validate_recovery_diagnostics(value))


def _load_archive(guard_home: Path) -> list[dict[str, object]]:
    payload = read_private_state(guard_home, DIAGNOSTICS_STATE_NAME, MAX_DIAGNOSTICS_BYTES)
    if payload is None:
        return []
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecoveryDiagnosticsError("recovery_diagnostics_state_invalid") from error
    # Accept the pre-archive v1 file as a one-entry archive during upgrade.
    if isinstance(decoded, Mapping) and decoded.get("schema") == DIAGNOSTICS_SCHEMA:
        return [validate_recovery_diagnostics(decoded)]
    if not isinstance(decoded, Mapping) or set(decoded) != {"schema", "reports"}:
        raise RecoveryDiagnosticsError("recovery_diagnostics_state_invalid")
    raw_reports = decoded.get("reports")
    if decoded.get("schema") != DIAGNOSTICS_ARCHIVE_SCHEMA or not isinstance(raw_reports, list):
        raise RecoveryDiagnosticsError("recovery_diagnostics_state_invalid")
    try:
        return [validate_recovery_diagnostics(report) for report in raw_reports]
    except RecoveryDiagnosticsError as error:
        raise RecoveryDiagnosticsError("recovery_diagnostics_state_invalid") from error


def _encode_archive(reports: list[dict[str, object]]) -> bytes:
    payload = json.dumps(
        {"schema": DIAGNOSTICS_ARCHIVE_SCHEMA, "reports": reports},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(payload) > MAX_DIAGNOSTICS_BYTES:
        raise RecoveryDiagnosticsError("recovery_diagnostics_archive_too_large")
    return payload


def _retention_now(value: datetime | None = None) -> datetime:
    current = value if isinstance(value, datetime) else datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def _report_sort_key(candidate: Mapping[str, object]) -> tuple[datetime, str]:
    generated_at = candidate.get("generatedAt")
    if not isinstance(generated_at, str):
        raise RecoveryDiagnosticsError("recovery_diagnostics_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise RecoveryDiagnosticsError("recovery_diagnostics_timestamp_invalid") from error
    if parsed.tzinfo is None:
        raise RecoveryDiagnosticsError("recovery_diagnostics_timestamp_invalid")
    return parsed.astimezone(timezone.utc), str(candidate["operationId"])


def _prune_archive(
    guard_home: Path,
    reports: list[dict[str, object]],
    *,
    now: datetime | None = None,
) -> list[dict[str, object]]:
    cutoff = _retention_now(now) - MAX_RETENTION_AGE
    retained = [candidate for candidate in reports if _report_sort_key(candidate)[0] >= cutoff]
    retained.sort(key=_report_sort_key)
    if len(retained) != len(reports):
        # Retention compaction is optional during reads. Keep the bounded
        # in-memory view usable even when the archive cannot be rewritten.
        with suppress(OSError):
            write_private_state(
                guard_home,
                DIAGNOSTICS_STATE_NAME,
                _encode_archive(retained),
                MAX_DIAGNOSTICS_BYTES,
            )
    return retained


def persist_recovery_diagnostics(
    guard_home: Path,
    snapshots: object,
    *,
    generated_at: datetime | None = None,
) -> dict[str, object]:
    """Atomically retain a bounded, owner-private incident archive."""

    report = build_recovery_diagnostics(snapshots, generated_at=generated_at)
    with hold_owner_private_lock(guard_home, _DIAGNOSTICS_LOCK_NAME):
        now = _retention_now()
        reports = []
        for candidate in _prune_archive(guard_home, _load_archive(guard_home), now=now):
            if candidate["operationId"] != report["operationId"]:
                reports.append(candidate)
        reports.append(report)
        reports.sort(key=_report_sort_key)
        reports = reports[-MAX_RETAINED_INCIDENTS:]
        while reports:
            try:
                payload = _encode_archive(reports)
                break
            except RecoveryDiagnosticsError as error:
                if error.args != ("recovery_diagnostics_archive_too_large",) or len(reports) == 1:
                    raise
                reports.pop(0)
        else:
            raise RecoveryDiagnosticsError("recovery_diagnostics_archive_empty")
        write_private_state(guard_home, DIAGNOSTICS_STATE_NAME, payload, MAX_DIAGNOSTICS_BYTES)
    return report


def load_recovery_diagnostics(guard_home: Path) -> dict[str, object] | None:
    with hold_owner_private_lock(guard_home, _DIAGNOSTICS_LOCK_NAME):
        reports = _prune_archive(guard_home, _load_archive(guard_home))
    return reports[-1] if reports else None


def recovery_diagnostics_for_operation(guard_home: Path, operation_id: str) -> dict[str, object]:
    expected = _canonical_uuid(operation_id)
    with hold_owner_private_lock(guard_home, _DIAGNOSTICS_LOCK_NAME):
        for report in reversed(_prune_archive(guard_home, _load_archive(guard_home))):
            if report.get("operationId") == expected:
                return report
    raise KeyError(expected)


# Names used by native/CLI adapters and older callers.
build_diagnostics_report = build_recovery_diagnostics
encode_diagnostics_report = encode_recovery_diagnostics
load_diagnostics_report = load_recovery_diagnostics
persist_diagnostics_report = persist_recovery_diagnostics

__all__ = [
    "DIAGNOSTICS_ARCHIVE_SCHEMA",
    "DIAGNOSTICS_SCHEMA",
    "DIAGNOSTICS_STATE_NAME",
    "MAX_DIAGNOSTICS_BYTES",
    "MAX_RETAINED_INCIDENTS",
    "RecoveryDiagnosticsError",
    "build_diagnostics_report",
    "build_recovery_diagnostics",
    "encode_diagnostics_report",
    "encode_recovery_diagnostics",
    "load_diagnostics_report",
    "load_recovery_diagnostics",
    "persist_diagnostics_report",
    "persist_recovery_diagnostics",
    "recovery_diagnostics_for_operation",
    "validate_recovery_diagnostics",
]
