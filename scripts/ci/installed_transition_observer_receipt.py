"""Independently replay bounded producer diagnostics after the worker exits."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from scripts.ci.installed_transition_observer_support import (
    MAX_LEDGER_BYTES,
    MAX_PROCESSES,
    MAX_RECORDS,
    MAX_REPORT_BYTES,
    identity,
    observer_directory,
    private_directory,
    sha256,
)

_EVENTS = frozenset(
    {
        "registered",
        "observer_ready",
        "subprocess_intent",
        "process_launch_attempt",
        "observer_changed",
        "interpreter_changed",
        "process_launch_exception",
        "native_client_entry",
        "review_send_entry",
        "snapshot_validator_entry",
        "call_started",
        "call_returned",
        "sealed",
        "snapshot_unknown_field_raised",
        "thread_creation_attempt",
    }
)


def _read(path: Path) -> tuple[bytes, list[dict[str, Any]]]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_LEDGER_BYTES:
            raise ValueError("ledger_bounds_invalid")
        if os.name != "nt" and (before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o077):
            raise ValueError("ledger_not_private")
        chunks = []
        total = 0
        while total <= MAX_LEDGER_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_LEDGER_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if total != before.st_size or any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ValueError("ledger_changed_during_read")
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if not data.endswith(b"\n"):
        raise ValueError("ledger_truncated")
    lines = data.splitlines()
    if len(lines) > MAX_RECORDS:
        raise ValueError("ledger_record_limit")
    records = [json.loads(line) for line in lines]
    if not all(isinstance(record, dict) for record in records):
        raise ValueError("ledger_record_invalid")
    return data, records


def _records_valid(records: list[dict[str, Any]], pid: int, errors: set[str]) -> bool:
    valid = True
    for index, record in enumerate(records, 1):
        if (
            type(record.get("sequence")) is not int
            or record["sequence"] != index
            or type(record.get("pid")) is not int
            or record["pid"] != pid
            or record.get("event") not in _EVENTS
        ):
            errors.add("ledger_sequence_or_identity_invalid")
            valid = False
    if not records or records[0].get("event") != "registered":
        errors.add("registration_missing")
        valid = False
    elif (
        type(records[0].get("parent_pid")) is not int
        or records[0]["parent_pid"] <= 0
        or not isinstance(records[0].get("run_id"), str)
        or len(records[0]["run_id"]) != 32
        or any(character not in "0123456789abcdef" for character in records[0]["run_id"])
        or records[0].get("role") not in {"phase", "python_spawn"}
        or sum(record.get("event") == "registered" for record in records) != 1
    ):
        errors.add("registration_contract_invalid")
        valid = False
    return valid


def _call_history(records: list[dict[str, Any]], errors: set[str]) -> None:
    active = {}
    seen = set()
    for record in records:
        if record["event"] not in {"call_started", "call_returned"}:
            continue
        call_id = record.get("call_id")
        if type(call_id) is not int or call_id <= 0:
            errors.add("call_identity_invalid")
            continue
        if record["event"] == "call_started":
            if call_id in seen:
                errors.add("call_identity_repeated")
            seen.add(call_id)
            active[call_id] = record
            continue
        prior = active.pop(call_id, None)
        if prior is None or any(prior.get(key) != record.get(key) for key in ("function", "code_sha256")):
            errors.add("call_return_unattributed")
        function = record.get("function")
        if (
            function in {"retire_worker_slot", "close_contained", "_finish_service", "_finish_service_locked"}
            and record.get("contained") is not True
        ):
            errors.add("original_cleanup_unconfirmed")
        if (
            function == "run_isolated_hook_process"
            and record.get("operation_kind") in {"native_nonspawning_probe", "native_stop"}
            and (
                type(record.get("return_code")) is not int
                or any(record.get(key) is not False for key in ("timed_out", "containment_failed", "limit_exceeded"))
            )
        ):
            errors.add("bounded_process_completion_unconfirmed")
        if function == "spawnv_passfds" and type(record.get("child_pid")) is not int:
            errors.add("spawn_return_unattributed")
    if active:
        errors.add("unfinished_call_history")
    returns = {
        record.get("call_id"): record
        for record in records
        if record["event"] == "call_returned" and type(record.get("call_id")) is int
    }
    for record in records:
        if record["event"] == "process_launch_attempt":
            owner = record.get("owner_call_id")
            returned = returns.get(owner) if type(owner) is int else None
            if returned is None or type(returned.get("child_pid")) is not int:
                errors.add("process_launch_unattributed")


def _process_row(pid: int, registered: dict[str, Any] | None, errors: set[str]) -> dict[str, Any]:
    current = identity(pid)
    row = {
        "pid": pid,
        "registered": registered is not None,
        "identity_status": current["identity_status"],
        "exit_observed": False,
        "sealed": False,
    }
    if registered is None:
        errors.add("child_registration_missing")
        return row
    marker = registered.get("start_marker")
    row["start_marker"] = marker
    row["executable_sha256"] = registered.get("executable_sha256")
    if registered.get("identity_status") != "observed" or not isinstance(marker, str):
        errors.add("registration_identity_unknown")
    elif current["identity_status"] == "not_present":
        row["exit_observed"] = True
    elif current.get("start_marker") != marker and current.get("start_marker") is not None:
        row.update(exit_observed=True, identity_status="pid_reused")
    elif current["identity_status"] == "exited_not_reaped":
        row["exit_observed"] = True
    else:
        errors.add("registered_process_exit_unconfirmed")
    return row


def collect(fixture_root: Path) -> dict[str, Any]:
    """No diagnostic outcome grants expected-negative credit or native retirement."""
    report: dict[str, Any] = {
        "schema": "hol-guard.transition-producer-observation.v1",
        "diagnostic_only": True,
        "proof_verified": False,
        "counts": {"native_client_entries": 0, "review_send_entries": 0, "process_launch_attempts": 0},
        "processes": [],
        "events": [],
        "incomplete": [],
        "coverage_qualified": False,
        "bootstrap_attestation_qualified": False,
    }
    errors = {"diagnostic_prototype_not_qualified", "bootstrap_source_attestation_pending"}
    ledgers: dict[int, list[dict[str, Any]]] = {}
    all_events = []
    try:
        directory = observer_directory(fixture_root)
        private_directory(directory)
        entries = []
        with os.scandir(directory) as iterator:
            for entry in iterator:
                if len(entries) >= MAX_PROCESSES:
                    raise ValueError("process_ledger_limit")
                entries.append(Path(entry.path))
        for path in sorted(entries):
            if path.suffix != ".jsonl" or not path.stem.isdecimal():
                errors.add("unrecognized_observation_file")
                continue
            pid = int(path.stem)
            if pid <= 0 or path.name != f"{pid}.jsonl" or pid in ledgers:
                errors.add("ledger_process_identity_invalid")
                continue
            try:
                data, records = _read(path)
                if not _records_valid(records, pid, errors):
                    continue
                _call_history(records, errors)
                ledgers[pid] = records
                all_events.extend(records)
                report["events"].append(
                    {"pid": pid, "event": "ledger_digest", "bytes": len(data), "sha256": sha256(data)}
                )
            except (OSError, ValueError, TypeError):
                errors.add("ledger_unreadable_or_invalid")
        roots = [records[0] for records in ledgers.values() if records[0].get("role") == "phase"]
        if len(roots) != 1:
            errors.add("phase_registration_not_unique")
        run_ids = {records[0].get("run_id") for records in ledgers.values()}
        if len(run_ids) != 1:
            errors.add("observation_run_identity_mismatch")
        if roots and roots[0].get("parent_pid") != os.getpid():
            errors.add("phase_parent_identity_mismatch")
        pids = set(ledgers)
        for event in all_events:
            child_pid = event.get("child_pid")
            if type(child_pid) is int and child_pid > 0:
                pids.add(child_pid)
            for name, counter in (
                ("native_client_entry", "native_client_entries"),
                ("review_send_entry", "review_send_entries"),
                ("process_launch_attempt", "process_launch_attempts"),
            ):
                if event["event"] == name:
                    report["counts"][counter] += 1
            if event["event"] in {"native_client_entry", "review_send_entry"}:
                errors.add("producer_capable_entry_observed")
            if event["event"] in {"observer_changed", "interpreter_changed", "process_launch_exception"}:
                errors.add("observer_coverage_changed_or_failed")
            if event.get("operation_kind") in {"unclassified", "native_producer"}:
                errors.add("unknown_or_producer_operation")
        for pid in sorted(pids):
            records = ledgers.get(pid, [])
            row = _process_row(pid, records[0] if records else None, errors)
            if records and records[0].get("role") == "python_spawn":
                parent_pid = records[0].get("parent_pid")
                parent_records = ledgers.get(parent_pid, []) if type(parent_pid) is int else []
                if not any(event.get("child_pid") == pid for event in parent_records):
                    errors.add("child_launch_edge_missing")
                for parent_event in parent_records:
                    if (
                        parent_event.get("child_pid") == pid
                        and parent_event.get("child_start_marker") is not None
                        and parent_event["child_start_marker"] != records[0].get("start_marker")
                    ):
                        errors.add("child_launch_identity_mismatch")
            seals = [index for index, event in enumerate(records) if event["event"] == "sealed"]
            row["sealed"] = len(seals) == 1 and seals[0] == len(records) - 1
            if not row["sealed"]:
                errors.add("missing_or_nonterminal_seal")
            else:
                incomplete = records[-1].get("incomplete")
                if not isinstance(incomplete, list) or not all(isinstance(item, str) for item in incomplete):
                    errors.add("seal_contract_invalid")
                elif incomplete:
                    errors.add("process_observer_reported_incomplete")
                if type(records[-1].get("alive_thread_count")) is not int or records[-1]["alive_thread_count"] != 0:
                    errors.add("producer_threads_exit_unconfirmed")
            ready = [record for record in records if record["event"] == "observer_ready"]
            if (
                len(ready) != 1
                or ready[0].get("audit_confirmed") is not True
                or ready[0].get("execution_monitor_confirmed") is not True
            ):
                errors.add("observer_registration_unconfirmed")
            report["processes"].append(row)
        # Retain the redacted observations themselves, bounded below, alongside hashes.
        for event in all_events:
            exported = dict(event)
            process_errors = exported.pop("incomplete", None)
            if process_errors is not None:
                exported["observer_error_count"] = len(process_errors) if isinstance(process_errors, list) else None
                if isinstance(process_errors, list):
                    for index, error in enumerate(process_errors):
                        if isinstance(error, str):
                            report["events"].append(
                                {
                                    "event": "observer_error",
                                    "pid": event["pid"],
                                    "error_index": index,
                                    "error_code": error,
                                }
                            )
            report["events"].append(exported)
        if len(report["events"]) > 256 or len(json.dumps(report, separators=(",", ":")).encode()) > MAX_REPORT_BYTES:
            report["events"] = [item for item in report["events"] if item["event"] == "ledger_digest"]
            errors.add("report_event_detail_truncated")
    except (OSError, ValueError, TypeError):
        errors.add("observation_unavailable_or_invalid")
    report["incomplete"] = sorted(errors)
    return report
