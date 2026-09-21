"""RSP-129/131/138 mixed contention qualification at installed daemon ingress.

Call ``run_mixed_scenario`` inside a fresh ``DaemonFixture(runtime, policy=
"normal")`` using the installed interpreter. It returns aggregate diagnostics
and writes a private, bounded JSONL ledger of every offer/control/outcome and
actual native receipt identity. This instrumented scenario does not replace
the separate uninstrumented latency gates or installed executable matrix.

Bounds inherit the offered-load contract: at most 100,000 attempts, concurrency
64, rate 10,000/s, one hour, and a ten-second completion drain. The generator
queue holds at most one additional item per worker. Control actions are capped
at 40 by the plan (64 in the private protocol); inventory bursts commit at most
128 local rows. The private ledger uses exclusive mode-0600 creation and caps
records at 8 KiB, total records at 350,000 and total bytes at 256 MiB. Receipt
pages contain at most 128 rows. The existing fixture applies its 30-second
control timeout; native readiness retains the existing 400 ms target.

``passed`` applies only to the named observed-scenario checks. It does not
close the full persistence measurement requirement: SQLite VFS bytes/fsync
remain null with ``full_persistence_metric_coverage=False``. Queue peaks are
sampled, and commit age includes polling delay. Resident recovery leaves the
Python fixture running. Local inventory upserts do not represent cloud scans.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from scripts.native_slo_contract import MAX_INSTALLED_ADAPTER_P95_MS, MAX_INSTALLED_ADAPTER_P99_MS, MAX_RSS_GROWTH
from scripts.native_slo_mixed_load import MixedLoad, MixedPlan, PrivateLedger
from scripts.native_slo_mixed_witness import writer_drained
from scripts.native_slo_resources import ResourceSampler


def _schedule(plan: MixedPlan) -> list[tuple[float, str, dict[str, object]]]:
    actions: list[tuple[float, str, dict[str, object]]] = []
    for index in range(plan.mutations):
        at = plan.duration_seconds * (index + 1) / (plan.mutations + 1)
        actions.append((at, "mixed_policy", {"index": index, "action": "block" if index % 2 == 0 else "allow"}))
    for index in range(plan.restarts):
        at = plan.duration_seconds * (index + 0.5) / plan.restarts
        actions.append((at, "mixed_restart", {"index": index}))
    for index in range(plan.inventory_batches):
        at = plan.duration_seconds * (index + 0.5) / plan.inventory_batches
        actions.append((at, "mixed_inventory", {"index": index, "count": 32}))
    return sorted(actions, key=lambda row: (row[0], row[1]))


def _control(session: Any, ledger: PrivateLedger, operation: str, **arguments: Any) -> dict[str, Any]:
    started = time.monotonic()
    ledger.write({"kind": "control_offer", "operation": operation, **arguments})
    result: dict[str, Any]
    try:
        result = dict(session.control(operation, **arguments))
    except Exception as error:
        result = {"status": "failed", "failure_type": type(error).__name__}
    result["control_elapsed_ms"] = (time.monotonic() - started) * 1000
    # Samples contain nested bounded summaries and can be larger than a ledger
    # row. Their queue counters and receipt totals are retained individually;
    # the final complete aggregate is returned through the qualification report.
    retained = (
        result
        if operation not in {"mixed_sample", "mixed_finish", "mixed_start"}
        else {
            "status": result.get("status"),
            "control_elapsed_ms": result["control_elapsed_ms"],
            "elapsed_ms": result.get("elapsed_ms"),
            "scheduler": result.get("scheduler"),
            "writer": result.get("writer"),
            "failure_type": result.get("failure_type"),
        }
    )
    ledger.write({"kind": "control_terminal", "operation": operation, **retained})
    return result


def _receipt_pages(session: Any, load: MixedLoad, ledger: PrivateLedger) -> dict[str, object]:
    offset = 0
    matched = mismatched = unexpected = 0
    while True:
        page = dict(session.control("mixed_page", offset=offset, limit=128))
        rows, total = page.get("rows"), page.get("total")
        if page.get("status") != "completed" or not isinstance(rows, list) or not isinstance(total, int):
            raise RuntimeError("mixed receipt page invalid")
        if total > load.plan.attempts + 64 or len(rows) > 128 or offset > total:
            raise RuntimeError("mixed receipt page exceeded bound")
        for row in rows:
            if not isinstance(row, dict):
                raise RuntimeError("mixed receipt row invalid")
            ledger.write({"kind": "receipt", **row})
            attempt = row.get("attempt")
            if isinstance(attempt, str) and attempt.startswith("mixed-load-"):
                result = load.row(int(attempt.removeprefix("mixed-load-")))
                if result is None:
                    unexpected += 1
                elif result["state"] == "completed":
                    valid = (
                        result["delivered_decision"] == row.get("decision")
                        and result["delivered_action"] == row.get("policy_action")
                        and not result["capacity_rejected"]
                    )
                    matched += int(valid)
                    mismatched += int(not valid)
        offset += len(rows)
        if offset == total:
            break
        if not rows:
            raise RuntimeError("mixed receipt page made no progress")
    return {
        "rows_retained": offset,
        "delivered_binding_matches": matched,
        "delivered_mismatches": mismatched,
        "unexpected": unexpected,
    }


def _checks(
    load: Mapping[str, Any],
    final: Mapping[str, Any],
    actions: list[dict[str, Any]],
    resources: Mapping[str, Any],
    reconciliation: Mapping[str, Any],
) -> dict[str, bool]:
    receipts = final.get("receipts", {})
    writer = final.get("writer", {})
    latency = load.get("offered_latency")
    counters = (
        "transport_failed",
        "completion_timeout",
        "generator_rejected",
        "generator_cancelled",
        "capacity_rejected",
        "workers_unfinished",
        "response_contract_invalid",
    )
    return {
        "all_offered_work_retained": load.get("accounting_complete") is True and not load.get("errors"),
        "all_offered_work_completed": load.get("offered", 0) > 0 and all(load.get(key) == 0 for key in counters),
        "control_actions_enforced": bool(actions)
        and all(
            action.get("status") == "completed"
            and action.get("overlapped_load") is True
            and (
                action.get("first_enforcing_receipt") is True
                if action["operation"] != "mixed_inventory"
                else action.get("committed") == 32
            )
            for action in actions
        ),
        "native_receipts_committed": receipts.get("native_receipts", 0) > 0
        and all(
            receipts.get(key) == 0
            for key in (
                "missing",
                "binding_mismatches",
                "writer_rejected",
                "writer_admission_unobserved",
                "pre_receipts_without_program_binding",
            )
        )
        and not any(
            receipts.get("observations", {}).get(key, 0)
            for key in (
                "duplicate_observations",
                "witness_overflow",
                "invalid_receipt_identity",
                "native_without_receipt",
            )
        ),
        "every_completed_hook_bound": reconciliation.get("delivered_binding_matches") == load.get("completed")
        and reconciliation.get("delivered_mismatches") == 0
        and reconciliation.get("unexpected") == 0,
        "evidence_drained": final.get("status") == "completed" and writer_drained(writer),
        "evidence_no_drops": isinstance(writer.get("dropped"), int)
        and writer["dropped"] == final.get("initial", {}).get("writer", {}).get("dropped"),
        "offered_completion_latency_target": isinstance(latency, dict)
        and latency["p95_ms"] <= MAX_INSTALLED_ADAPTER_P95_MS
        and latency["p99_ms"] <= MAX_INSTALLED_ADAPTER_P99_MS,
        "resource_coverage": resources.get("sample_minimum_met") is True,
        "rss_growth_target": isinstance(resources.get("rss_growth"), (int, float))
        and resources["rss_growth"] <= MAX_RSS_GROWTH,
    }


def run_mixed_scenario(
    session: Any,
    *,
    raw_file: Path,
    duration_seconds: float = 30.0,
    rate: float = 20.0,
    concurrency: int = 16,
    mutations: int = 4,
    restarts: int = 1,
    inventory_batches: int = 3,
    receipt_profile: str = "candidate",
) -> dict[str, object]:
    """Run bounded actual HTTP contention; return failures without dropping work.

    ``session`` must be an already-started isolated installed DaemonFixture with
    normal enforcing/allow fixture policy. ``raw_file`` must not already exist.
    This function creates no production fixtures or native-runtime overrides.
    Only the qualification driver for the pinned baseline artifact may select
    ``receipt_profile="baseline_2e672d2"``; candidate is the strict default.
    """
    plan = MixedPlan(duration_seconds, rate, concurrency, mutations, restarts, inventory_batches)
    if receipt_profile not in {"candidate", "baseline_2e672d2"}:
        raise ValueError("mixed receipt profile unsupported")
    ledger = PrivateLedger(raw_file)
    actions: list[dict[str, Any]] = []
    load = MixedLoad(plan, session.request, ledger)
    final: dict[str, Any] = {}
    load_result: dict[str, Any] = {}
    reconciliation: dict[str, Any] = {}
    resources: dict[str, Any] = {}
    failures: Counter[str] = Counter()
    collection_started = finish_attempted = False
    try:
        started = _control(
            session,
            ledger,
            "mixed_start",
            maximum=plan.attempts + mutations + restarts,
            receipt_profile=receipt_profile,
        )
        if started.get("status") != "completed":
            failures["setup_failed"] += 1
        else:
            collection_started = True
            with ResourceSampler(pid=session.pid) as sampler:
                load.start()
                try:
                    for scheduled, operation, arguments in _schedule(plan):
                        while time.monotonic() < load.started + scheduled:
                            delay = min(0.25, load.started + scheduled - time.monotonic())
                            if delay > 0:
                                time.sleep(delay)
                            sample = _control(session, ledger, "mixed_sample")
                            if sample.get("status") != "completed":
                                failures["sample_failed"] += 1
                        began_ms = (time.monotonic() - load.started) * 1000
                        action = _control(session, ledger, operation, **arguments)
                        action.update(
                            operation=operation,
                            scheduled_ms=scheduled * 1000,
                            began_ms=began_ms,
                            overlapped_load=began_ms < plan.duration_seconds * 1000,
                        )
                        actions.append(action)
                    while time.monotonic() < load.started + plan.duration_seconds:
                        time.sleep(min(0.25, max(0, load.started + plan.duration_seconds - time.monotonic())))
                        sample = _control(session, ledger, "mixed_sample")
                        if sample.get("status") != "completed":
                            failures["sample_failed"] += 1
                finally:
                    load_result = load.finish()
                    finish_attempted = True
                    final = _control(session, ledger, "mixed_finish")
                    try:
                        reconciliation = _receipt_pages(session, load, ledger)
                    except Exception as error:
                        failures["reconciliation_failed"] += 1
                        ledger.write({"kind": "reconciliation_failure", "failure_type": type(error).__name__})
            resources = sampler.report(attempted=plan.attempts)
    except Exception as error:
        failures["runner_failed"] += 1
        ledger.write({"kind": "runner_failure", "failure_type": type(error).__name__})
    finally:
        if collection_started and not finish_attempted:
            final = _control(session, ledger, "mixed_finish")
        retained = ledger.finish()
    checks = _checks(load_result, final, actions, resources, reconciliation)
    controls = Counter(action.get("status", "missing") for action in actions)
    return {
        "schema": "hol-guard.native-mixed-scenario.v1",
        "scope": "installed_daemon_http_instrumented",
        "receipt_profile": receipt_profile,
        "headline_timing_eligible": False,
        "passed": all(checks.values()) and not failures,
        "checks": checks,
        "load": load_result,
        "controls": {"planned": mutations + restarts + inventory_batches, "offered": len(actions), **dict(controls)},
        "actions": actions,
        "queues_and_persistence": final,
        "resources": resources,
        "reconciliation": reconciliation,
        "private_ledger": retained,
        "failures": dict(failures),
        "coverage_limits": {
            "recovery": "contained_resident_restart_python_fixture_stays_running",
            "inventory": "real_local_inventory_upserts_no_remote_scanner",
            "phase_timing": "mutation_ack_first_decision_inclusive_no_separate_compile_push",
            "fsync": "journal_calls_only_sqlite_vfs_unavailable",
        },
    }
