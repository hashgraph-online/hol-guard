"""Installed workspace publication diagnostics for RSP-128 and RSP-129.

Run with the installed wheel interpreter and its default native runtime. Each
count starts a fresh contained daemon. Real atomic workspace edits and public
policy changes drive the unchanged production publisher, cache and resident.
The forwarding observer includes its own overhead. No collected duration is
eligible for a headline performance claim, and the pending fault matrix remains
explicit. Unit controls use test doubles only to verify the collector itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    # Admit only checkout qualification helpers. Never add src or change the
    # installed production package selected by this interpreter.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.bench_guard_native_installed_slo_runtime import _clear_proof_overrides, _runtime_summary
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_daemon_fixture import DaemonFixture
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_mixed_load import PrivateLedger
from scripts.native_slo_qualification_scenarios import validate_receipt_profile
from scripts.native_slo_resources import ResourceSampler
from scripts.native_slo_workspace_observer import MAX_EVENTS, PAGE_SIZE, public_binding
from scripts.native_slo_workspace_server import WORKSPACE_COUNTS, WORKSPACE_PHASES
from scripts.native_slo_workspace_trace import startup_rows, validate_trace


def _definition() -> dict[str, object]:
    root = Path(__file__).parent
    selected = sorted(
        {
            *root.glob("native_slo_*.py"),
            *root.glob("native_probe_*.py"),
            root / "bench_guard_native_installed_slo_runtime.py",
        }
    )
    digest = hashlib.sha256()
    for path in selected:
        digest.update(path.name.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    return {"files": len(selected), "sha256": digest.hexdigest(), "scope": "collector_and_native_slo_helpers"}


def _write(ledger: PrivateLedger, count: int, kind: str, **fields: Any) -> None:
    ledger.write(assert_privacy_safe({"kind": kind, "registered_workspaces": count, **fields}))


def _control(session: Any, ledger: PrivateLedger, count: int, operation: str, **arguments: Any) -> dict[str, Any]:
    _write(ledger, count, "control_offer", operation=operation, **arguments)
    try:
        result = dict(session.control(operation, **arguments))
    except Exception as error:
        result = {"status": "failed", "passed": False, "failure": failure_evidence(error)}
    retained = (
        result
        if operation != "workspace_page"
        else {
            "status": result.get("status"),
            "total": result.get("total"),
            "failure": result.get("failure"),
        }
    )
    _write(ledger, count, "control_terminal", operation=operation, result=retained)
    return result


def _pages(session: Any, ledger: PrivateLedger, count: int, report: Mapping[str, Any]) -> int:
    rows: list[dict[str, object]] = []
    expected = report.get("events")
    if type(expected) is not int or not 0 <= expected <= MAX_EVENTS:
        raise ValueError("workspace observer total outside bound")
    while len(rows) < expected:
        page = _control(session, ledger, count, "workspace_page", offset=len(rows))
        values = page.get("rows")
        if (
            page.get("status") != "completed"
            or type(page.get("total")) is not int
            or page["total"] != expected
            or not isinstance(values, list)
            or not 1 <= len(values) <= PAGE_SIZE
            or len(rows) + len(values) > expected
            or not all(isinstance(row, dict) for row in values)
        ):
            raise ValueError("workspace observer page invalid")
        for row in values:
            _write(ledger, count, "publisher_event", event=row)
        rows.extend(values)
    validate_trace(rows, report)
    return len(rows)


def _cell(runtime: Path, count: int, profile: str, runtime_digest: str, ledger: PrivateLedger) -> dict[str, Any]:
    phases: list[dict[str, Any]] = []
    result: dict[str, Any] = {"registered_workspaces": count, "passed": False, "phases": phases}
    offered = 0
    final: dict[str, Any] = {}
    resources: ResourceSampler | None = None
    _write(ledger, count, "cell_offer")
    try:
        with DaemonFixture(runtime, policy="normal", workspace_count=count) as session:
            result.update(startup_ms=session.startup_ms, startup_readiness_ms=session.readiness_ms)
            with ResourceSampler(pid=session.pid) as resources:
                begun = _control(session, ledger, count, "workspace_start", receipt_profile=profile)
                if begun.get("status") != "completed":
                    raise RuntimeError("workspace installed witness setup failed")
                try:
                    for name in WORKSPACE_PHASES:
                        offered += 1
                        phase = _control(session, ledger, count, "workspace_phase", phase=name)
                        phases.append(phase)
                        binding = public_binding(phase.get("binding"))
                        phase["installed_runtime_matches"] = (
                            binding is not None and binding["runtime_identity"] == runtime_digest
                        )
                        _write(
                            ledger,
                            count,
                            "phase_identity",
                            phase=name,
                            binding=binding,
                            installed_runtime_matches=phase["installed_runtime_matches"],
                        )
                        if phase.get("passed") is not True or phase["installed_runtime_matches"] is not True:
                            break
                finally:
                    final = _control(session, ledger, count, "workspace_finish")
                result["final"] = final
                result["retained_events"] = _pages(session, ledger, count, final.get("observer", {}))
            result["passed"] = (
                final.get("passed") is True
                and len(phases) == len(WORKSPACE_PHASES)
                and all(phase["installed_runtime_matches"] is True for phase in phases)
            )
            result["cache_feature_checks_passed"] = final.get("cache_feature_checks_passed") is True
        result["fixture_contained"] = True
    except Exception as error:
        original_detail = failure_evidence(error)
        try:
            detail, rows = startup_rows(original_detail)
        except (KeyError, TypeError, ValueError) as trace_error:
            detail = {
                "primary": {key: value for key, value in original_detail.items() if key != "workspace_observation"},
                "trace_failure": failure_evidence(trace_error),
                "startup_trace_retained": False,
            }
            rows = []
        for row in rows:
            _write(ledger, count, "publisher_event", event=row)
        result.update(passed=False, failure=detail, retained_startup_events=len(rows))
    if resources is not None:
        result["resources"] = resources.report(attempted=offered)
        result["resource_scope"] = "daemon_tree_after_startup_excludes_initial_compilation_and_generator"
    result["unvisited_phases"] = list(WORKSPACE_PHASES[offered:])
    _write(
        ledger,
        count,
        "cell_terminal",
        passed=result["passed"],
        unvisited_phases=result["unvisited_phases"],
        failure=result.get("failure"),
        fixture_contained=result.get("fixture_contained", False),
    )
    return result


def run_workspace_sweep(
    runtime: Path,
    *,
    raw_file: Path,
    receipt_profile: str = "candidate",
    counts: tuple[int, ...] = WORKSPACE_COUNTS,
) -> dict[str, object]:
    if not counts or any(type(count) is not int or count not in WORKSPACE_COUNTS for count in counts):
        raise ValueError("workspace counts outside declared matrix")
    if tuple(sorted(set(counts))) != counts:
        raise ValueError("workspace counts must be ordered and unique")
    _clear_proof_overrides()
    identity = _runtime_summary(runtime)
    runtime_digest = identity.get("runtime_sha256")
    if not isinstance(runtime_digest, str):
        raise ValueError("workspace installed binary digest unavailable")
    validate_receipt_profile(receipt_profile, identity)
    definition = _definition()
    raw_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    ledger = PrivateLedger(raw_file)
    cells: list[dict[str, Any]] = []
    try:
        ledger.write(
            assert_privacy_safe(
                {
                    "kind": "matrix_offer",
                    "counts": counts,
                    "identity": identity,
                    "definition": definition,
                    "receipt_profile": receipt_profile,
                }
            )
        )
        for count in counts:
            cells.append(_cell(runtime, count, receipt_profile, runtime_digest, ledger))
    finally:
        ledger_report = ledger.finish()
    complete_matrix = counts == WORKSPACE_COUNTS and len(cells) == len(WORKSPACE_COUNTS)
    return assert_privacy_safe(
        {
            "scope": "installed_workspace_publication_diagnostic",
            "identity": identity,
            "definition": definition,
            "receipt_profile": receipt_profile,
            "cells": cells,
            "ledger": ledger_report,
            "authority_checks_passed": complete_matrix and all(cell["passed"] for cell in cells),
            "implemented_checks_passed": complete_matrix
            and all(cell["passed"] and cell.get("cache_feature_checks_passed") is True for cell in cells),
            "declared_matrix_visited": complete_matrix,
            "headline_timing_eligible": False,
            "full_rsp_128_129_qualification": False,
            "pending": [
                "key_rotation",
                "expiry_fault",
                "first_admission_fault",
                "lost_metadata_hint",
                "uninstrumented_paired_performance",
            ],
        }
    )


def main() -> int:
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--receipt-profile", choices=("candidate", "baseline_2e672d2"), default="candidate")
    arguments = parser.parse_args()
    _clear_proof_overrides()
    status = native_runtime_status()
    if status.identity is None:
        raise RuntimeError("workspace installed native runtime unavailable")
    report = run_workspace_sweep(
        status.identity.path, raw_file=arguments.ledger, receipt_profile=arguments.receipt_profile
    )
    descriptor = os.open(arguments.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
        destination.write(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
        destination.flush()
        os.fsync(destination.fileno())
    print(json.dumps({key: report[key] for key in ("implemented_checks_passed", "headline_timing_eligible")}))
    return 0 if report["implemented_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
