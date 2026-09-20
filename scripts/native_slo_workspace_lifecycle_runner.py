"""Installed lifecycle fault sweep with a fresh owned daemon per matrix cell."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.bench_guard_native_installed_slo_runtime import _clear_proof_overrides, _runtime_summary
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_daemon_fixture import DaemonFixture
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_mixed_load import PrivateLedger
from scripts.native_slo_qualification_scenarios import validate_receipt_profile
from scripts.native_slo_workspace import _definition
from scripts.native_slo_workspace_lifecycle import LIFECYCLE_SCENARIOS
from scripts.native_slo_workspace_lifecycle_evidence import retain_cell
from scripts.native_slo_workspace_server import WORKSPACE_COUNTS


def run_lifecycle_sweep(
    runtime: Path,
    *,
    ledger_path: Path,
    counts: tuple[int, ...] = WORKSPACE_COUNTS,
    scenarios: tuple[str, ...] = LIFECYCLE_SCENARIOS,
) -> dict[str, object]:
    if (
        not counts
        or any(type(count) is not int or count not in WORKSPACE_COUNTS for count in counts)
        or tuple(sorted(set(counts))) != counts
        or not scenarios
        or len(set(scenarios)) != len(scenarios)
        or any(scenario not in LIFECYCLE_SCENARIOS for scenario in scenarios)
    ):
        raise ValueError("workspace lifecycle declared matrix invalid")
    _clear_proof_overrides()
    identity = _runtime_summary(runtime)
    runtime_digest = identity.get("runtime_sha256")
    if not isinstance(runtime_digest, str):
        raise ValueError("workspace installed binary digest unavailable")
    validate_receipt_profile("candidate", identity)
    cells: list[dict[str, Any]] = []
    ledger_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    ledger = PrivateLedger(ledger_path)
    try:
        for count in counts:
            for scenario in scenarios:
                offered = {"registered_workspaces": count, "scenario": scenario}
                ledger.write({"kind": "lifecycle_cell_offer", **offered})
                result: dict[str, Any] = dict(offered)
                try:
                    with DaemonFixture(runtime, policy="normal", workspace_count=count) as session:
                        result = dict(
                            session.control("workspace_lifecycle", scenario=scenario, receipt_profile="candidate")
                        )
                    binding = result.get("binding")
                    result["installed_runtime_matches"] = (
                        isinstance(binding, dict) and binding.get("runtime_identity") == runtime_digest
                    )
                    result["declared_cell_matches"] = (
                        result.get("scenario") == scenario
                        and type(result.get("registered_workspaces")) is int
                        and result["registered_workspaces"] == count
                    )
                    result["passed"] = (
                        result.get("passed") is True
                        and result.get("status") == "completed"
                        and result["installed_runtime_matches"]
                        and result["declared_cell_matches"]
                    )
                except Exception as error:
                    if "status" in result:
                        result["fixture_cleanup_failure"] = failure_evidence(error)
                    else:
                        result["failure"] = failure_evidence(error)
                    result.update(status="failed", passed=False)
                cells.append(retain_cell(ledger, result))
    finally:
        ledger_report = ledger.finish()
    complete = counts == WORKSPACE_COUNTS and scenarios == LIFECYCLE_SCENARIOS
    return assert_privacy_safe(
        {
            "schema": "hol-guard.native-workspace-lifecycle.v1",
            "scope": "instrumented_installed_producer_faults_and_same_process_service_replacement",
            "runtime": identity,
            "definition": _definition(),
            "counts": list(counts),
            "scenarios": list(scenarios),
            "cells": cells,
            "declared_cells_visited": len(cells) == len(counts) * len(scenarios),
            "complete_lifecycle_matrix_visited": complete,
            "implemented_checks_passed": complete and all(cell["passed"] for cell in cells),
            "headline_timing_eligible": False,
            "full_rsp_128_129_qualification": False,
            "pending": ["true_python_process_restart", "uninstrumented_paired_performance", "cross_platform_matrix"],
            "ledger": ledger_report,
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--counts", type=int, nargs="+", default=WORKSPACE_COUNTS)
    parser.add_argument("--scenarios", nargs="+", choices=LIFECYCLE_SCENARIOS, default=LIFECYCLE_SCENARIOS)
    args = parser.parse_args()
    report = run_lifecycle_sweep(
        args.runtime, ledger_path=args.ledger, counts=tuple(args.counts), scenarios=tuple(args.scenarios)
    )
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return 0 if report["implemented_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
