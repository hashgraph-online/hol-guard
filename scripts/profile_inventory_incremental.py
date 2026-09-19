"""Attribute installed inventory refreshes with an overlapping file-event burst.

Run this diagnostic in the existing bounded installed qualification process.
It preserves 24/128/486 cells and records a terminal result for every cell.
The cloud transport is explicitly synthetic; real scanner wrappers retain their
actual unavailable/failure outcomes and unchanged client_unverified provenance.
No duration from this observed diagnostic is a headline latency sample.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.bench_guard_native_installed_slo_runtime import _clear_proof_overrides, _runtime_summary  # noqa: E402
from scripts.inventory_refresh_fixture import COUNTS, run_inventory_witness  # noqa: E402
from scripts.native_slo_contract import assert_privacy_safe  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402
from scripts.native_slo_mixed_load import PrivateLedger  # noqa: E402
from scripts.native_slo_resources import ResourceSampler  # noqa: E402


def _definition() -> dict[str, object]:
    names = (
        "profile_inventory_incremental.py",
        "inventory_refresh_fixture.py",
        "inventory_refresh_observer.py",
        "profile_inventory_refresh.py",
        "native_slo_failure.py",
        "native_slo_mixed_load.py",
        "native_slo_resources.py",
        "bench_guard_native_installed_slo_runtime.py",
    )
    return {
        "collector_files_sha256": {
            name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest() for name in names
        },
        "counts": list(COUNTS),
        "input_events": 32,
        "empty_static_mcp_configurations": 1,
        "recent_refresh_calls": 4,
        "scanner_budget_seconds": 30.0,
        "offline_ack_release_budget_seconds": 5.0,
        "logical_timestamps": ["2026-09-18T00:00:00Z", "2026-09-18T00:01:00Z", "2026-09-18T00:30:00Z"],
    }


def run_incremental_sweep(runtime: Path, *, raw_file: Path) -> dict[str, Any]:
    _clear_proof_overrides()
    identity = _runtime_summary(runtime)
    definition = _definition()
    ledger = PrivateLedger(raw_file)
    cells: list[dict[str, Any]] = []
    identity_after: dict[str, object] = {}
    identity_failure: dict[str, object] | None = None
    definition_after: dict[str, object] = {}
    definition_failure: dict[str, object] | None = None
    try:
        ledger.write({"kind": "campaign", "identity": identity, "definition": definition})
        for count in COUNTS:
            ledger.write({"kind": "cell_offer", "count": count})
            resources: ResourceSampler | None = None
            cell: dict[str, Any]
            try:
                with (
                    tempfile.TemporaryDirectory(prefix="hol-inventory-incremental-") as directory,
                    ResourceSampler() as resources,
                ):
                    cell = run_inventory_witness(Path(directory), count, ledger)
            except Exception as error:
                cell = {"count": count, "passed": False, "failure": failure_evidence(error)}
            if resources is not None:
                cell["resources"] = resources.report(attempted=1)
                cell["resource_scope"] = "whole_diagnostic_process_tree_including_fixture_producer_and_observer"
            cells.append(cell)
            ledger.write(
                {
                    "kind": "cell_terminal",
                    "count": count,
                    "passed": cell["passed"],
                    "failure": cell.get("failure"),
                }
            )
        try:
            identity_after = _runtime_summary(runtime)
        except Exception as error:
            identity_failure = failure_evidence(error)
        try:
            definition_after = _definition()
        except Exception as error:
            definition_failure = failure_evidence(error)
        ledger.write(
            {
                "kind": "identity_after",
                "identity": identity_after,
                "matches_before": identity_after == identity,
                "failure": identity_failure,
                "collector_definition": definition_after,
                "collector_matches_before": definition_after == definition,
                "collector_failure": definition_failure,
            }
        )
    finally:
        retained = ledger.finish()
    return assert_privacy_safe(
        {
            "schema": "hol-guard.inventory-incremental-diagnostic.v1",
            "identity": identity,
            "identity_after": identity_after,
            "identity_unchanged": identity_after == identity,
            "identity_failure": identity_failure,
            "definition": definition,
            "definition_after": definition_after,
            "definition_unchanged": definition_after == definition,
            "definition_failure": definition_failure,
            "cells": cells,
            "ledger": retained,
            "implemented_checks_passed": len(cells) == len(COUNTS)
            and all(cell["passed"] for cell in cells)
            and identity_after == identity
            and definition_after == definition,
            "headline_timing_eligible": False,
            "full_rsp_130_qualification": False,
            "pending": [
                "actual_daemon_periodic_refresh_and_coalescing",
                "successful_installed_cisco_engine_accuracy_and_process_resources",
                "authorized_live_cloud_scan_and_network_wait",
                "observer_overhead_and_uninstrumented_paired_performance",
                "cross_platform_and_supported_harness_lifecycle",
                "broader_sql_transaction_batching_with_approval_and_crash_semantics",
            ],
        }
    )


def main() -> int:
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()
    _clear_proof_overrides()
    status = native_runtime_status()
    if status.identity is None:
        raise RuntimeError("inventory installed native artifact identity unavailable")
    report = run_incremental_sweep(status.identity.path, raw_file=arguments.ledger)
    descriptor = os.open(arguments.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
        destination.write(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
        destination.flush()
        os.fsync(destination.fileno())
    print(json.dumps({key: report[key] for key in ("implemented_checks_passed", "headline_timing_eligible")}))
    return 0 if report["implemented_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
