#!/usr/bin/env python3
"""One frozen B-versus-owned-Python E campaign; no production activation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from compare_guard_mcp_risk import source_identity, verify_facts
from profile_guard_mcp_session import BenchmarkCaseError, performance_lock, run_case, write_checkpoint


def harness_identity():
    return {
        name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
        for name in (
            "compare_guard_mcp_owned_preparation.py",
            "compare_guard_mcp_risk.py",
            "profile_guard_mcp_session.py",
            "guard_mcp_owned_preparation_pilot.py",
        )
    }


def oracle_identity():
    from codex_plugin_scanner.guard import mcp_tool_calls
    from codex_plugin_scanner.guard.proxy import framing, runtime_mcp, tool_catalog

    return {
        name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
        for name, module in (
            ("mcp_tool_calls.py", mcp_tool_calls),
            ("proxy/runtime_mcp.py", runtime_mcp),
            ("proxy/framing.py", framing),
            ("proxy/tool_catalog.py", tool_catalog),
        )
    }


def schedule(samples):
    ordinary = [{"payload_bytes": size, "payload_kind": "ascii", "samples": samples} for size in (1024, 16384, 131072)]
    large = [
        {"payload_bytes": 4 * 1024 * 1024 - 512, "payload_kind": kind, "samples": 3, "compact_result": True}
        for kind in ("unicode", "dense-integers")
    ]
    cases = []
    for block in range(5):
        for fixture in ordinary + large:
            for arm in ("B", "E") if block % 2 == 0 else ("E", "B"):
                cases.append({**fixture, "block": block, "arm": arm})
    diagnostics = (
        ordinary
        + large
        + [
            {"payload_bytes": 4 * 1024 * 1024 - 512, "payload_kind": kind, "samples": 3, "compact_result": True}
            for kind in ("ascii", "nested-records")
        ]
    )
    for fixture in diagnostics:
        for arm in ("B", "E"):
            cases.append(
                {**fixture, "samples": min(fixture["samples"], 10), "profile": True, "block": None, "arm": arm}
            )
    return cases


def run_comparison(args):
    if args.json.exists():
        raise ValueError("owned_mcp_refuses_to_overwrite_attempts")
    roots = {"B": args.baseline_src.resolve(), "E": args.candidate_src.resolve()}
    sources = {name: source_identity(root) for name, root in roots.items()}
    harness = harness_identity()
    report = {
        "schema": "hol-guard-mcp-owned-preparation-comparison.v1",
        "qualification": False,
        "production_activation": False,
        "platform": platform.system(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "runtime_sources_sha256": sources,
        "harness_sources_sha256": harness,
        "measurement_lock": "per_case_POSIX_flock",
        "campaign": "five_alternating_process_blocks_B_vs_explicit_E",
        "limitations": [
            "source_only_single_shared_host_c1",
            "large_blocks_three_warm_samples_not_tail_qualification",
            "profiles_separate_from_gate",
            "package_and_unsupported_shapes_use_legacy_B",
            "no_native_installed_or_platform_qualification",
        ],
        "cases": [],
    }
    write_checkpoint(args.json, report)
    try:
        with performance_lock(args.lock_file):
            report["public_oracle_loaded_sources_sha256"] = oracle_identity()
            if report["public_oracle_loaded_sources_sha256"] != sources["E"]:
                raise RuntimeError("owned_mcp_public_oracle_wrong_candidate_source")
            report["public_api_facts_parity"] = verify_facts(roots["B"])
    except (Exception, KeyboardInterrupt) as error:
        report["failed_parity_gate"] = {
            "reason": type(error).__name__,
            "failure_code": str(error) if str(error).startswith("owned_mcp_") else type(error).__name__,
        }
        write_checkpoint(args.json, report)
        raise
    write_checkpoint(args.json, report)
    prior_path = os.environ.get("PYTHONPATH")
    cases = schedule(args.samples)
    try:
        for index, scheduled in enumerate(cases):
            options = dict(scheduled)
            arm, block = options.pop("arm"), options.pop("block")
            result = None
            started = None
            try:
                if source_identity(roots[arm]) != sources[arm] or harness_identity() != harness:
                    raise RuntimeError("owned_mcp_source_changed")
                os.environ["PYTHONPATH"] = str(roots[arm])
                with performance_lock(args.lock_file):
                    started = datetime.now(timezone.utc).isoformat()
                    result = run_case(**options, owned_preparation_pilot=arm == "E")
                    finished = datetime.now(timezone.utc).isoformat()
                if result["loaded_runtime_sha256"] != sources[arm]:
                    raise RuntimeError("owned_mcp_wrong_runtime_loaded")
                if source_identity(roots[arm]) != sources[arm] or harness_identity() != harness:
                    raise RuntimeError("owned_mcp_source_changed_during_case")
                if arm == "E":
                    counts = result["owned_preparation_pilot"]["counters"]
                    expected = options["samples"] + 1
                    if any(
                        counts.get(name, 0) != expected
                        for name in (
                            "requests_admitted",
                            "category_derivations",
                            "preparations_completed",
                            "bound_forwards",
                        )
                    ):
                        raise RuntimeError("owned_mcp_expected_private_preparations_missing")
                    if any(
                        counts.get(name, 0)
                        for name in ("selected_failures", "unsupported_fallback", "busy_fallback", "package_fallback")
                    ):
                        raise RuntimeError("owned_mcp_unexpected_fallback_or_failure")
            except (Exception, KeyboardInterrupt) as error:
                failure = (
                    dict(error.evidence)
                    if isinstance(error, BenchmarkCaseError)
                    else {
                        "reason": type(error).__name__,
                        "failure_code": str(error) if str(error).startswith("owned_mcp_") else type(error).__name__,
                    }
                )
                if result is not None:
                    failure.update(completed_case_result=result, measurement_valid=False)
                report["failed_case"] = {
                    "index": index + 1,
                    "scheduled": scheduled,
                    "started_utc": started,
                    "failed_utc": datetime.now(timezone.utc).isoformat(),
                    **failure,
                }
                write_checkpoint(args.json, report)
                raise
            result.update(arm=arm, block=block, started_utc=started, finished_utc=finished)
            report["cases"].append(result)
            report["completed_cases"] = len(report["cases"])
            write_checkpoint(args.json, report)
            print(json.dumps({"case": index + 1, "total": len(cases), **scheduled}), file=sys.stderr, flush=True)
            time.sleep(0.1)
    finally:
        if prior_path is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = prior_path
    comparisons = []
    for index in range(0, len(report["cases"]), 2):
        pair = report["cases"][index : index + 2]
        old = next(case for case in pair if case["arm"] == "B")
        new = next(case for case in pair if case["arm"] == "E")
        parity = old["correctness"] == new["correctness"]
        comparison = {
            "block": old["block"],
            "payload_bytes": old["fixture"]["payload_bytes"],
            "payload_kind": old["fixture"]["payload_kind"],
            "profile": old["fixture"]["profile"],
            "exact_correctness_parity": parity,
            "roundtrip_p95_change_percent": 100
            * (new["client_roundtrip_ms"]["p95"] / old["client_roundtrip_ms"]["p95"] - 1),
            "tree_cpu_change_percent": 100 * (new["tree_cpu_ms_per_call"] / old["tree_cpu_ms_per_call"] - 1),
        }
        comparisons.append(comparison)
        report["comparisons"] = comparisons
        if not parity:
            report["failed_parity"] = {"pair": index // 2}
            write_checkpoint(args.json, report)
            raise RuntimeError("owned_mcp_exact_route_parity_failed")
    write_checkpoint(args.json, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-src", type=Path, required=True)
    parser.add_argument("--candidate-src", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--lock-file", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.samples <= 10000:
        parser.error("samples must be 1..10000")
    report = run_comparison(args)
    print(json.dumps({"completed_cases": report["completed_cases"], "qualification": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
