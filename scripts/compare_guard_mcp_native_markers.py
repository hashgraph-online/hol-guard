#!/usr/bin/env python3
"""Separate actual-route diagnostics for early/late positive text markers.

The frozen sparse-text matrix is never changed. These instrumented controls
test whether its gain also applies when Python can finish predicate scans early.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import profile_guard_mcp_session as profile
from compare_guard_mcp_native_text import executable_identity, harness_identity
from compare_guard_mcp_risk import source_identity

PAYLOAD_BYTES = 4 * 1024 * 1024 - 512
MARKER = " subprocess https://fixture.invalid .env sudo "


def marker_arguments(payload_bytes: int, kind: str, index: int, position: str) -> dict:
    remaining = payload_bytes - len(MARKER.encode())
    filler = "x" * remaining if kind == "ascii" else "€" * (remaining // 3) + "x" * (remaining % 3)
    text = MARKER + filler if position == "early" else filler + MARKER
    return {"text": text, "sample": index}


def run(args) -> dict:
    if args.json.exists():
        raise ValueError("native_mcp_marker_refuses_to_overwrite_attempts")
    source = args.text_src.resolve()
    sources = source_identity(source)
    harness = harness_identity()
    own_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    executable = executable_identity(args.native_text_helper)
    report = {
        "schema": "hol-guard-mcp-native-positive-markers.v1",
        "qualification": False,
        "campaign": "one_alternating_pair_per_kind_and_position_instrumented_diagnostic",
        "samples_per_cell": 3,
        "runtime_scope": "same_frozen_D_both_arms",
        "runtime_sources_sha256": sources,
        "harness_sources_sha256": {**harness, Path(__file__).name: own_digest},
        "native_executable": executable,
        "marker": "declared_synthetic_four_categories_early_or_late",
        "measurement_lock": "per_case_POSIX_flock",
        "limitations": ["three_instrumented_samples", "not_tail_or_installed_qualification"],
        "cases": [],
    }
    profile.write_checkpoint(args.json, report)
    prior_pythonpath = os.environ.get("PYTHONPATH")
    original_fixture = profile.fixture_arguments
    try:
        os.environ["PYTHONPATH"] = str(source)
        for kind in ("ascii", "unicode"):
            for position in ("early", "late"):
                order = ("python", "native") if position == "early" else ("native", "python")
                for arm in order:
                    result = None
                    started = None
                    scheduled = {"kind": kind, "position": position, "arm": arm}
                    try:
                        if source_identity(source) != sources or harness_identity() != harness:
                            raise RuntimeError("native_mcp_marker_source_changed")
                        if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != own_digest:
                            raise RuntimeError("native_mcp_marker_runner_changed")
                        if executable_identity(args.native_text_helper) != executable:
                            raise RuntimeError("native_mcp_marker_executable_changed")
                        profile.fixture_arguments = lambda size, kind, index, position=position: marker_arguments(
                            size, kind, index, position
                        )
                        with profile.performance_lock(args.lock_file):
                            started = datetime.now(timezone.utc).isoformat()
                            result = profile.run_case(
                                payload_bytes=PAYLOAD_BYTES,
                                payload_kind=kind,
                                compact_result=True,
                                samples=3,
                                profile=True,
                                native_text_helper=args.native_text_helper if arm == "native" else None,
                            )
                            finished = datetime.now(timezone.utc).isoformat()
                        if source_identity(source) != sources or harness_identity() != harness:
                            raise RuntimeError("native_mcp_marker_source_changed_during_case")
                        if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != own_digest:
                            raise RuntimeError("native_mcp_marker_runner_changed_during_case")
                        if executable_identity(args.native_text_helper) != executable:
                            raise RuntimeError("native_mcp_marker_executable_changed_during_case")
                        if any(sources.get(name) != digest for name, digest in result["loaded_runtime_sha256"].items()):
                            raise RuntimeError("native_mcp_marker_wrong_runtime_loaded")
                        if arm == "native":
                            counters = result["native_text_pilot"]["counters"]
                            if counters.get("native_failures", 0) or counters.get("native_completed", 0) < 4:
                                raise RuntimeError("native_mcp_marker_native_execution_failed")
                    except (Exception, KeyboardInterrupt) as error:
                        failure = (
                            error.evidence
                            if isinstance(error, profile.BenchmarkCaseError)
                            else {"reason": type(error).__name__}
                        )
                        if result is not None:
                            failure["completed_case_result"] = result
                            failure["measurement_valid"] = False
                        report["failed_case"] = {"scheduled": scheduled, "started_utc": started, **failure}
                        profile.write_checkpoint(args.json, report)
                        raise
                    result.update({**scheduled, "started_utc": started, "finished_utc": finished})
                    report["cases"].append(result)
                    profile.write_checkpoint(args.json, report)
                    print(json.dumps({"case": len(report["cases"]), "total": 8, **scheduled}), flush=True)
                    time.sleep(0.1)
        comparisons = []
        for offset in range(0, len(report["cases"]), 2):
            pair = report["cases"][offset : offset + 2]
            old = next(case for case in pair if case["arm"] == "python")
            new = next(case for case in pair if case["arm"] == "native")
            parity = old["correctness"] == new["correctness"]
            comparisons.append({"kind": old["kind"], "position": old["position"], "exact_correctness_parity": parity})
            if not parity:
                report["failed_parity"] = {"pair": offset // 2}
                profile.write_checkpoint(args.json, report)
                raise RuntimeError("native_mcp_marker_exact_parity_failed")
        report["comparisons"] = comparisons
        profile.write_checkpoint(args.json, report)
        return report
    finally:
        profile.fixture_arguments = original_fixture
        if prior_pythonpath is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = prior_pythonpath


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--text-src", type=Path, required=True)
    parser.add_argument("--native-text-helper", type=Path, required=True)
    parser.add_argument("--lock-file", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    run(parser.parse_args())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
