#!/usr/bin/env python3
"""Compare an explicit four-predicate helper to each applicable Python source.

Small controls use optimized Python B. String-heavy near-limit inputs use
the frozen structural-facts candidate D as their stronger Python comparator.
Both arms of each pair import exactly the same runtime source. The native arm
adds only the qualification adapter; no production selection is made here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import time
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path

from compare_guard_mcp_risk import source_identity, verify_facts
from guard_mcp_text_facts_pilot import TextFactsPilot, executable_identity, install_adapter
from profile_guard_mcp_session import BenchmarkCaseError, performance_lock, run_case, write_checkpoint


def harness_identity() -> dict[str, str]:
    return {
        name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
        for name in (
            "compare_guard_mcp_native_text.py",
            "compare_guard_mcp_risk.py",
            "profile_guard_mcp_session.py",
            "guard_mcp_text_facts_pilot.py",
        )
    }


def facts_oracle(baseline: Path, executable: Path) -> tuple[dict, int]:
    from codex_plugin_scanner.guard import mcp_tool_calls as candidate

    pilot = TextFactsPilot(executable, minimum_characters=0)
    restore = install_adapter(candidate, pilot)
    report = {
        "matched_cases": 0,
        "attempted_cases": 0,
        "qualification": False,
        "loaded_risk_sha256": hashlib.sha256(Path(candidate.__file__).read_bytes()).hexdigest(),
    }

    def progress(count):
        report["matched_cases"] = count
        # Bounded progress survives even an outer timeout; no input is emitted.
        print(json.dumps({"matched_cases_progress": count}), flush=True)

    def attempt(count):
        report["attempted_cases"] = count
        print(json.dumps({"attempted_cases_progress": count}), flush=True)

    try:
        report["parity"] = verify_facts(baseline, progress=progress, attempt=attempt)
        if pilot.counters["native_completed"] < report["matched_cases"]:
            raise RuntimeError("native_mcp_oracle_did_not_force_every_case")
        status = 0
    except Exception as error:
        report["failure"] = type(error).__name__
        status = 1
    finally:
        restore()
        report["native_text_pilot"] = pilot.evidence()
    return report, status


def schedule(samples: int) -> list[dict]:
    fixtures = [
        {"scope": "ordinary_B", "payload_bytes": size, "payload_kind": "ascii"} for size in (1024, 16384, 131072)
    ] + [
        {
            "scope": "near_limit_text_D",
            "payload_bytes": 4 * 1024 * 1024 - 512,
            "payload_kind": kind,
            "compact_result": True,
        }
        for kind in ("ascii", "unicode")
    ]
    cases = []
    for block in range(5):
        for fixture in fixtures:
            for arm in ("python", "native") if block % 2 == 0 else ("native", "python"):
                cases.append({**fixture, "block": block, "arm": arm, "samples": samples})
    for fixture in fixtures:
        for arm in ("python", "native"):
            cases.append({**fixture, "block": None, "arm": arm, "samples": min(samples, 10), "profile": True})
    return cases


def run_comparison(args) -> dict:
    roots = {"ordinary_B": args.ordinary_src.resolve(), "near_limit_text_D": args.text_src.resolve()}
    sources = {scope: source_identity(root) for scope, root in roots.items()}
    harness = harness_identity()
    executable = executable_identity(args.native_text_helper)
    report = {
        "schema": "hol-guard-mcp-native-text-comparison.v1",
        "qualification": False,
        "platform": platform.system(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "runtime_sources_sha256": sources,
        "harness_sources_sha256": harness,
        "native_executable": executable,
        "measurement_lock": "per_case_POSIX_flock",
        "campaign": "five_alternating_process_blocks_same_source_per_pair",
        "samples_per_uninstrumented_block": args.samples,
        "limitations": [
            "explicit_source_route_pilot_not_installed_or_production_selected",
            "single_host_c1",
            "sample_count_below_release_tail_gate",
            "profile_timings_not_qualification",
            "no_windows_macos_tls_or_live_remote_native_claim",
            "RSP100_unresolved_D_is_only_the_string_heavy_comparator",
        ],
        "facts_parity": {},
        "cases": [],
    }
    if args.json.exists():
        raise ValueError("native_mcp_comparison_refuses_to_overwrite_attempts")
    write_checkpoint(args.json, report)
    for scope, source in roots.items():
        environment = {**os.environ, "PYTHONPATH": str(source)}
        with performance_lock(args.lock_file):
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--facts-oracle",
                    "--ordinary-src",
                    str(roots["ordinary_B"]),
                    "--text-src",
                    str(source),
                    "--native-text-helper",
                    str(args.native_text_helper),
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                start_new_session=True,
            )
            timed_out = False
            try:
                output, _ = process.communicate(timeout=180)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                output, _ = process.communicate(timeout=5)
        records = []
        for line in output.splitlines():
            with suppress(ValueError):
                records.append(json.loads(line))
        if records and "native_text_pilot" in records[-1]:
            parity = records[-1]
        else:
            parity = {
                "failure": "oracle_timeout" if timed_out else "oracle_unavailable",
                "returncode": process.returncode,
                "matched_cases": max((record.get("matched_cases_progress", 0) for record in records), default=0),
                "attempted_cases": max((record.get("attempted_cases_progress", 0) for record in records), default=0),
            }
        report["facts_parity"][scope] = parity
        write_checkpoint(args.json, report)
        if process.returncode or parity.get("failure"):
            raise RuntimeError("native_mcp_facts_parity_failed")
        if parity["loaded_risk_sha256"] != sources[scope]["mcp_tool_calls.py"]:
            report["facts_parity"][scope]["failure"] = "wrong_runtime_source_loaded"
            write_checkpoint(args.json, report)
            raise RuntimeError("native_mcp_facts_oracle_wrong_source")
    cases = schedule(args.samples)
    prior_pythonpath = os.environ.get("PYTHONPATH")
    try:
        for index, scheduled in enumerate(cases):
            options = dict(scheduled)
            scope, arm, block = options.pop("scope"), options.pop("arm"), options.pop("block")
            started = None
            result = None
            try:
                if source_identity(roots[scope]) != sources[scope] or harness_identity() != harness:
                    raise RuntimeError("native_mcp_comparison_source_changed")
                if executable_identity(args.native_text_helper) != executable:
                    raise RuntimeError("native_mcp_comparison_executable_changed")
                os.environ["PYTHONPATH"] = str(roots[scope])
                with performance_lock(args.lock_file):
                    started = datetime.now(timezone.utc).isoformat()
                    result = run_case(
                        **options,
                        native_text_helper=args.native_text_helper if arm == "native" else None,
                    )
                    finished = datetime.now(timezone.utc).isoformat()
                if any(sources[scope].get(name) != digest for name, digest in result["loaded_runtime_sha256"].items()):
                    raise RuntimeError("native_mcp_comparison_wrong_runtime_loaded")
                if source_identity(roots[scope]) != sources[scope] or harness_identity() != harness:
                    raise RuntimeError("native_mcp_comparison_source_changed_during_case")
                if executable_identity(args.native_text_helper) != executable:
                    raise RuntimeError("native_mcp_comparison_executable_changed_during_case")
                native = result["native_text_pilot"]
                if arm == "native":
                    counts = native["counters"]
                    if scope == "ordinary_B":
                        if counts.get("starts", 0) or counts.get("native_attempts", 0):
                            raise RuntimeError("native_mcp_small_control_did_not_select_python")
                    elif counts.get("native_completed", 0) < options["samples"] + 1:
                        raise RuntimeError("native_mcp_large_case_did_not_use_native")
                    if counts.get("native_failures", 0):
                        raise RuntimeError("native_mcp_comparison_hidden_helper_failure")
            except (Exception, KeyboardInterrupt) as error:
                failure = (
                    error.evidence
                    if isinstance(error, BenchmarkCaseError)
                    else {
                        "reason": type(error).__name__,
                        "failure_code": str(error) if str(error).startswith("native_mcp_") else type(error).__name__,
                    }
                )
                if result is not None:
                    failure["completed_case_result"] = result
                    failure["measurement_valid"] = False
                report["failed_case"] = {
                    "index": index + 1,
                    "scheduled": scheduled,
                    "started_utc": started,
                    "failed_utc": datetime.now(timezone.utc).isoformat(),
                    **failure,
                }
                write_checkpoint(args.json, report)
                raise
            result.update(
                {"scope": scope, "arm": arm, "block": block, "started_utc": started, "finished_utc": finished}
            )
            report["cases"].append(result)
            report["completed_cases"] = len(report["cases"])
            write_checkpoint(args.json, report)
            print(json.dumps({"case": index + 1, "total": len(cases), **scheduled}), file=sys.stderr, flush=True)
            time.sleep(0.1)
    finally:
        if prior_pythonpath is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = prior_pythonpath
    comparisons = []
    for index in range(0, len(report["cases"]), 2):
        pair = report["cases"][index : index + 2]
        old = next(case for case in pair if case["arm"] == "python")
        new = next(case for case in pair if case["arm"] == "native")
        parity = old["correctness"] == new["correctness"]
        comparisons.append(
            {
                "scope": old["scope"],
                "block": old["block"],
                "payload_bytes": old["fixture"]["payload_bytes"],
                "payload_kind": old["fixture"]["payload_kind"],
                "profile": old["fixture"]["profile"],
                "exact_correctness_parity": parity,
                "roundtrip_p95_change_percent": 100
                * (new["client_roundtrip_ms"]["p95"] / old["client_roundtrip_ms"]["p95"] - 1),
                "tree_cpu_change_percent": 100 * (new["tree_cpu_ms_per_call"] / old["tree_cpu_ms_per_call"] - 1),
            }
        )
        if not parity:
            report["failed_parity"] = {"pair": index // 2}
            write_checkpoint(args.json, report)
            raise RuntimeError("native_mcp_comparison_exact_parity_failed")
    report["comparisons"] = comparisons
    write_checkpoint(args.json, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ordinary-src", type=Path, required=True)
    parser.add_argument("--text-src", type=Path, required=True)
    parser.add_argument("--native-text-helper", type=Path, required=True)
    parser.add_argument("--facts-oracle", action="store_true")
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--lock-file", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.facts_oracle:
        report, status = facts_oracle(args.ordinary_src, args.native_text_helper)
        print(json.dumps(report))
        return status
    if args.json is None or args.lock_file is None or not 1 <= args.samples <= 10000:
        parser.error("comparison requires --json, --lock-file and samples1..10000")
    report = run_comparison(args)
    print(json.dumps({"completed_cases": report["completed_cases"], "qualification": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
