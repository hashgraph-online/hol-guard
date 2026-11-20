"""Fixed installed readiness/Stop diagnostic; not an installed SLO qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", choices=("off", "on"), required=True)
    parser.add_argument("--expected-build-sha", required=True)
    parser.add_argument("--cases", type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.cases <= 6 or re.fullmatch(r"[0-9a-f]{40}", args.expected_build_sha) is None:
        parser.error("select a bounded cohort and exact installed source SHA")
    root = args.root.resolve()
    root.mkdir(mode=0o700)
    profile = root / "profile"
    profile.mkdir(mode=0o700)
    os.environ["HOME"] = str(profile)
    for key in ("HOL_GUARD_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "CODEX_HOME"):
        os.environ.pop(key, None)

    from scripts.bench_guard_native_installed_slo_runtime import (
        _clear_proof_overrides,
        _readiness_samples,
        _runtime_summary,
    )
    from scripts.cigar_benchmark_processes import ProcessSampler
    from scripts.cigar_slo_activity import CigarSloActivity
    from scripts.native_slo_stop_trace import StopTrace

    runtime = args.runtime.resolve(strict=True)
    _clear_proof_overrides()
    identity = _runtime_summary(runtime)
    if identity["build_sha"] != args.expected_build_sha:
        raise RuntimeError("readiness Stop diagnostic selected a different installed source")
    selected = Path(json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text())["python"])
    repo = Path(__file__).resolve().parents[1]
    inputs = sorted(
        set((repo / "scripts").glob("native_slo*.py"))
        | {
            repo / name
            for name in (
                "scripts/bench_guard_cigar_readiness_stop_trace.py",
                "scripts/bench_guard_native_installed_slo_runtime.py",
                "scripts/cigar_slo_activity.py",
                "scripts/cigar_benchmark_processes.py",
                "scripts/cigar_benchmark_workload.py",
            )
        }
    )
    hashes = {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    result = {
        "schema": "guard-cigar-readiness-stop-trace.v1",
        "qualification": "fixed diagnostic cohort; helper phase logging; not an SLO or relative benchmark",
        "mode": args.mode,
        "planned_cases": args.cases,
        "runtime": identity,
        "source_sha256": hashes,
        "completed": False,
        "cases": [],
    }
    started = time.monotonic()
    try:
        with ProcessSampler(selected) as sampler, StopTrace(runtime, sampler) as trace:
            activity = CigarSloActivity(
                runtime,
                enabled=args.mode == "on",
                sampler=sampler,
                settle_seconds=0,
                diagnostics_dir=root / "diagnostics",
            )
            try:
                for index in range(args.cases):
                    trace.case = f"{args.mode}_{index + 1}"
                    before, baseline = sampler.sample_with_identities()
                    readiness = _readiness_samples(runtime, 1, activity=activity)
                    after, current = sampler.sample_with_identities()
                    result["cases"].append(
                        {
                            "case": trace.case,
                            "native_readiness_ms": readiness[0],
                            "before": before,
                            "after": after,
                            "new_counts": dict(Counter(kind for key, kind in current.items() if key not in baseline)),
                        }
                    )
            finally:
                result["stop_events"] = trace.events
                result["fixture_containment"] = activity.cleanups
                result["activation_ms"] = activity.activation_ms
                result["activity_phases"] = activity.phases
                result["observed_at_end"] = sampler.sample()
                result["all_observed_processes"] = sampler.summary()
        result["completed"] = True
    finally:
        result["seconds"] = round(time.monotonic() - started, 3)
        result["source_unchanged"] = all(
            hashlib.sha256((repo / name).read_bytes()).hexdigest() == h for name, h in hashes.items()
        )
        events = result.get("stop_events", [])
        result["strict_stops_all_succeeded"] = bool(events) and all(e.get("returncode") == 0 for e in events)
        result["trace_complete"] = (
            result["completed"]
            and len(result["cases"]) == args.cases
            and result["all_observed_processes"]["sampling_errors"] == 0
            and all(
                e["stderr_within_bound"] and not any("sampling_error_type" in e[side] for side in ("before", "after"))
                for e in events
            )
        )
        with (root / "result.json").open("x") as output:
            json.dump(result, output, indent=2)
            output.write("\n")
    return 0 if result["strict_stops_all_succeeded"] and result["trace_complete"] and result["source_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
