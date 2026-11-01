"""Fixed, alternating off/on cohort around the unchanged focused latency limits.

Keep failed runs and stop at the first failure. Compare medians of per-run p95
values, and retain every paired delta. This is not the complete installed SLO.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts.native_slo_contract import clear_proof_environment  # noqa: E402


def receipt(path: Path) -> dict:
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def qualified(report: dict, mode: str, build: str) -> bool:
    gates = report.get("gates", {})
    return (
        report.get("completed") is True
        and report.get("mode") == mode
        and report.get("build_sha") == build
        and isinstance(gates, dict)
        and len(gates) >= 12
        and all(type(value) is bool and value for value in gates.values())
    )


def comparison(rows: list[dict], pairs: int) -> dict:
    expected = {(pair, mode) for pair in range(1, pairs + 1) for mode in ("off", "on")}
    if len(rows) != pairs * 2 or {(r["pair"], r["mode"]) for r in rows} != expected:
        raise ValueError("relative qualification requires every declared pair exactly once")
    builds = {r["report"].get("build_sha") for r in rows}
    if len(builds) != 1:
        raise ValueError("relative qualification requires one artifact and every individual gate")
    build = next(iter(builds))
    if (
        not isinstance(build, str)
        or re.fullmatch(r"[0-9a-f]{40}", build) is None
        or not all(qualified(r["report"], r["mode"], build) for r in rows)
    ):
        raise ValueError("relative qualification requires one artifact and every individual gate")
    selected = {(r["pair"], r["mode"]): r["report"] for r in rows}
    result = {}
    for boundary in ("direct", "installed_http"):
        values = {"off": [], "on": []}
        deltas = []
        for pair in range(1, pairs + 1):
            for mode in values:
                report = selected[pair, mode]
                value = (report["direct_adapter_warm"] if boundary == "direct" else report["stages"]["1"]["latency"])[
                    "p95_ms"
                ]
                if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                    raise ValueError("relative latency must be a finite nonnegative measurement")
                values[mode].append(value)
            delta = values["on"][-1] - values["off"][-1]
            deltas.append(
                {"pair": pair, "delta_ms": round(delta, 3), "allowance_ms": max(1.0, values["off"][-1] * 0.05)}
            )
        off, on = statistics.median(values["off"]), statistics.median(values["on"])
        allowance = max(1.0, off * 0.05)
        result[boundary] = {
            "per_run_p95_ms": values,
            "off_median_p95_ms": off,
            "on_median_p95_ms": on,
            "median_delta_ms": round(on - off, 3),
            "allowance_ms": allowance,
            "relative_gate": on - off <= allowance,
            "paired_deltas": deltas,
        }
    result["all_relative_gates"] = all(result[k]["relative_gate"] for k in ("direct", "installed_http"))
    return result


def fingerprints(runtime: Path, installed: Path) -> dict[str, str]:
    paths = set((installed / "codex_plugin_scanner").rglob("*.py"))
    paths.update((REPO / "scripts").glob("native_slo*.py"))
    paths.update((REPO / "scripts").glob("bench_guard_native*.py"))
    paths.update(
        REPO / "scripts" / name
        for name in (
            "bench_guard_cigar_contention.py",
            "bench_guard_cigar_cohort.py",
            "cigar_benchmark_workload.py",
            "cigar_benchmark_processes.py",
        )
    )
    paths.update(
        (runtime, runtime.with_name("runtime-manifest.json"), runtime.with_name("source-compiler-manifest.json"))
    )
    paths.update(Path(os.environ[key]) for key in ("GUARD_CIGAR_TEST_SELECTION", "GUARD_CIGAR_TEST_APPROVAL"))
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--expected-build-sha", required=True)
    parser.add_argument("--pairs", type=int, default=5)
    parser.add_argument("--warm-iterations", type=int, default=200)
    parser.add_argument("--waves", type=int, default=5)
    args = parser.parse_args()
    if not 3 <= args.pairs <= 10 or not 50 <= args.warm_iterations <= 2000 or not 2 <= args.waves <= 20:
        parser.error("cohort profile exceeds its bounded range")
    if re.fullmatch(r"[0-9a-f]{40}", args.expected_build_sha) is None:
        parser.error("select the exact installed artifact source SHA")
    runtime = args.runtime.resolve(strict=True)
    installed = runtime.parents[2]
    root = args.root.resolve()
    root.mkdir(mode=0o700)
    profile = root / "controller-profile"
    profile.mkdir(mode=0o700)
    environment = dict(os.environ)
    clear_proof_environment(environment)
    for key in (
        "HOL_GUARD_HOME",
        "HOL_GUARD_RESIDENT_TEST_SEAMS",
        "NATIVE_STOP_DIAGNOSTIC_PATH",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
        "CODEX_HOME",
    ):
        environment.pop(key, None)
    environment.update(HOME=str(profile), PYTHONPATH=os.pathsep.join((str(installed), str(REPO))))
    origin = subprocess.check_output(
        [sys.executable, "-c", "import importlib.util; print(importlib.util.find_spec('codex_plugin_scanner').origin)"],
        env=environment,
        text=True,
        timeout=10,
    ).strip()
    if Path(origin).resolve() != installed / "codex_plugin_scanner/__init__.py":
        raise RuntimeError("cohort must import the explicitly selected installed package")
    caps = json.loads(subprocess.check_output([str(runtime), "capabilities", "--json"], env=environment, timeout=10))
    if caps["build_sha"] != args.expected_build_sha:
        raise RuntimeError("cohort native source differs from the declared artifact")
    frozen = fingerprints(runtime, installed)
    with (root / "inputs.json").open("x") as output:
        json.dump(frozen, output, indent=2)
        output.write("\n")
    result = {
        "schema": "guard-cigar-matched-contention-cohort.v1",
        "completed": False,
        "qualification": "focused installed synthetic cohort; explicitly selected force-mode native artifact",
        "build_sha": caps["build_sha"],
        "native": receipt(runtime),
        "inputs": receipt(root / "inputs.json"),
        "planned_pairs": args.pairs,
        "warm_iterations": args.warm_iterations,
        "waves": args.waves,
        "order": "odd pairs off/on; even pairs on/off",
        "rows": [],
        "estimator": "median of each mode's per-run p95 values; allowance max(1 ms, 5% of off median)",
        "limits": [
            "Original focused absolute gates remain intact; this is separate from the complete installed SLO.",
            "Hook clients/load thread/daemon share one driver; measurements include that topology and sampler work.",
            "All observed worker RSS is included; shared pages may be counted more than once.",
            "One selected document and unchanged graph; no internal tokenization or model/human efficiency claim.",
        ],
    }
    started = time.monotonic()
    try:
        for pair in range(1, args.pairs + 1):
            for mode in ("off", "on") if pair % 2 else ("on", "off"):
                if fingerprints(runtime, installed) != frozen:
                    raise RuntimeError("cohort inputs changed before a run")
                case = f"pair-{pair}-{mode}"
                row = {"pair": pair, "mode": mode, "case": case}
                result["rows"].append(row)
                print(json.dumps({"starting": case}), flush=True)
                command = [
                    sys.executable,
                    "-u",
                    str(REPO / "scripts/bench_guard_cigar_contention.py"),
                    "--runtime",
                    str(runtime),
                    "--root",
                    str(root / case),
                    "--mode",
                    mode,
                    "--expected-build-sha",
                    args.expected_build_sha,
                    "--warm-iterations",
                    str(args.warm_iterations),
                    "--waves",
                    str(args.waves),
                ]
                with (root / f"{case}.stdout.log").open("x") as out, (root / f"{case}.stderr.log").open("x") as err:
                    outcome = subprocess.run(command, env=environment, cwd=REPO, stdout=out, stderr=err, timeout=900)
                row["returncode"] = outcome.returncode
                path = root / case / "result.json"
                if path.exists():
                    row["report_receipt"] = receipt(path)
                    row["report"] = json.loads(path.read_text())
                row["inputs_unchanged"] = fingerprints(runtime, installed) == frozen
                row["passed"] = (
                    outcome.returncode == 0
                    and row["inputs_unchanged"]
                    and qualified(row.get("report", {}), mode, args.expected_build_sha)
                )
                print(json.dumps({"finished": case, "passed": row["passed"]}), flush=True)
                if not row["passed"]:
                    return 1
        result["comparison"] = comparison(result["rows"], args.pairs)
        result["completed"] = True
    except BaseException as error:
        result["failure_type"] = type(error).__name__
        raise
    finally:
        result["seconds"] = round(time.monotonic() - started, 3)
        try:
            result["final_inputs_unchanged"] = fingerprints(runtime, installed) == frozen
        except (OSError, ValueError) as error:
            result["final_inputs_unchanged"] = False
            result["fingerprint_error_type"] = type(error).__name__
        result["qualified"] = (
            result["completed"]
            and result["final_inputs_unchanged"]
            and result.get("comparison", {}).get("all_relative_gates", False)
        )
        with (root / "result.json").open("x") as output:
            json.dump(result, output, indent=2)
            output.write("\n")
    return 0 if result["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
