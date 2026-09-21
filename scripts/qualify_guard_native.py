#!/usr/bin/env python3
"""Run paired installed-artifact performance blocks with explicit coverage gaps.

Use separate interpreters containing baseline and candidate native wheels. This
runner never silently substitutes a semantic oracle for the production baseline.
Private numeric observations and publishable aggregates are saved separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process  # noqa: E402
from scripts.native_slo_acceptance import scoped_acceptance  # noqa: E402
from scripts.native_slo_artifact import wheel_package_digest  # noqa: E402
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402
from scripts.native_slo_qualification import compare_routes, paired_order, sampling_gates, sampling_plan  # noqa: E402


def _object_field(report: Mapping[str, object], field: str) -> Mapping[str, object]:
    value = report.get(field)
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise RuntimeError("paired block evidence object invalid: " + field)
    return cast(Mapping[str, object], value)


def _text_field(report: Mapping[str, object], field: str) -> str:
    value = report.get(field)
    if not isinstance(value, str) or not value:
        raise RuntimeError("paired block evidence identifier invalid: " + field)
    return value


def _run_pair(args: argparse.Namespace) -> dict[str, object]:
    import os

    plan = sampling_plan(runs=args.runs, qualification=args.mode == "qualification")
    interpreters = {"baseline": args.baseline_python, "candidate": args.candidate_python}
    if any(interpreter is None for interpreter in interpreters.values()):
        raise ValueError("both installed-artifact interpreters are required")
    # Virtualenv interpreters may be symlinks to the same Python executable;
    # their distinct launch paths still select different installed artifacts.
    if os.path.abspath(args.baseline_python) == os.path.abspath(args.candidate_python):
        raise ValueError("baseline and candidate must use distinct installed environments")
    artifact_digests: dict[str, str] = {}
    expected_package_digests: dict[str, str] = {}
    for arm, artifact in (("baseline", args.baseline_artifact), ("candidate", args.candidate_artifact)):
        if artifact is None:
            if args.mode == "qualification":
                raise ValueError("qualification requires both installed wheel artifact files")
            artifact_digests[arm] = "unrecorded"
        else:
            digest = hashlib.sha256()
            with artifact.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            artifact_digests[arm] = digest.hexdigest()
            expected_package_digests[arm] = wheel_package_digest(artifact)
    environment = dict(os.environ)
    clear_proof_environment(environment)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    private = args.output_dir / "private_samples"
    public = args.output_dir / "aggregate"
    private.mkdir(mode=0o700, exist_ok=True)
    public.mkdir(exist_ok=True)
    reports: dict[str, list[dict[str, object]]] = {"baseline": [], "candidate": []}
    for run in range(args.runs):
        failures: list[dict[str, object]] = []
        for arm in paired_order(run):
            raw_file = private / f"{run:02d}-{arm}.json"
            completed = run_isolated_hook_process(
                (
                    str(interpreters[arm]),
                    str(Path(__file__).resolve()),
                    "--worker",
                    "--mode",
                    args.mode,
                    "--runs",
                    str(args.runs),
                    "--raw-file",
                    str(raw_file),
                    "--receipt-profile",
                    "baseline_2e672d2" if arm == "baseline" else "candidate",
                ),
                input_text="",
                cwd=_ROOT,
                environment=environment,
                timeout_seconds=args.block_timeout_seconds,
                output_limit=256 * 1024,
            )
            if (
                completed.returncode != 0
                or completed.timed_out
                or completed.containment_failed
                or completed.output_limit_exceeded
            ):
                failure: dict[str, object] = {
                    "schema": "hol-guard.native-qualification-failure.v1",
                    "reason": "paired_worker_process_failed",
                }
                try:
                    parsed_failure = json.loads(completed.stdout)
                    if isinstance(parsed_failure, dict) and parsed_failure.get("schema") == failure["schema"]:
                        failure = assert_privacy_safe(parsed_failure)
                except (ValueError, TypeError):
                    pass
                failure.update(
                    arm=arm,
                    run=run,
                    artifact_sha256=artifact_digests[arm],
                    timed_out=completed.timed_out,
                    containment_failed=completed.containment_failed,
                    worker_limit_exceeded=completed.output_limit_exceeded,
                    return_code=completed.returncode,
                )
                failure = assert_privacy_safe(failure)
                (public / f"{run:02d}-{arm}-failure.json").write_text(
                    json.dumps(failure, indent=2) + "\n", encoding="utf-8"
                )
                # Raw stderr/tracebacks remain private; expose only bounded
                # generated failure identifiers from our worker protocol.
                print(json.dumps(failure, sort_keys=True), file=sys.stderr, flush=True)
                failures.append(failure)
                continue
            report = json.loads(completed.stdout)
            if not isinstance(report, dict) or report.get("schema") != "hol-guard.native-qualification-block.v1":
                raise RuntimeError("paired block returned invalid evidence")
            safe = assert_privacy_safe(report)
            if (
                arm in expected_package_digests
                and _object_field(safe, "runtime").get("installed_package_sha256") != expected_package_digests[arm]
            ):
                raise RuntimeError("paired interpreter does not contain the declared wheel artifact")
            if not raw_file.is_file():
                raise RuntimeError("paired block did not retain numeric observations")
            safe["artifact_sha256"] = artifact_digests[arm]
            (public / f"{run:02d}-{arm}.json").write_text(json.dumps(safe, indent=2) + "\n", encoding="utf-8")
            reports[arm].append(safe)
            print(f"completed paired block {run + 1}/{args.runs} {arm}", file=sys.stderr, flush=True)
        if failures:
            # A baseline failure must not suppress the candidate in that pair.
            # Stop after both arms have had the same opportunity; never form a
            # comparison from incomplete pairs or resample a failed block.
            incomplete = assert_privacy_safe(
                {
                    "schema": "hol-guard.native-incomplete-pair.v1",
                    "failed_run": run,
                    "planned_runs": args.runs,
                    "attempted_blocks": 2 * (run + 1),
                    "unattempted_blocks": 2 * (args.runs - run - 1),
                    "completed_blocks": {arm: len(items) for arm, items in reports.items()},
                    "failures": failures,
                    "comparison_available": False,
                    "qualification_complete": False,
                }
            )
            (public / "incomplete-pair.json").write_text(json.dumps(incomplete, indent=2) + "\n", encoding="utf-8")
            raise RuntimeError(f"paired block failed: run={run}; both arms retained; comparison unavailable")
    combined = reports["baseline"] + reports["candidate"]
    if len({_text_field(report, "corpus_digest") for report in combined}) != 1:
        raise RuntimeError("paired artifacts used different corpus definitions")
    identities = [_object_field(report, "hardware") for report in combined]
    stable_fields = ("platform", "cpu_model", "cpu_count", "effective_cpu_count", "ram_bytes", "os_release")
    if any(any(item.get(field) != identities[0].get(field) for field in stable_fields) for item in identities[1:]):
        raise RuntimeError("paired hardware identity changed between blocks")
    if len({_text_field(_object_field(report, "runtime"), "python_version") for report in combined}) != 1:
        raise RuntimeError("paired interpreter version changed between artifacts")
    # Keep artifact identity stable within each arm, not equal across arms.
    for arm in reports.values():
        if (
            len(
                {
                    tuple(
                        _text_field(_object_field(report, "runtime"), key)
                        for key in ("runtime_sha256", "package_record_sha256")
                    )
                    for report in arm
                }
            )
            != 1
        ):
            raise RuntimeError("artifact changed within a paired arm")
    comparison = compare_routes(
        [_object_field(report, "measurements") for report in reports["baseline"]],
        [_object_field(report, "measurements") for report in reports["candidate"]],
    )
    gates = sampling_gates(comparison, runs=args.runs)
    gates["steady_state_resources"] = all(
        _object_field(report, "resources").get("sample_minimum_met") is True for report in combined
    )
    acceptance = scoped_acceptance(reports["baseline"], reports["candidate"], comparison, gates)
    result = assert_privacy_safe(
        {
            "schema": "hol-guard.native-paired-performance.v1",
            "evidence_class": "qualification_sampling" if args.mode == "qualification" else "smoke",
            "plan": plan,
            "order": "alternating_baseline_candidate_blocks",
            "corpus_digest": combined[0]["corpus_digest"],
            "baseline": reports["baseline"][0]["runtime"],
            "candidate": reports["candidate"][0]["runtime"],
            "artifact_digests": artifact_digests,
            "hardware": identities[0],
            "comparisons": comparison,
            "sampling_gates": gates,
            "sampling_passed": all(gates.values()),
            "acceptance": acceptance,
            "qualification_complete": args.mode == "qualification"
            and all(scope["qualified"] for scope in acceptance["scopes"].values()),
            "qualification_scope": "observed_platform_implemented_hook_boundaries",
            "program_qualification_complete": False,
        }
    )
    (public / "comparison.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-python", type=Path)
    parser.add_argument("--candidate-python", type=Path)
    parser.add_argument("--baseline-artifact", type=Path)
    parser.add_argument("--candidate-artifact", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("native-qualification"))
    parser.add_argument("--mode", choices=("smoke", "qualification"), default="smoke")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--block-timeout-seconds", type=float, default=3600)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--raw-file", type=Path, help=argparse.SUPPRESS)
    parser.add_argument(
        "--receipt-profile", choices=("candidate", "baseline_2e672d2"), default="candidate", help=argparse.SUPPRESS
    )
    args = parser.parse_args()
    try:
        plan = sampling_plan(runs=args.runs, qualification=args.mode == "qualification")
        if not 0 < args.block_timeout_seconds <= 14400:
            raise ValueError("block timeout must be positive and at most four hours")
        if args.worker:
            if args.raw_file is None:
                raise ValueError("worker numeric sample destination is required")
            from scripts.native_slo_qualification_run import run_block

            result = run_block(plan=plan, raw_file=args.raw_file, receipt_profile=args.receipt_profile)
        else:
            result = _run_pair(args)
    except Exception as error:
        if args.worker:
            print(json.dumps(failure_evidence(error), sort_keys=True))
            return 1
        parser.exit(1, f"native qualification failed: {error}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    # Sampling success does not imply that remaining PRD obligations passed.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
