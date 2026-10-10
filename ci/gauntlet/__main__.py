"""Command-line entry point for real-agent acceptance and evidence verification."""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import signal
import sys
from pathlib import Path

from .catalog import load_catalog
from .provider import REASONING_EFFORTS


def main() -> int:
    """Dispatch Gauntlet commands and return a process exit status."""
    parser = argparse.ArgumentParser(description="Guard Gauntlet: real agents, real tools, observed protection")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List the fixed required scenarios without running them")
    run = sub.add_parser("run", help="Run actual Oh My Pi with a live inference provider")
    run.add_argument("--expected-source-sha", required=True)
    run.add_argument("--candidate-sha", help="PR head when testing its exact two-parent merge")
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--provider-url", default=os.environ.get("GUARD_GAUNTLET_PROVIDER_URL"))
    run.add_argument("--model", default=os.environ.get("GUARD_GAUNTLET_MODEL"))
    run.add_argument("--provider-identity", default=os.environ.get("GUARD_GAUNTLET_PROVIDER_IDENTITY"))
    run.add_argument(
        "--reasoning-effort",
        choices=REASONING_EFFORTS,
        default=os.environ.get("GUARD_GAUNTLET_REASONING_EFFORT") or None,
        help="Pin the provider's reasoning_effort on every relayed request (for example GPT 6 Luna High)",
    )
    run.add_argument("--api-key-env", default="GUARD_GAUNTLET_API_KEY")
    run.add_argument("--allow-loopback-provider", action="store_true")
    run.add_argument(
        "--native-luna-route",
        action="store_true",
        help="Run OpenAI Luna (openai-codex/gpt-6-luna) through the existing Oh My Pi ChatGPT login; "
        "medium effort unless --reasoning-effort high or low",
    )
    run.add_argument("--sdk-root", type=Path, help="Pinned SDK directory for --native-luna-route (default: from omp)")
    run.add_argument("--case", action="append", dest="cases", help="Targeted runs are never full-profile qualification")
    run.add_argument("--timeout", type=float, default=300, help="Per-scenario host deadline in seconds")
    run.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Concurrent isolated case workers (1-8; default 1 runs cases sequentially in-process)",
    )
    run.add_argument("--max-inference-rounds", type=int, default=32)
    run.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop scheduling new cases after the first non-pass outcome; in-flight cases finish normally",
    )
    run.add_argument(
        "--host-slots",
        type=int,
        default=os.environ.get("GUARD_GAUNTLET_HOST_SLOTS"),
        help="Host-wide cap on running cases via shared slot files (1-64; POSIX only)",
    )
    run.add_argument(
        "--slot-dir",
        type=Path,
        default=os.environ.get("GUARD_GAUNTLET_SLOT_DIR"),
        help="Directory of host slot files (default ~/.cache/hol-guard-gauntlet/slots)",
    )
    run.add_argument(
        "--max-load",
        type=float,
        default=os.environ.get("GUARD_GAUNTLET_MAX_LOAD"),
        help="Start new cases only while the 1-minute host load average is at or below this (POSIX only)",
    )
    run.add_argument(
        "--max-load-wait",
        type=float,
        default=os.environ.get("GUARD_GAUNTLET_MAX_LOAD_WAIT"),
        help="Total seconds to wait on host load before proceeding anyway (default 180; requires --max-load)",
    )
    run.add_argument("--omp", help="Path to the repository-pinned Oh My Pi executable")
    run.add_argument(
        "--harness",
        choices=("omp", "claude-code", "codex", "cursor"),
        default="omp",
        help="Agent CLI to drive. omp (default) is the qualification harness; claude-code, codex and cursor "
        "run through their own login and Guard's installed hooks and are never merge-qualifying",
    )
    run.add_argument("--harness-cli", help="Path to the claude, codex or cursor-agent executable (default: PATH)")
    run.add_argument("--harness-model", help="Model for --harness claude-code, codex or cursor (default: the CLI's)")
    run.add_argument("--work-root", type=Path, help="Parent for newly created disposable fixtures")
    run.add_argument(
        "--profile",
        choices=("core", "contained-bun-vitest"),
        default="core",
        help="Complete core qualification or the additive contained Bun/Vitest profile",
    )
    run.add_argument(
        "--contained-test-project",
        type=Path,
        help="Explicit fixture project for --profile contained-bun-vitest; dependencies are never installed",
    )
    verify = sub.add_parser("verify", help="Independently reconcile a complete evidence package")
    verify.add_argument("directory", type=Path)
    verify.add_argument("--expected-sha", required=True)
    verify.add_argument("--source-root", type=Path, help="Candidate checkout read only as data by a trusted verifier")
    verify.add_argument("--source-manifest", type=Path, help="Independently fetched immutable GitHub blob manifest")
    pack = sub.add_parser("pack", help="Verify and export only public qualification evidence")
    pack.add_argument("directory", type=Path)
    pack.add_argument("--expected-sha", required=True)
    pack.add_argument("--output", type=Path, required=True)
    pack.add_argument("--pr", type=int, help="Pull request receiving the inline public bundle")
    pack.add_argument("--dispatch-inputs", type=Path, help="Write bounded JSON for gh workflow run --json")
    pack.add_argument("--attest-real-inference", action="store_true")
    verify.add_argument(
        "--exploratory", action="store_true", help="Do not treat old-runtime exploration as merge proof"
    )
    qualify = sub.add_parser(
        "qualify", help="Cached build-and-run qualification driver; run it from a trusted main checkout"
    )
    qualify.add_argument("--sha", required=True, help="Full commit of the tested source or test merge")
    qualify.add_argument("--candidate-sha", help="PR head when qualifying its exact two-parent test merge")
    qualify.add_argument("--attempts", type=int, default=2, help="Bounded fresh runs (1-3)")
    qualify.add_argument("--jobs", type=int, default=4)
    qualify.add_argument(
        "--host-slots",
        type=int,
        default=os.environ.get("GUARD_GAUNTLET_HOST_SLOTS") or 8,
        help="Host-wide cap on running cases (1-64)",
    )
    qualify.add_argument(
        "--max-load",
        type=float,
        default=2.0 * (os.cpu_count() or 1),
        help="Start new cases only while the 1-minute host load average is at or below this",
    )
    qualify.add_argument(
        "--max-load-wait",
        type=float,
        default=180.0,
        help="Total seconds to wait on host load before proceeding anyway",
    )
    qualify.add_argument("--effort", choices=("medium", "high", "low"), default="medium")
    qualify.add_argument("--cache-root", type=Path, default=Path.home() / ".cache" / "hol-guard-gauntlet")
    qualify.add_argument(
        "--run-root",
        type=Path,
        help="New directory for this driver's work and evidence (default /tmp/hol-guard-gauntlet-<uid>/<sha>-<stamp>)",
    )
    qualify.add_argument(
        "--work-parent",
        type=Path,
        help="Parent for the short per-attempt fixture work directories (default /tmp/hol-guard-gauntlet-<uid>/w)",
    )
    qualify.add_argument("--wheel", type=Path, help="Prebuilt native wheel; required off macOS")
    qualify.add_argument("--sdk-root", type=Path, help="Pinned SDK directory; skips the lock-keyed SDK cache")
    qualify.add_argument("--keep-work", action="store_true", help="Keep passing attempts' work roots")
    qualify.add_argument("--timeout", type=float, default=300)
    qualify.add_argument("--max-inference-rounds", type=int, default=32)
    args = parser.parse_args()
    try:
        if args.command == "list":
            print(
                json.dumps(
                    [{"id": s.id, "expectation": s.expectation, "oracle": s.oracle} for s in load_catalog()], indent=2
                )
            )
            return 0
        if args.command == "pack":
            from .bundle import pack as pack_bundle
            from .verify import verify_report

            verify_report(args.directory, expected_sha=args.expected_sha)
            digest = pack_bundle(args.directory, args.output)
            if args.dispatch_inputs is not None:
                from .submission import inline_dispatch_inputs

                inputs = inline_dispatch_inputs(
                    args.output,
                    candidate_sha=args.expected_sha,
                    pr_number=args.pr or 0,
                    attested=args.attest_real_inference,
                )
                with args.dispatch_inputs.open("x", encoding="utf-8") as stream:
                    json.dump(inputs, stream)
            print(json.dumps({"path": str(args.output), "sha256": digest}))
            return 0
        if args.command == "verify":
            from .verify import verify_report

            print(
                json.dumps(
                    verify_report(
                        args.directory,
                        expected_sha=args.expected_sha,
                        require_qualified=not args.exploratory,
                        source_root=args.source_root,
                        source_manifest=args.source_manifest,
                    ),
                    indent=2,
                )
            )
            return 0
        if args.command == "qualify":
            from .qualify import main as qualify_main

            return qualify_main(args)
        if args.harness != "omp":
            return _run_harness(args)
        if args.harness_cli or args.harness_model:
            raise ValueError("--harness-cli and --harness-model need --harness claude-code, codex or cursor")
        if args.native_luna_route:
            if args.provider_url or args.model or args.provider_identity or args.allow_loopback_provider:
                raise ValueError("--native-luna-route selects the provider, model, identity and loopback itself")
            from .luna_route import DEFAULT_EFFORT, EFFORTS

            args.reasoning_effort = args.reasoning_effort or DEFAULT_EFFORT
            if args.reasoning_effort not in EFFORTS:
                raise ValueError("--native-luna-route supports Luna " + " or ".join(EFFORTS))
        elif not args.provider_url or not args.model or not args.provider_identity:
            raise ValueError("live provider URL, model and provider identity are required; there is no mock fallback")
        if not 30 <= args.timeout <= 1800 or not 1 <= args.max_inference_rounds <= 128:
            raise ValueError("host timeout or inference-round budget is outside supported bounds")
        # argparse does not apply choices to an environment-supplied default.
        if args.reasoning_effort is not None and args.reasoning_effort not in REASONING_EFFORTS:
            raise ValueError("unsupported reasoning effort; use " + ", ".join(REASONING_EFFORTS))
        from .parallel import MAX_SLOTS, validate_jobs

        validate_jobs(args.jobs)
        if args.profile == "contained-bun-vitest" and args.jobs != 1:
            raise ValueError("--jobs is only supported by the core profile")
        if args.profile == "core" and args.contained_test_project is not None:
            raise ValueError("--contained-test-project requires --profile contained-bun-vitest")
        if args.profile == "contained-bun-vitest" and args.contained_test_project is None:
            raise ValueError("--profile contained-bun-vitest requires --contained-test-project")
        if args.profile == "contained-bun-vitest" and args.cases:
            raise ValueError("--case is only supported by the core profile")
        if args.profile == "contained-bun-vitest" and (
            args.fail_fast or args.host_slots is not None or args.max_load is not None
        ):
            raise ValueError("--fail-fast, --host-slots and --max-load are only supported by the core profile")
        if args.slot_dir is not None and args.host_slots is None:
            raise ValueError("--slot-dir requires --host-slots")
        if args.host_slots is not None and not 1 <= args.host_slots <= MAX_SLOTS:
            raise ValueError(f"--host-slots must be an integer from 1 to {MAX_SLOTS}")
        if args.host_slots is not None and os.name == "nt":
            raise ValueError("--host-slots requires a POSIX host")
        if args.max_load is not None and not (math.isfinite(args.max_load) and args.max_load > 0):
            raise ValueError("--max-load must be a positive finite number")
        if args.max_load is not None and os.name == "nt":
            raise ValueError("--max-load requires a POSIX host")
        if args.max_load_wait is not None and not (math.isfinite(args.max_load_wait) and args.max_load_wait >= 0):
            raise ValueError("--max-load-wait must be a finite number >= 0")
        if args.max_load_wait is not None and args.max_load is None:
            raise ValueError("--max-load-wait requires --max-load")
        api_key = os.environ.pop(args.api_key_env, None)
        if not api_key and not args.allow_loopback_provider and not args.native_luna_route:
            raise ValueError("configure a dedicated inference API key; missing inference cannot pass")
        from .contained import run_contained_profile
        from .runner import run_suite

        with contextlib.ExitStack() as stack:
            if args.native_luna_route:
                from .luna_route import NativeLunaRoute

                # Unwind the context manager on SIGTERM/SIGHUP so the adapter is always reaped.
                for name in (signal.SIGTERM, getattr(signal, "SIGHUP", None)):
                    if name is None:
                        continue
                    signal.signal(name, lambda number, _frame: sys.exit(128 + number))

                route = stack.enter_context(
                    NativeLunaRoute(omp=args.omp, sdk_root=args.sdk_root, effort=args.reasoning_effort)
                )
                provider = route.provider(max_rounds=args.max_inference_rounds, timeout=min(args.timeout, 120))
            else:
                provider = {
                    "base_url": args.provider_url,
                    "model": args.model,
                    "api_key": api_key,
                    "identity": args.provider_identity,
                    "allow_loopback": args.allow_loopback_provider,
                    "max_rounds": args.max_inference_rounds,
                    "timeout": min(args.timeout, 120),
                    "reasoning_effort": args.reasoning_effort,
                }
            if args.profile == "contained-bun-vitest":
                report = run_contained_profile(
                    expected_source_sha=args.expected_source_sha,
                    output=args.output,
                    provider=provider,
                    test_project=args.contained_test_project,
                    model_timeout=args.timeout,
                    omp=args.omp,
                    work_root=args.work_root,
                    candidate_sha=args.candidate_sha,
                )
            else:
                report = run_suite(
                    expected_source_sha=args.expected_source_sha,
                    output=args.output,
                    provider=provider,
                    model_timeout=args.timeout,
                    selected_ids=args.cases,
                    omp=args.omp,
                    work_root=args.work_root,
                    candidate_sha=args.candidate_sha,
                    jobs=args.jobs,
                    fail_fast=args.fail_fast,
                    host_slots=args.host_slots,
                    slot_dir=args.slot_dir,
                    max_load=args.max_load,
                    max_load_wait=args.max_load_wait if args.max_load_wait is not None else 180.0,
                )
        print(
            json.dumps(
                {
                    "pass": report["pass"],
                    "merge_qualified": report["merge_qualified"],
                    "scenarios": len(report["cases"]),
                    "profile": report.get("profile", "core"),
                    "evidence": str(args.output),
                }
            )
        )
        return 0 if report["pass"] else 1
    except (ValueError, RuntimeError, OSError) as exc:
        print(json.dumps({"pass": False, "error_type": type(exc).__name__, "error": str(exc)}), file=sys.stderr)
        return 2


def _run_harness(args: argparse.Namespace) -> int:
    """Drive a non-omp agent CLI; inference goes through that CLI's own login."""
    if (
        args.native_luna_route
        or args.provider_url
        or args.provider_identity
        or args.allow_loopback_provider
        or args.model
        or args.reasoning_effort
        or args.omp
    ):
        raise ValueError("--harness uses the CLI's own login and model; omit provider, Luna and omp options")
    if args.fail_fast or args.host_slots is not None or args.slot_dir is not None or args.max_load is not None:
        raise ValueError("--fail-fast, --host-slots and --max-load are only supported by the omp harness")
    if args.profile != "core":
        raise ValueError("--harness supports only the core profile")
    if not 30 <= args.timeout <= 1800:
        raise ValueError("host timeout is outside supported bounds")
    from .harness_suite import run_harness_suite

    report = run_harness_suite(
        harness=args.harness,
        expected_source_sha=args.expected_source_sha,
        output=args.output,
        model_timeout=args.timeout,
        selected_ids=args.cases,
        executable=args.harness_cli,
        model=args.harness_model,
        work_root=args.work_root,
        candidate_sha=args.candidate_sha,
        jobs=args.jobs,
    )
    print(
        json.dumps(
            {
                "harness": args.harness,
                "pass": report["pass"],
                "merge_qualified": False,
                "scenarios": len(report["cases"]),
                "outcomes": report["outcomes"],
                "evidence": str(args.output),
            }
        )
    )
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
