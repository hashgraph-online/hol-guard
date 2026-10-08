"""Command-line entry point for real-agent acceptance and evidence verification."""

from __future__ import annotations

import argparse
import contextlib
import json
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
        help="Run OpenAI Luna high (openai-codex/gpt-5.6-luna) through the existing Oh My Pi ChatGPT login",
    )
    run.add_argument("--sdk-root", type=Path, help="Pinned SDK directory for --native-luna-route (default: from omp)")
    run.add_argument("--case", action="append", dest="cases", help="Targeted runs are never full-profile qualification")
    run.add_argument("--timeout", type=float, default=300, help="Per-scenario host deadline in seconds")
    run.add_argument("--max-inference-rounds", type=int, default=32)
    run.add_argument("--omp", help="Path to the repository-pinned Oh My Pi executable")
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
        if args.native_luna_route:
            if args.provider_url or args.model or args.provider_identity or args.allow_loopback_provider:
                raise ValueError("--native-luna-route selects the provider, model, identity and loopback itself")
            if args.reasoning_effort not in (None, "high"):
                raise ValueError("--native-luna-route is Luna high only")
        elif not args.provider_url or not args.model or not args.provider_identity:
            raise ValueError("live provider URL, model and provider identity are required; there is no mock fallback")
        if not 30 <= args.timeout <= 1800 or not 1 <= args.max_inference_rounds <= 128:
            raise ValueError("host timeout or inference-round budget is outside supported bounds")
        # argparse does not apply choices to an environment-supplied default.
        if args.reasoning_effort is not None and args.reasoning_effort not in REASONING_EFFORTS:
            raise ValueError("unsupported reasoning effort; use " + ", ".join(REASONING_EFFORTS))
        if args.profile == "core" and args.contained_test_project is not None:
            raise ValueError("--contained-test-project requires --profile contained-bun-vitest")
        if args.profile == "contained-bun-vitest" and args.contained_test_project is None:
            raise ValueError("--profile contained-bun-vitest requires --contained-test-project")
        if args.profile == "contained-bun-vitest" and args.cases:
            raise ValueError("--case is only supported by the core profile")
        api_key = os.environ.pop(args.api_key_env, None)
        if not api_key and not args.allow_loopback_provider and not args.native_luna_route:
            raise ValueError("configure a dedicated inference API key; missing inference cannot pass")
        from .contained import run_contained_profile
        from .runner import run_suite

        with contextlib.ExitStack() as stack:
            if args.native_luna_route:
                from .luna_route import NativeLunaRoute

                # Unwind the context manager on SIGTERM/SIGHUP so the adapter is always reaped.
                for name in (signal.SIGTERM, signal.SIGHUP):
                    signal.signal(name, lambda number, _frame: sys.exit(128 + number))

                route = stack.enter_context(NativeLunaRoute(omp=args.omp, sdk_root=args.sdk_root))
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


if __name__ == "__main__":
    raise SystemExit(main())
