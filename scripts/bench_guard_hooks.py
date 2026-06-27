#!/usr/bin/env python3
"""Benchmark script for HOL Guard fast hook review.

Measures p50/p95/p99 latency for various hook review cases.
Never prints raw secret fixture values.

Usage:
    python scripts/bench_guard_hooks.py \\
        --harness pi \\
        --daemon warm \\
        --cases small-post,read-ts-250kb,read-md-1mb,secret-early \\
        --iterations 50 \\
        --json .artifacts/hook-bench-pi-warm.json

Threshold mode:
    python scripts/bench_guard_hooks.py \\
        --harness pi \\
        --daemon warm \\
        --cases small-post,read-ts-250kb \\
        --fail-p95 small-post=75ms,read-ts-250kb=200ms
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

# Ensure the package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.hook_content_scanner import ContentScanner
from codex_plugin_scanner.guard.runtime.hook_decision_cache import HookDecisionCache
from codex_plugin_scanner.guard.runtime.hook_review_engine import HookReviewEngine
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest, HookSourceFileRef, HookOutputSummary
from codex_plugin_scanner.guard.runtime.hook_source_read import sha256_text
from codex_plugin_scanner.guard.store import GuardStore


def _create_workspace(tmp: Path) -> Path:
    ws = tmp / "workspace"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "src").mkdir(exist_ok=True)
    (ws / "docs").mkdir(exist_ok=True)
    return ws


def _make_source_ref(path: str, text: str) -> HookSourceFileRef:
    stripped = text.rstrip("\n")
    return HookSourceFileRef(
        version=1,
        path=path,
        output_sha256=sha256_text(stripped),
        output_chars=len(stripped),
        tool_input_path=path,
    )


def _make_request(
    *,
    harness: str,
    event_name: str,
    cwd: Path,
    home_dir: Path,
    guard_home: Path,
    source_ref: HookSourceFileRef | None = None,
    output_summary: HookOutputSummary | None = None,
) -> HookReviewRequest:
    payload: dict[str, object] = {
        "hook_event_name": event_name,
        "tool_name": "Read",
    }
    if source_ref is not None:
        payload["tool_input"] = {"file_path": source_ref.path}
        payload["guard_source_ref"] = {
            "version": source_ref.version,
            "path": source_ref.path,
            "output_sha256": source_ref.output_sha256,
            "output_chars": source_ref.output_chars,
            "tool_input_path": source_ref.tool_input_path,
        }
    return HookReviewRequest(
        harness=harness,
        event_name=event_name,
        payload=payload,
        payload_kind="source_file_ref" if source_ref else "inline",
        config_path=None,
        cwd=cwd,
        home_dir=home_dir,
        guard_home=guard_home,
        source_scope="project",
        source_ref=source_ref,
        output_summary=output_summary,
    )


def _bench_case(
    name: str,
    engine: HookReviewEngine,
    request: HookReviewRequest,
    iterations: int,
) -> dict[str, object]:
    latencies: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        engine.review(request)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        latencies.append(elapsed_ms)

    latencies.sort()
    p50 = statistics.median(latencies)
    p95 = latencies[int(len(latencies) * 0.95)] if len(latencies) > 1 else latencies[0]
    p99 = latencies[int(len(latencies) * 0.99)] if len(latencies) > 1 else latencies[0]

    return {
        "case": name,
        "iterations": iterations,
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
        "p99_ms": round(p99, 2),
        "min_ms": round(min(latencies), 2),
        "max_ms": round(max(latencies), 2),
    }


def _setup_cases(tmp: Path, workspace: Path) -> dict[str, HookReviewRequest]:
    """Create benchmark fixtures. Never stores raw secret values in output."""
    home_dir = tmp / "home"
    home_dir.mkdir(exist_ok=True)
    guard_home = tmp / "guard-home"
    guard_home.mkdir(exist_ok=True)

    cases: dict[str, HookReviewRequest] = {}

    # small-post: 1KB output
    small_content = "export const x = 1;\n" * 50
    small_file = workspace / "src" / "small.ts"
    small_file.write_text(small_content)
    cases["small-post"] = _make_request(
        harness="pi",
        event_name="PostToolUse",
        cwd=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        source_ref=_make_source_ref("src/small.ts", small_content),
    )

    # read-ts-250kb: 250KB TypeScript file
    ts_content = "// TypeScript source file\n" + "const x = 1;\n" * 12000
    ts_file = workspace / "src" / "large.ts"
    ts_file.write_text(ts_content)
    cases["read-ts-250kb"] = _make_request(
        harness="pi",
        event_name="PostToolUse",
        cwd=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        source_ref=_make_source_ref("src/large.ts", ts_content),
    )

    # read-md-1mb: 1MB Markdown file
    md_content = "# Markdown spec\n\n" + "Paragraph text here.\n\n" * 50000
    md_file = workspace / "docs" / "spec.md"
    md_file.write_text(md_content)
    cases["read-md-1mb"] = _make_request(
        harness="pi",
        event_name="PostToolUse",
        cwd=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        source_ref=_make_source_ref("docs/spec.md", md_content),
    )

    # secret-early: secret at byte ~100
    secret_content = 'x = 1;\nconst token = "FAKE_BENCH_TOKEN_NOT_REAL";\n' + "y = 2;\n" * 100
    secret_file = workspace / "src" / "secret.ts"
    secret_file.write_text(secret_content)
    cases["secret-early"] = _make_request(
        harness="pi",
        event_name="PostToolUse",
        cwd=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        source_ref=_make_source_ref("src/secret.ts", secret_content),
    )

    # stdout-1mb: arbitrary stdout (no source ref, just excerpt)
    stdout_content = "line of output\n" * 60000
    cases["stdout-1mb"] = _make_request(
        harness="pi",
        event_name="PostToolUse",
        cwd=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        source_ref=None,
        output_summary=HookOutputSummary(
            text_excerpt=stdout_content[:12000],
            excerpt_truncated=True,
            output_sha256=sha256_text(stdout_content),
            output_chars=len(stdout_content),
        ),
    )

    # adversarial-json-1mb: large JSON payload
    adv_content = '{"key": "value", "items": [' + ", ".join(['"item"'] * 50000) + "]}\n"
    adv_file = workspace / "src" / "data.json"
    adv_file.write_text(adv_content)
    cases["adversarial-json-1mb"] = _make_request(
        harness="pi",
        event_name="PostToolUse",
        cwd=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        source_ref=_make_source_ref("src/data.json", adv_content),
    )

    return cases


def _parse_thresholds(threshold_str: str) -> dict[str, float]:
    """Parse 'case=75ms,other=200ms' into {'case': 75.0, 'other': 200.0}."""
    thresholds: dict[str, float] = {}
    for part in threshold_str.split(","):
        part = part.strip()
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        value = value.strip().rstrip("ms").strip()
        try:
            thresholds[name] = float(value)
        except ValueError:
            pass
    return thresholds


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark HOL Guard fast hook review")
    parser.add_argument("--harness", default="pi", help="Harness name")
    parser.add_argument("--daemon", default="warm", help="Daemon state (warm/cold)")
    parser.add_argument("--cases", default="small-post,read-ts-250kb,read-md-1mb,secret-early", help="Comma-separated case names")
    parser.add_argument("--iterations", type=int, default=50, help="Iterations per case")
    parser.add_argument("--json", default=None, help="Output JSON file path")
    parser.add_argument("--fail-p95", default=None, help="Threshold mode: case=p95ms,...")
    args = parser.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="hol-guard-bench-"))
    workspace = _create_workspace(tmp)
    store = GuardStore(tmp / "guard-home")
    scanner = ContentScanner()
    cache = HookDecisionCache(store)

    def config_loader(guard_home: Path, ws: Path | None) -> GuardConfig:
        return GuardConfig(guard_home=guard_home, workspace=ws)

    engine = HookReviewEngine(
        store=store,
        scanner=scanner,
        cache=cache,
        config_loader=config_loader,
    )

    all_cases = _setup_cases(tmp, workspace)
    requested = [c.strip() for c in args.cases.split(",") if c.strip()]
    thresholds = _parse_thresholds(args.fail_p95) if args.fail_p95 else {}

    results: list[dict[str, object]] = []
    failed: list[str] = []

    for case_name in requested:
        if case_name not in all_cases:
            print(f"  UNKNOWN: {case_name}", file=sys.stderr)
            continue

        # Warm up
        engine.review(all_cases[case_name])

        result = _bench_case(case_name, engine, all_cases[case_name], args.iterations)
        results.append(result)

        print(f"  {case_name}: p50={result['p50_ms']}ms p95={result['p95_ms']}ms p99={result['p99_ms']}ms")

        if case_name in thresholds:
            if result["p95_ms"] > thresholds[case_name]:
                failed.append(f"{case_name}: p95={result['p95_ms']}ms > {thresholds[case_name]}ms")

    if args.json:
        output_path = Path(args.json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(
                {
                    "harness": args.harness,
                    "daemon": args.daemon,
                    "iterations": args.iterations,
                    "results": results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\n  JSON output: {output_path}")

    if failed:
        print("\n  THRESHOLD FAILURES:", file=sys.stderr)
        for f in failed:
            print(f"    {f}", file=sys.stderr)
        return 1

    if thresholds:
        print("\n  All thresholds passed.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
