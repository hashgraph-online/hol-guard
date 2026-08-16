#!/usr/bin/env python3
"""Compare the existing Python hook-process path with the Rust runtime.

The corpus is synthetic and contains no user commands, secrets, or paths in
reported output. The benchmark records p50/p95/p99/max only.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import tempfile
import time
from pathlib import Path

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.native_runtime import review_post_tool_native
from codex_plugin_scanner.guard.native_runtime_resident import close_resident_native_runtimes
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def _percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(len(ordered) * quantile)))
    return ordered[index]


def _summary(values: list[float]) -> dict[str, float]:
    return {
        "p50_ms": round(statistics.median(values), 3),
        "p95_ms": round(_percentile(values, 0.95), 3),
        "p99_ms": round(_percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }


def _synthetic_payload() -> dict[str, object]:
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/example.ts"},
        "tool_response": [{"type": "text", "text": "export const value = 1;\n" * 40}],
    }


def _native_request(*, workspace: Path, guard_home: Path) -> HookReviewRequest:
    return HookReviewRequest(
        harness="claude-code",
        event_name="PostToolUse",
        payload=_synthetic_payload(),
        payload_kind="inline",
        config_path=None,
        cwd=workspace,
        home_dir=workspace,
        guard_home=guard_home,
        source_scope="project",
        request_id="native-benchmark",
        deadline_monotonic=time.monotonic() + 5.0,
    )


def _native_wire_request(*, workspace: Path, guard_home: Path) -> str:
    return json.dumps(
        {
            "protocol_version": 1,
            "request_id": "native-benchmark-oneshot",
            "harness": "claude-code",
            "event_name": "PostToolUse",
            "payload": _synthetic_payload(),
            "cwd": str(workspace),
            "home_dir": str(workspace),
            "guard_home": str(guard_home),
            "source_ref_external_allowed": False,
            "observe_mode": False,
            "deadline_budget_ms": 5_000,
        },
        separators=(",", ":"),
    )


def _native_environment(workspace: Path) -> dict[str, str]:
    environment = {
        "HOME": str(workspace),
        "TMPDIR": tempfile.gettempdir(),
    }
    for key in ("LANG", "LC_ALL"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment


def _bench_python_warm(
    *,
    runner: HookProcessRunner,
    workspace: Path,
    guard_home: Path,
    iterations: int,
) -> list[float]:
    payload = _synthetic_payload()
    values: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        result = runner.review(
            payload=payload,
            harness="claude-code",
            home_dir=workspace,
            guard_home=guard_home,
            workspace=workspace,
            hook_env={},
            deadline=time.monotonic() + 5.0,
        )
        elapsed = (time.perf_counter() - started) * 1_000.0
        if result.payload is None:
            raise RuntimeError(f"Python hook process did not return a decision: {result.reason_code}")
        values.append(elapsed)
    return values


def _bench_native_warm(
    *,
    workspace: Path,
    guard_home: Path,
    iterations: int,
) -> list[float]:
    values: list[float] = []
    for index in range(iterations):
        request = _native_request(workspace=workspace, guard_home=guard_home)
        request = HookReviewRequest(
            **{
                **request.__dict__,
                "request_id": f"native-warm-{index}",
                "deadline_monotonic": time.monotonic() + 5.0,
            }
        )
        started = time.perf_counter()
        response = review_post_tool_native(request, observe_mode=False)
        elapsed = (time.perf_counter() - started) * 1_000.0
        if response is None or response.decision != "allow":
            raise RuntimeError("Native resident runtime did not return the expected allow decision")
        values.append(elapsed)
    return values


def _bench_python_cold(*, workspace: Path, guard_home: Path, iterations: int) -> list[float]:
    values: list[float] = []
    for _ in range(iterations):
        runner = HookProcessRunner(guard_home=guard_home, process_limit=1)
        started = time.perf_counter()
        runner.start()
        result = runner.review(
            payload=_synthetic_payload(),
            harness="claude-code",
            home_dir=workspace,
            guard_home=guard_home,
            workspace=workspace,
            hook_env={},
            deadline=time.monotonic() + 5.0,
        )
        elapsed = (time.perf_counter() - started) * 1_000.0
        if result.payload is None:
            runner.close()
            raise RuntimeError(f"Cold Python hook process failed: {result.reason_code}")
        values.append(elapsed)
        runner.close()
    return values


def _bench_native_oneshot(
    *,
    runtime: Path,
    workspace: Path,
    guard_home: Path,
    iterations: int,
) -> list[float]:
    wire_request = _native_wire_request(workspace=workspace, guard_home=guard_home)
    environment = _native_environment(workspace)
    values: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        result = run_isolated_hook_process(
            (str(runtime), "hook", "--stdin"),
            input_text=wire_request,
            cwd=runtime.parent,
            environment=environment,
            timeout_seconds=5.0,
            output_limit=_MAX_RESPONSE_BYTES,
        )
        elapsed = (time.perf_counter() - started) * 1_000.0
        if result.returncode != 0 or result.timed_out or result.containment_failed:
            raise RuntimeError("Cold native one-shot runtime failed")
        payload = json.loads(result.stdout)
        if payload.get("decision") != "allow":
            raise RuntimeError("Cold native one-shot runtime returned an unexpected decision")
        values.append(elapsed)
    return values


def _speedup(slower_p95: float, faster_p95: float) -> float:
    return round(slower_p95 / max(faster_p95, 0.001), 2)


def _validate_runtime(path: Path) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError("native runtime must be a regular non-symlink file")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark Python versus Rust full hook paths")
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--warm-iterations", type=int, default=40)
    parser.add_argument("--cold-iterations", type=int, default=3)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    if args.warm_iterations < 10 or args.cold_iterations < 2:
        parser.error("benchmark iteration counts are too small")

    runtime = _validate_runtime(args.runtime)
    with tempfile.TemporaryDirectory(prefix="hol-guard-native-bench-") as temp_dir:
        workspace = Path(temp_dir)
        guard_home = workspace / "guard-home"
        guard_home.mkdir(mode=0o700)

        python_runner = HookProcessRunner(guard_home=guard_home, process_limit=1)
        python_runner.start()
        try:
            _ = _bench_python_warm(
                runner=python_runner,
                workspace=workspace,
                guard_home=guard_home,
                iterations=2,
            )
            close_resident_native_runtimes()
            first_native_started = time.perf_counter()
            first_native = review_post_tool_native(
                _native_request(workspace=workspace, guard_home=guard_home),
                observe_mode=False,
            )
            native_readiness_ms = (time.perf_counter() - first_native_started) * 1_000.0
            if first_native is None or first_native.decision != "allow":
                raise RuntimeError("Native resident runtime readiness probe failed")

            python_warm = _bench_python_warm(
                runner=python_runner,
                workspace=workspace,
                guard_home=guard_home,
                iterations=args.warm_iterations,
            )
            native_warm = _bench_native_warm(
                workspace=workspace,
                guard_home=guard_home,
                iterations=args.warm_iterations,
            )
        finally:
            python_runner.close()
            close_resident_native_runtimes()

        python_cold = _bench_python_cold(
            workspace=workspace,
            guard_home=guard_home,
            iterations=args.cold_iterations,
        )
        native_oneshot = _bench_native_oneshot(
            runtime=runtime,
            workspace=workspace,
            guard_home=guard_home,
            iterations=args.cold_iterations,
        )

    python_warm_summary = _summary(python_warm)
    native_warm_summary = _summary(native_warm)
    python_cold_summary = _summary(python_cold)
    native_oneshot_summary = _summary(native_oneshot)
    result = {
        "schema": "hol-guard-native-performance.v1",
        "warm": {
            "python_hook_process": python_warm_summary,
            "native_resident": native_warm_summary,
            "p95_speedup": _speedup(python_warm_summary["p95_ms"], native_warm_summary["p95_ms"]),
        },
        "cold": {
            "python_hook_process": python_cold_summary,
            "native_oneshot": native_oneshot_summary,
            "p95_speedup": _speedup(python_cold_summary["p95_ms"], native_oneshot_summary["p95_ms"]),
        },
        "native_readiness_ms": round(native_readiness_ms, 3),
    }
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")

    if not args.enforce:
        return 0
    failures: list[str] = []
    if result["warm"]["p95_speedup"] < 3.0:
        failures.append("warm native resident p95 speedup is below 3x")
    if native_warm_summary["p95_ms"] > 20.0:
        failures.append("warm native resident p95 exceeds 20ms")
    if result["cold"]["p95_speedup"] < 5.0:
        failures.append("cold native one-shot p95 speedup is below 5x")
    if native_oneshot_summary["p95_ms"] > 100.0:
        failures.append("cold native one-shot p95 exceeds 100ms")
    if native_readiness_ms > 250.0:
        failures.append("native resident readiness exceeds 250ms")
    if failures:
        for failure in failures:
            print(f"PERFORMANCE GATE: {failure}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
