#!/usr/bin/env python3
"""Release-gate benchmark for Python hook workers versus the Rust runtime.

Only aggregate synthetic measurements are emitted. No user commands, file
contents, secrets, or machine paths are included in benchmark output.

The warm comparison measures two already-resident IPC paths. It accepts either
the absolute latency ceiling or a material improvement over the pinned Python
baseline, matching the release acceptance contract.
The cold comparison measures the process topology that the native runtime is
intended to replace and therefore retains the stronger relative-speedup gate.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.native_policy_test_support import native_policy_snapshot
from codex_plugin_scanner.guard.native_runtime import (
    native_runtime_status,
    review_post_tool_native,
)
from codex_plugin_scanner.guard.native_runtime_resident import close_resident_native_runtimes
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MIN_WARM_P95_SPEEDUP = 1.15
_MAX_WARM_P95_MS = 20.0
_MIN_COLD_P95_SPEEDUP = 5.0
_MAX_COLD_P95_MS = 100.0
_MAX_NATIVE_READINESS_MS = 250.0


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


def _payload() -> dict[str, object]:
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/example.ts"},
        "tool_response": [{"type": "text", "text": "export const value = 1;\n" * 40}],
    }


def _request(*, workspace: Path, guard_home: Path, request_id: str) -> HookReviewRequest:
    return HookReviewRequest(
        harness="claude-code",
        event_name="PostToolUse",
        payload=_payload(),
        payload_kind="inline",
        config_path=None,
        cwd=workspace,
        home_dir=workspace,
        guard_home=guard_home,
        source_scope="project",
        request_id=request_id,
        deadline_monotonic=time.monotonic() + 5.0,
    )


def _wire_request(*, workspace: Path, guard_home: Path) -> str:
    return json.dumps(
        {
            "protocol_version": 1,
            "request_id": "native-benchmark-oneshot",
            "harness": "claude-code",
            "event_name": "PostToolUse",
            "payload": _payload(),
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
    environment = {"HOME": str(workspace), "TMPDIR": tempfile.gettempdir()}
    for key in ("LANG", "LC_ALL"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment


def _python_review(
    runner: HookProcessRunner,
    *,
    workspace: Path,
    guard_home: Path,
) -> None:
    result = runner.review(
        payload=_payload(),
        harness="claude-code",
        home_dir=workspace,
        guard_home=guard_home,
        workspace=workspace,
        hook_env={},
        deadline=time.monotonic() + 5.0,
    )
    if result.payload is None:
        raise RuntimeError(f"Python hook process did not return a decision: {result.reason_code}")


def _bench_python_warm(
    runner: HookProcessRunner,
    *,
    workspace: Path,
    guard_home: Path,
    iterations: int,
) -> list[float]:
    values: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        _python_review(runner, workspace=workspace, guard_home=guard_home)
        values.append((time.perf_counter() - started) * 1_000.0)
    return values


def _bench_native_warm(
    *,
    workspace: Path,
    guard_home: Path,
    iterations: int,
    policy_snapshot: Mapping[str, object],
) -> list[float]:
    values: list[float] = []
    for index in range(iterations):
        request = _request(workspace=workspace, guard_home=guard_home, request_id=f"native-warm-{index}")
        started = time.perf_counter()
        response = review_post_tool_native(request, observe_mode=False, policy_snapshot=policy_snapshot)
        values.append((time.perf_counter() - started) * 1_000.0)
        if response is None or response.decision != "allow":
            raise RuntimeError("Native resident runtime did not return the expected allow decision")
    return values


def _bench_python_cold(*, workspace: Path, guard_home: Path, iterations: int) -> list[float]:
    values: list[float] = []
    for _ in range(iterations):
        runner = HookProcessRunner(guard_home=guard_home, process_limit=1)
        started = time.perf_counter()
        runner.start()
        _python_review(runner, workspace=workspace, guard_home=guard_home)
        values.append((time.perf_counter() - started) * 1_000.0)
        runner.close()
    return values


def _bench_native_oneshot(
    *,
    runtime: Path,
    workspace: Path,
    guard_home: Path,
    iterations: int,
) -> list[float]:
    wire_request = _wire_request(workspace=workspace, guard_home=guard_home)
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
        values.append((time.perf_counter() - started) * 1_000.0)
        if result.returncode != 0 or result.timed_out or result.containment_failed:
            raise RuntimeError("Cold native one-shot runtime failed")
        response = json.loads(result.stdout)
        if response.get("decision") != "allow":
            raise RuntimeError("Cold native one-shot runtime returned an unexpected decision")
    return values


def _speedup(slower_p95: float, faster_p95: float) -> float:
    return round(slower_p95 / max(faster_p95, 0.001), 2)


def _validated_runtime(path: Path) -> Path:
    lexical = path.expanduser()
    if lexical.is_symlink():
        raise ValueError("native runtime must not be a symlink")
    resolved = lexical.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("native runtime must be a regular file")
    _bind_native_runtime(resolved)
    return resolved


def _bind_native_runtime(runtime: Path) -> None:
    os.environ["HOL_GUARD_NATIVE"] = "force"
    os.environ["HOL_GUARD_NATIVE_BINARY"] = str(runtime)


def _readiness_failure(response: object) -> RuntimeError:
    status = native_runtime_status()
    return RuntimeError(
        "Native resident readiness probe failed: "
        f"reason={status.reason} available={status.available} "
        f"compatible={status.compatible} decision={getattr(response, 'decision', None)}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark the Python and Rust hook paths")
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--warm-iterations", type=int, default=100)
    parser.add_argument("--cold-iterations", type=int, default=3)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    if args.warm_iterations < 10 or args.cold_iterations < 2:
        parser.error("benchmark iteration counts are too small")
    runtime = _validated_runtime(args.runtime)
    with tempfile.TemporaryDirectory(prefix="hol-guard-native-bench-") as temp_dir:
        workspace = Path(temp_dir)
        guard_home = workspace / "guard-home"
        guard_home.mkdir(mode=0o700)

        python_runner = HookProcessRunner(guard_home=guard_home, process_limit=1)
        python_runner.start()
        try:
            _python_review(python_runner, workspace=workspace, guard_home=guard_home)
            close_resident_native_runtimes()
            readiness_started = time.perf_counter()
            with native_policy_snapshot(guard_home) as snapshot:
                readiness_response = review_post_tool_native(
                    _request(workspace=workspace, guard_home=guard_home, request_id="native-readiness"),
                    observe_mode=False,
                    policy_snapshot=snapshot,
                )
                native_readiness_ms = (time.perf_counter() - readiness_started) * 1_000.0
                if readiness_response is None or readiness_response.decision != "allow":
                    raise _readiness_failure(readiness_response)
                python_warm = _bench_python_warm(
                    python_runner,
                    workspace=workspace,
                    guard_home=guard_home,
                    iterations=args.warm_iterations,
                )
                native_warm = _bench_native_warm(
                    workspace=workspace,
                    guard_home=guard_home,
                    iterations=args.warm_iterations,
                    policy_snapshot=snapshot,
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
    warm_speedup = _speedup(python_warm_summary["p95_ms"], native_warm_summary["p95_ms"])
    cold_speedup = _speedup(python_cold_summary["p95_ms"], native_oneshot_summary["p95_ms"])
    result = {
        "schema": "hol-guard-native-performance.v1",
        "warm": {
            "python_hook_process": python_warm_summary,
            "native_resident": native_warm_summary,
            "p95_speedup": warm_speedup,
        },
        "cold": {
            "python_hook_process": python_cold_summary,
            "native_oneshot": native_oneshot_summary,
            "p95_speedup": cold_speedup,
        },
        "native_readiness_ms": round(native_readiness_ms, 3),
        "gates": {
            "warm_acceptance": "p95_ms_lte_maximum_or_speedup_gte_minimum",
            "minimum_warm_p95_speedup": _MIN_WARM_P95_SPEEDUP,
            "maximum_warm_p95_ms": _MAX_WARM_P95_MS,
            "minimum_cold_p95_speedup": _MIN_COLD_P95_SPEEDUP,
            "maximum_cold_p95_ms": _MAX_COLD_P95_MS,
            "maximum_native_readiness_ms": _MAX_NATIVE_READINESS_MS,
        },
    }
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")

    if not args.enforce:
        return 0
    failures: list[str] = []
    if warm_speedup < _MIN_WARM_P95_SPEEDUP and native_warm_summary["p95_ms"] > _MAX_WARM_P95_MS:
        failures.append(
            "warm native resident p95 neither meets the "
            f"{_MAX_WARM_P95_MS:.0f}ms ceiling nor improves by "
            f"{_MIN_WARM_P95_SPEEDUP:.2f}x"
        )
    if cold_speedup < _MIN_COLD_P95_SPEEDUP:
        failures.append(f"cold native one-shot p95 speedup is below {_MIN_COLD_P95_SPEEDUP:.0f}x")
    if native_oneshot_summary["p95_ms"] > _MAX_COLD_P95_MS:
        failures.append(f"cold native one-shot p95 exceeds {_MAX_COLD_P95_MS:.0f}ms")
    if native_readiness_ms > _MAX_NATIVE_READINESS_MS:
        failures.append(f"native resident readiness exceeds {_MAX_NATIVE_READINESS_MS:.0f}ms")
    if failures:
        for failure in failures:
            print(f"PERFORMANCE GATE: {failure}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
