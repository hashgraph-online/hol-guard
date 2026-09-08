#!/usr/bin/env python3
"""Release-gate benchmark for Python hook workers versus the Rust runtime.

Only aggregate synthetic measurements are emitted; benchmark output excludes
user commands, file contents, secrets, and machine paths.

The enforced warm comparison measures the production adapter-to-decision path
against a persistent Python worker; direct resident IPC is also reported as a diagnostic.
The Python reference disables native authority and varies synthetic samples to avoid cache distortion.
Relative speed remains informative because trivial allow payloads can favor Python, while release acceptance follows
the contract: native p95 must stay below the absolute ceiling or materially improve over the pinned Python
reference. Cold comparison retains the stronger relative-speedup gate.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.native_policy_test_support import native_policy_snapshot
from codex_plugin_scanner.guard.native_route_receipt import native_hook_route, reset_native_hook_route
from codex_plugin_scanner.guard.native_runtime import (
    native_runtime_status,
    review_post_tool_native,
)
from codex_plugin_scanner.guard.native_runtime_resident import close_resident_native_runtimes, resident_native_request
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MIN_WARM_P95_SPEEDUP = 1.15
_MAX_WARM_P95_MS = 20.0
_MIN_COLD_P95_SPEEDUP = 5.0
_MAX_COLD_P95_MS = 100.0
_MAX_NATIVE_READINESS_MS = 250.0


@contextmanager
def _python_reference_mode() -> Iterator[None]:
    previous = os.environ.get("HOL_GUARD_NATIVE")
    os.environ["HOL_GUARD_NATIVE"] = "off"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("HOL_GUARD_NATIVE", None)
        else:
            os.environ["HOL_GUARD_NATIVE"] = previous


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


def _payload(sample: int | None = None) -> dict[str, object]:
    sample_marker = "" if sample is None else f"// benchmark sample {sample}\n"
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/example.ts"},
        "tool_response": [{"type": "text", "text": ("export const value = 1;\n" * 40) + sample_marker}],
    }


def _request(
    *,
    workspace: Path,
    guard_home: Path,
    request_id: str,
    sample: int | None = None,
) -> HookReviewRequest:
    return HookReviewRequest(
        harness="claude-code",
        event_name="PostToolUse",
        payload=_payload(sample),
        payload_kind="inline",
        config_path=None,
        cwd=workspace,
        home_dir=workspace,
        guard_home=guard_home,
        source_scope="project",
        request_id=request_id,
        deadline_monotonic=time.monotonic() + 5.0,
    )


def _wire_request(
    *,
    workspace: Path,
    guard_home: Path,
    request_id: str = "native-benchmark-oneshot",
    sample: int | None = None,
) -> str:
    return json.dumps(
        {
            "protocol_version": 1,
            "request_id": request_id,
            "harness": "claude-code",
            "event_name": "PostToolUse",
            "payload": _payload(sample),
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


def _stop_native_resident(runtime: Path, state_dir: Path, workspace: Path) -> None:
    state_files = list(state_dir.glob("resident-v3-*/generation-*.json"))
    if not state_files:
        return
    result = run_isolated_hook_process(
        (str(runtime), "resident-stop", "--state-dir", str(state_dir)),
        input_text="",
        cwd=runtime.parent,
        environment=_native_environment(workspace),
        timeout_seconds=3.0,
        output_limit=_MAX_RESPONSE_BYTES,
    )
    if result.returncode != 0 or result.timed_out or result.containment_failed:
        raise RuntimeError("Native resident teardown failed")
    if list(state_dir.glob("resident-v3-*/generation-*.json")):
        raise RuntimeError("Native resident teardown left state behind")


def _python_review(
    runner: HookProcessRunner,
    *,
    workspace: Path,
    guard_home: Path,
    sample: int | None = None,
) -> None:
    result = runner.review(
        payload=_payload(sample),
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
    for index in range(iterations):
        started = time.perf_counter()
        _python_review(runner, workspace=workspace, guard_home=guard_home, sample=index)
        values.append((time.perf_counter() - started) * 1_000.0)
    return values


def _bench_python_warm_reference(*, workspace: Path, guard_home: Path, iterations: int) -> list[float]:
    with _python_reference_mode():
        runner = HookProcessRunner(guard_home=guard_home, process_limit=1)
        runner.start()
        try:
            _python_review(runner, workspace=workspace, guard_home=guard_home)
            return _bench_python_warm(
                runner,
                workspace=workspace,
                guard_home=guard_home,
                iterations=iterations,
            )
        finally:
            runner.close()


def _bench_native_warm(
    *,
    workspace: Path,
    guard_home: Path,
    iterations: int,
) -> list[float]:
    """Measure direct authenticated resident IPC as a diagnostic."""
    status = native_runtime_status()
    if status.identity is None:
        raise RuntimeError("Native resident runtime identity is unavailable")
    values: list[float] = []
    for index in range(iterations):
        request = _wire_request(
            workspace=workspace,
            guard_home=guard_home,
            request_id=f"native-warm-{index}",
            sample=index,
        )
        started = time.perf_counter()
        response_bytes = resident_native_request(
            executable=status.identity.path,
            identity_sha256=status.identity.sha256,
            guard_home=guard_home,
            environment=_native_environment(workspace),
            payload=request.encode("utf-8"),
            timeout_seconds=5.0,
        )
        values.append((time.perf_counter() - started) * 1_000.0)
        if response_bytes is None:
            raise RuntimeError("Native resident IPC request failed")
        response = json.loads(response_bytes)
        if response.get("decision") != "allow":
            raise RuntimeError(
                "Native resident runtime did not return the expected allow decision: "
                f"sample={index} response={response!r}"
            )
    return values


def _bench_native_warm_production(
    *,
    workspace: Path,
    guard_home: Path,
    iterations: int,
    policy_snapshot: Mapping[str, object] | None = None,
) -> list[float]:
    """Measure the production adapter-to-decision route over a warm resident."""
    values: list[float] = []
    for index in range(iterations):
        reset_native_hook_route()
        request = _request(
            workspace=workspace,
            guard_home=guard_home,
            request_id=f"native-production-warm-{index}",
            sample=index,
        )
        started = time.perf_counter()
        if policy_snapshot is None:
            response = review_post_tool_native(request, observe_mode=False, policy_snapshot=None)
        else:
            response = review_post_tool_native(
                request,
                observe_mode=False,
                policy_snapshot=policy_snapshot,
            )
        values.append((time.perf_counter() - started) * 1_000.0)
        if native_hook_route() != "native_resident":
            raise RuntimeError(
                "Native production warm benchmark did not use the authenticated resident route: "
                f"sample={index} route={native_hook_route()!r}"
            )
        if response is None or response.decision != "allow":
            raise RuntimeError(
                "Native production warm benchmark returned an unexpected decision: "
                f"sample={index} reason_code={getattr(response, 'reason_code', None)}"
            )
    return values


def _bench_python_cold(*, workspace: Path, guard_home: Path, iterations: int) -> list[float]:
    values: list[float] = []
    with _python_reference_mode():
        for _ in range(iterations):
            runner = HookProcessRunner(guard_home=guard_home, process_limit=1)
            started = time.perf_counter()
            runner.start()
            try:
                _python_review(runner, workspace=workspace, guard_home=guard_home)
                values.append((time.perf_counter() - started) * 1_000.0)
            finally:
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


def _run_benchmarks(
    *, runtime: Path, warm_iterations: int, cold_iterations: int
) -> tuple[list[float], list[float], list[float], list[float], list[float], float]:
    short_temp_root = "/tmp" if os.name != "nt" and Path("/tmp").is_dir() else None
    with tempfile.TemporaryDirectory(prefix="hg-native-bench-", dir=short_temp_root) as temp_dir:
        workspace = Path(temp_dir)
        guard_home = workspace / "guard-home"
        guard_home.mkdir(mode=0o700)

        python_warm = _bench_python_warm_reference(
            workspace=workspace,
            guard_home=guard_home,
            iterations=warm_iterations,
        )

        close_resident_native_runtimes()
        try:
            with native_policy_snapshot(guard_home) as snapshot:
                reset_native_hook_route()
                # Snapshot materialization is durable policy bookkeeping, not resident readiness.
                # Start the gate when the production adapter begins its first authenticated request.
                readiness_started = time.perf_counter()
                readiness_response = review_post_tool_native(
                    _request(workspace=workspace, guard_home=guard_home, request_id="native-readiness"),
                    observe_mode=False,
                    policy_snapshot=snapshot,
                )
                native_readiness_ms = (time.perf_counter() - readiness_started) * 1_000.0
                if (
                    readiness_response is None
                    or readiness_response.decision != "allow"
                    or native_hook_route() != "native_resident"
                ):
                    raise _readiness_failure(readiness_response)
                native_warm = _bench_native_warm_production(
                    workspace=workspace,
                    guard_home=guard_home,
                    iterations=warm_iterations,
                    policy_snapshot=snapshot,
                )
                native_warm_ipc = _bench_native_warm(
                    workspace=workspace,
                    guard_home=guard_home,
                    iterations=warm_iterations,
                )
        finally:
            _stop_native_resident(runtime, guard_home / "native-runtime", workspace)
            close_resident_native_runtimes()

        python_cold = _bench_python_cold(
            workspace=workspace,
            guard_home=guard_home,
            iterations=cold_iterations,
        )
        native_oneshot = _bench_native_oneshot(
            runtime=runtime,
            workspace=workspace,
            guard_home=guard_home,
            iterations=cold_iterations,
        )
    return python_warm, native_warm, native_warm_ipc, python_cold, native_oneshot, native_readiness_ms


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
    python_warm, native_warm, native_warm_ipc, python_cold, native_oneshot, native_readiness_ms = _run_benchmarks(
        runtime=runtime,
        warm_iterations=args.warm_iterations,
        cold_iterations=args.cold_iterations,
    )
    python_warm_summary = _summary(python_warm)
    native_warm_summary = _summary(native_warm)
    native_warm_ipc_summary = _summary(native_warm_ipc)
    python_cold_summary = _summary(python_cold)
    native_oneshot_summary = _summary(native_oneshot)
    warm_speedup = _speedup(python_warm_summary["p95_ms"], native_warm_summary["p95_ms"])
    cold_speedup = _speedup(python_cold_summary["p95_ms"], native_oneshot_summary["p95_ms"])
    result = {
        "schema": "hol-guard-native-performance.v1",
        "warm": {
            "python_hook_process": python_warm_summary,
            "native_resident": native_warm_summary,
            "native_resident_ipc_diagnostic": native_warm_ipc_summary,
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
            print(f"PERFORMANCE GATE: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
