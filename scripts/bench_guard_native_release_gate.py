#!/usr/bin/env python3
"""Release-gate benchmark for Python hook workers versus the Rust runtime.

Only aggregate synthetic measurements are emitted. No user commands, file
contents, secrets, or machine paths are included in benchmark output.

The warm comparison measures two already-resident IPC paths. The Python
reference explicitly disables native authority and varies synthetic samples to
avoid cache distortion. Relative speed remains informative because trivial
allow payloads can be faster in Python, while release acceptance follows the
contract: native p95 must either stay below the absolute ceiling or materially
improve over the pinned Python reference. The cold comparison measures the
process topology that the native runtime is intended to replace and therefore
retains the stronger relative-speedup gate.
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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process  # noqa: E402
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner  # noqa: E402
from codex_plugin_scanner.guard.native_policy_test_support import native_policy_snapshot  # noqa: E402
from codex_plugin_scanner.guard.native_runtime import (  # noqa: E402
    native_runtime_status,
    review_post_tool_native,
)
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest  # noqa: E402
from scripts import native_release_reporting as _native_release_reporting  # noqa: E402
from scripts.native_slo_session import stop_native_resident  # noqa: E402

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_DIRECT_CONCURRENCY = _native_release_reporting.DIRECT_CONCURRENCY
_build_result = _native_release_reporting.build_result
_measurement_summaries = _native_release_reporting.measurement_summaries
_performance_failures = _native_release_reporting.performance_failures


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

def _bench_native_warm(
    *,
    workspace: Path,
    guard_home: Path,
    iterations: int,
    policy_snapshot: Mapping[str, object],
) -> list[float]:
    values: list[float] = []
    for index in range(iterations):
        request = _request(
            workspace=workspace,
            guard_home=guard_home,
            request_id=f"native-warm-{index}",
            sample=index,
        )
        started = time.perf_counter()
        response = review_post_tool_native(request, observe_mode=False, policy_snapshot=policy_snapshot)
        values.append((time.perf_counter() - started) * 1_000.0)
        if response is None or response.decision != "allow":
            raise RuntimeError(
                "Native resident runtime did not return the expected allow decision: "
                f"sample={index} reason_code={getattr(response, 'reason_code', None)} "
                f"reason={getattr(response, 'reason', None)}"
            )
    return values


def _bench_native_concurrent(
    *,
    workspace: Path,
    guard_home: Path,
    policy_snapshot: Mapping[str, object],
) -> tuple[list[float], int]:
    """Measure direct resident native c16 latency and completed-call errors."""

    def review(index: int) -> float:
        request = _request(workspace=workspace, guard_home=guard_home, request_id=f"native-concurrent-{index}")
        started = time.perf_counter()
        response = review_post_tool_native(request, observe_mode=False, policy_snapshot=policy_snapshot)
        elapsed_ms = (time.perf_counter() - started) * 1_000.0
        if response is None or response.decision != "allow":
            raise RuntimeError("Direct native concurrent runtime returned an unexpected decision")
        return elapsed_ms

    values: list[float] = []
    errors = 0
    with ThreadPoolExecutor(max_workers=_DIRECT_CONCURRENCY) as executor:
        futures = [executor.submit(review, index) for index in range(_DIRECT_CONCURRENCY)]
        for future in futures:
            try:
                values.append(future.result(timeout=5))
            except Exception:
                errors += 1
    return values, errors


def _prewarm_native_concurrent(
    *,
    workspace: Path,
    guard_home: Path,
    policy_snapshot: Mapping[str, object],
) -> None:
    """Start every resident stream before collecting the direct c16 sample."""

    values, errors = _bench_native_concurrent(
        workspace=workspace,
        guard_home=guard_home,
        policy_snapshot=policy_snapshot,
    )
    if errors or len(values) != _DIRECT_CONCURRENCY:
        raise RuntimeError("Native resident concurrency prewarm did not fill the client pool")


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


def _collect_measurements(
    runtime: Path,
    *,
    warm_iterations: int,
    cold_iterations: int,
) -> tuple[
    list[float],
    list[float],
    list[float],
    list[float],
    float,
    list[float],
    int,
]:
    with tempfile.TemporaryDirectory(prefix="hol-guard-native-bench-") as temp_dir:
        workspace = Path(temp_dir)
        guard_home = workspace / "guard-home"
        guard_home.mkdir(mode=0o700)
        python_runner = HookProcessRunner(guard_home=guard_home, process_limit=1)
        python_runner.start()
        try:
            _python_review(python_runner, workspace=workspace, guard_home=guard_home)
            stop_native_resident(runtime, guard_home)
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
                    iterations=warm_iterations,
                )
                native_warm = _bench_native_warm(
                    workspace=workspace,
                    guard_home=guard_home,
                    iterations=warm_iterations,
                    policy_snapshot=snapshot,
                )
                _prewarm_native_concurrent(
                    workspace=workspace,
                    guard_home=guard_home,
                    policy_snapshot=snapshot,
                )
                native_concurrent, native_concurrent_errors = _bench_native_concurrent(
                    workspace=workspace,
                    guard_home=guard_home,
                    policy_snapshot=snapshot,
                )
        finally:
            python_runner.close()
            stop_native_resident(runtime, guard_home)
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
    return (
        python_warm,
        native_warm,
        python_cold,
        native_oneshot,
        native_readiness_ms,
        native_concurrent,
        native_concurrent_errors,
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
    (
        python_warm,
        native_warm,
        python_cold,
        native_oneshot,
        native_readiness_ms,
        native_concurrent,
        native_concurrent_errors,
    ) = _collect_measurements(
        runtime,
        warm_iterations=args.warm_iterations,
        cold_iterations=args.cold_iterations,
    )

    (
        python_warm_summary,
        native_warm_summary,
        python_cold_summary,
        native_oneshot_summary,
        native_concurrent_summary,
    ) = _measurement_summaries(_summary, python_warm, native_warm, python_cold, native_oneshot, native_concurrent)
    result, warm_speedup, cold_speedup = _build_result(
        python_warm_summary=python_warm_summary,
        native_warm_summary=native_warm_summary,
        python_cold_summary=python_cold_summary,
        native_oneshot_summary=native_oneshot_summary,
        native_concurrent_summary=native_concurrent_summary,
        native_readiness_ms=native_readiness_ms,
        native_concurrent_errors=native_concurrent_errors,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")

    if not args.enforce:
        return 0
    failures = _performance_failures(
        warm_speedup=warm_speedup,
        native_warm_summary=native_warm_summary,
        cold_speedup=cold_speedup,
        native_oneshot_summary=native_oneshot_summary,
        native_readiness_ms=native_readiness_ms,
        native_concurrent=native_concurrent,
        native_concurrent_errors=native_concurrent_errors,
        native_concurrent_summary=native_concurrent_summary,
    )
    if failures:
        for failure in failures:
            print(f"PERFORMANCE GATE: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
