#!/usr/bin/env python3
"""Release-gate benchmark for Python hook workers versus the Rust runtime.

Only aggregate synthetic measurements are emitted; benchmark output excludes
user commands, file contents, secrets, and machine paths.

The enforced warm comparison measures NATIVE_CLIENT, from the Python native
adapter to a decision, against an isolated benchmark-only Python semantic engine
process. Direct resident IPC is also a NATIVE_CLIENT diagnostic. Neither timer
includes daemon HTTP ingress or an installed launcher. Both arms must correctly
allow a benign fixture and block a synthetic credential before timing.
Relative speed remains informative because trivial allow payloads can favor Python, while release acceptance follows
the contract: native p95 must stay below the absolute ceiling or materially improve over the pinned Python
reference. Cold comparison retains the stronger relative-speedup gate.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from codex_plugin_scanner.guard.native_hook_edge import _decode_edge, _encode_hook_envelope
from codex_plugin_scanner.guard.native_policy_test_support import native_policy_snapshot
from codex_plugin_scanner.guard.native_resident_client import close_native_residents, native_resident_client_request
from codex_plugin_scanner.guard.native_route_receipt import native_hook_route, reset_native_hook_route
from codex_plugin_scanner.guard.native_runtime import (
    native_runtime_health,
    native_runtime_status,
    review_post_tool_native,
)
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MIN_WARM_P95_SPEEDUP = 1.15
_MAX_WARM_P95_MS = 20.0
_MIN_COLD_P95_SPEEDUP = 5.0
_MAX_COLD_P95_MS = 150.0
_MAX_NATIVE_READINESS_MS = 400.0


# A scripts-only oracle must not be imported by any production entry point.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

from scripts.native_benchmark_oracle import (  # noqa: E402
    BenchmarkPythonOracle,
    synthetic_payload,
    validate_semantic_response,
)


def _percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * quantile) - 1))
    return ordered[index]


def _summary(values: list[float]) -> dict[str, float]:
    return {
        "count": len(values),
        "p50_ms": round(statistics.median(values), 3),
        "p95_ms": round(_percentile(values, 0.95), 3),
        "p99_ms": round(_percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }


def _payload(sample: int | None = None, *, case: str = "benign") -> dict[str, object]:
    return synthetic_payload(sample, case=case)


def _prepare_benchmark_policy(guard_home: Path) -> None:
    """Give both semantic arms the same explicit policy before any timing."""
    from scripts.native_slo_workloads import configuration_text

    with (guard_home / "config.toml").open("x", encoding="utf-8") as handle:
        handle.write(configuration_text("normal"))


def _require_benchmark_policy(snapshot: Mapping[str, object]) -> None:
    effective = snapshot.get("effective_policy")
    if not isinstance(effective, Mapping):
        raise RuntimeError("benchmark acknowledged policy missing")
    actions = (
        "default_action",
        "subprocess_action",
        "unknown_publisher_action",
        "changed_hash_action",
        "new_network_domain_action",
    )
    selectors = ("artifact_actions", "harness_actions", "publisher_actions", "harness_risk_actions")
    risks = effective.get("risk_actions")
    if (
        snapshot.get("mode") != "enforce"
        or effective.get("protection_posture") != "protected"
        or any(effective.get(name) != "allow" for name in actions)
        or any(effective.get(name) != {} for name in selectors)
        or not isinstance(risks, Mapping)
        or not risks
        or any(action != "allow" for action in risks.values())
    ):
        raise RuntimeError("benchmark acknowledged policy does not match explicit semantic fixture")


def _request(
    *,
    workspace: Path,
    guard_home: Path,
    request_id: str,
    sample: int | None = None,
    case: str = "benign",
) -> HookReviewRequest:
    return HookReviewRequest(
        harness="claude-code",
        event_name="PostToolUse",
        payload=_payload(sample, case=case),
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
    case: str = "benign",
) -> str:
    return json.dumps(
        {
            "protocol_version": 1,
            "request_id": request_id,
            "harness": "claude-code",
            "event_name": "PostToolUse",
            "payload": _payload(sample, case=case),
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
    runner: BenchmarkPythonOracle,
    *,
    sample: int | None = None,
    case: str = "benign",
) -> None:
    result = runner.review(sample=sample, case=case)
    validate_semantic_response(
        result,
        route=str(result.get("route")),
        expected_route="python_semantic",
        case=case,
    )


def _bench_python_warm_reference(*, workspace: Path, guard_home: Path, iterations: int) -> list[float]:
    runner = BenchmarkPythonOracle(workspace=workspace, guard_home=guard_home)
    values: list[float] = []
    try:
        runner.start()
        for case in ("benign", "secret"):
            _python_review(runner, case=case)
        for index in range(iterations):
            started = time.perf_counter()
            response = runner.review(sample=index)
            values.append((time.perf_counter() - started) * 1_000.0)
            validate_semantic_response(
                response, route=str(response.get("route")), expected_route="python_semantic", case="benign"
            )
    finally:
        runner.close()
    return values


def _bench_native_warm(
    *, workspace: Path, guard_home: Path, iterations: int, policy_snapshot: Mapping[str, object]
) -> list[float]:
    """Measure generation-bound authenticated resident IPC as a diagnostic."""
    status = native_runtime_status()
    if status.identity is None:
        raise RuntimeError("Native resident runtime identity is unavailable")
    values: list[float] = []
    for index in range(iterations):
        request = _encode_hook_envelope(
            payload=_payload(index),
            harness="claude-code",
            event="PostToolUse",
            guard_home=guard_home,
            home_dir=workspace,
            cwd=workspace,
            source_ref_external_allowed=False,
            deadline_budget_ms=5_000,
            snapshot=policy_snapshot,
        )
        if request is None:
            raise RuntimeError("native benchmark envelope encoding failed")
        started = time.perf_counter()
        response_bytes = native_resident_client_request(
            executable=status.identity.path,
            guard_home=guard_home,
            environment=_native_environment(workspace),
            payload=request,
            timeout_seconds=5.0,
            raw_hook_envelope=True,
        )
        values.append((time.perf_counter() - started) * 1_000.0)
        if response_bytes is None:
            raise RuntimeError("Native resident IPC request failed")
        edge = _decode_edge(json.loads(response_bytes))
        if edge is None:
            raise RuntimeError("native benchmark response receipt validation failed")
        validate_semantic_response(
            edge["result"], route="native_resident", expected_route="native_resident", case="benign"
        )
    return values


def _bench_native_warm_production(
    *,
    workspace: Path,
    guard_home: Path,
    iterations: int,
    policy_snapshot: Mapping[str, object] | None = None,
) -> list[float]:
    """Measure NATIVE_CLIENT: the Python native adapter over a warm resident."""
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
        validate_semantic_response(
            response,
            route=native_hook_route(),
            expected_route="native_resident",
            case="benign",
        )
    return values


def _bench_python_cold(*, workspace: Path, guard_home: Path, iterations: int) -> list[float]:
    values: list[float] = []
    for index in range(iterations):
        runner = BenchmarkPythonOracle(workspace=workspace, guard_home=guard_home)
        started = time.perf_counter()
        try:
            runner.start()
            response = runner.review(sample=index)
            values.append((time.perf_counter() - started) * 1_000.0)
            validate_semantic_response(
                response, route=str(response.get("route")), expected_route="python_semantic", case="benign"
            )
            _python_review(runner, case="secret")
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
        validate_semantic_response(response, route="native_oneshot", expected_route="native_oneshot", case="benign")
    return values


def _validate_native_cases(
    *, runtime: Path, workspace: Path, guard_home: Path, policy_snapshot: Mapping[str, object]
) -> None:
    """Prove semantic work for both native adapters, outside timing samples."""
    for case in ("benign", "secret"):
        reset_native_hook_route()
        response = review_post_tool_native(
            _request(workspace=workspace, guard_home=guard_home, request_id=f"native-check-{case}", case=case),
            observe_mode=False,
            policy_snapshot=policy_snapshot,
        )
        try:
            validate_semantic_response(response, route=native_hook_route(), expected_route="native_resident", case=case)
        except RuntimeError as error:
            # Health reasons are bounded product identifiers; never log the
            # native response or the hook's content to diagnose a failed gate.
            health = native_runtime_health(guard_home)
            raise RuntimeError(f"{error} health={health.reason} failures={health.resident_failures}") from None
        result = run_isolated_hook_process(
            (str(runtime), "hook", "--stdin"),
            input_text=_wire_request(workspace=workspace, guard_home=guard_home, case=case),
            cwd=runtime.parent,
            environment=_native_environment(workspace),
            timeout_seconds=5.0,
            output_limit=_MAX_RESPONSE_BYTES,
        )
        if result.returncode != 0 or result.timed_out or result.containment_failed:
            raise RuntimeError("native semantic qualification process failed")
        validate_semantic_response(
            json.loads(result.stdout), route="native_oneshot", expected_route="native_oneshot", case=case
        )


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
        _prepare_benchmark_policy(guard_home)

        python_warm = _bench_python_warm_reference(
            workspace=workspace,
            guard_home=guard_home,
            iterations=warm_iterations,
        )

        close_native_residents()
        try:
            with native_policy_snapshot(guard_home) as snapshot:
                _require_benchmark_policy(snapshot)
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
                _validate_native_cases(
                    runtime=runtime, workspace=workspace, guard_home=guard_home, policy_snapshot=snapshot
                )
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
                    policy_snapshot=snapshot,
                )
        finally:
            _stop_native_resident(runtime, guard_home / "native-runtime", workspace)
            close_native_residents()

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
        "schema": "hol-guard-native-performance.v2",
        "evidence_class": "smoke",
        "qualification_complete": False,
        "percentile_estimator": "nearest_rank",
        "timing_boundaries": {
            "KERNEL": "not_measured",
            "NATIVE_CLIENT": "python_native_adapter_and_authenticated_ipc",
            "DAEMON_INGRESS": "not_measured",
            "INSTALLED_LAUNCHER": "not_measured",
        },
        "reference": {
            "implementation": "isolated_benchmark_python_semantic_engine",
            "production_fallback": False,
            "cases_validated": ["benign", "secret"],
            "comparison_scope": "semantic_engine_process_not_legacy_guardian_topology",
            "shared_policy_fixture": "explicit_protected_allow_policy",
            "acknowledged_policy_validated": True,
        },
        "warm": {
            "boundary": "NATIVE_CLIENT",
            "python_semantic_oracle_process": python_warm_summary,
            "native_resident": native_warm_summary,
            "native_resident_ipc_diagnostic": native_warm_ipc_summary,
            "p95_speedup": warm_speedup,
        },
        "cold": {
            "boundary": "NATIVE_CLIENT",
            "process_startup_included": True,
            "python_semantic_oracle_process": python_cold_summary,
            "native_oneshot": native_oneshot_summary,
            "p95_speedup": cold_speedup,
        },
        "native_readiness_ms": round(native_readiness_ms, 3),
        "readiness_excludes_snapshot_materialization": True,
        "direct_concurrent_16": "not_measured",
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
