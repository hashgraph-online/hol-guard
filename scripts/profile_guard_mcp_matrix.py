"""Shared MCP profiler matrix, remote helper, and checkpoints."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import platform
import sys
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scripts.profile_guard_mcp_fixture import BenchmarkCaseError, summarize
else:
    from profile_guard_mcp_fixture import BenchmarkCaseError, summarize


def run_remote_case(*, samples: int, server_delay_ms: float, payload_bytes: int = 1024) -> dict[str, Any]:
    """The shipped HTTP helper against loopback, not the draft hosted proxy."""
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from codex_plugin_scanner.guard.proxy.remote import RemoteGuardProxy

    server_waits: list[float] = []
    requests_seen: list[Any] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any, **_kwargs: Any) -> None:
            return

        def do_POST(self) -> None:
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests_seen.append(request.get("id"))
            if "id" not in request:
                self.send_response(204)
                self.end_headers()
                return
            started = time.perf_counter_ns()
            time.sleep(server_delay_ms / 1000)
            server_waits.append((time.perf_counter_ns() - started) / 1e6)
            response = {"jsonrpc": "2.0", "id": request["id"], "result": request["params"]}
            body = json.dumps(response, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    worker.start()
    proxy = RemoteGuardProxy(f"http://127.0.0.1:{server.server_port}/mcp", allow_insecure_localhost=True)
    wall: list[float] = []
    cpu: list[float] = []
    digest = hashlib.sha256()
    try:
        for index in range(samples + 1):
            request = {"jsonrpc": "2.0", "id": index, "method": "tools/call", "params": {"text": "x" * payload_bytes}}
            started, cpu_started = time.perf_counter_ns(), time.thread_time_ns()
            result = proxy.forward("", request)
            wall.append((time.perf_counter_ns() - started) / 1e6)
            cpu.append((time.thread_time_ns() - cpu_started) / 1e6)
            expected = {"jsonrpc": "2.0", "id": index, "result": request["params"]}
            if result != expected:
                raise RuntimeError("mcp_benchmark_remote_result_mismatch")
            digest.update(json.dumps(result, sort_keys=True).encode())
        if (
            proxy.forward("", {"jsonrpc": "2.0", "method": "notifications/initialized"}, expect_response=False)
            is not None
        ):
            raise RuntimeError("mcp_benchmark_remote_notification_response")
        if requests_seen != [*range(samples + 1), None]:
            raise RuntimeError("mcp_benchmark_remote_forwarding_mismatch")
        return {
            "boundary": "EXISTING_REMOTE_GUARD_PROXY_HTTP_LOOPBACK_HELPER",
            "fixture": {"samples": samples, "payload_bytes": payload_bytes, "server_delay_ms": server_delay_ms},
            "qualification": False,
            "remote_roundtrip_ms": summarize(wall[1:]),
            "client_thread_cpu_ms": summarize(cpu[1:]),
            "declared_server_wait_ms": summarize(server_waits[1:]),
            "correctness": {
                "exact_results": samples + 1,
                "notification_204": True,
                "errors": 0,
                "trace_sha256": digest.hexdigest(),
            },
            "limitations": [
                "loopback_only_no_tls_or_auth_or_live_network",
                "not_hosted_proxy_draft_2931",
                "existing_helper_has_no_stdio_catalog_or_approval_path",
            ],
        }
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def runtime_source_identity() -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    names = (
        "proxy/runtime_mcp.py",
        "proxy/framing.py",
        "proxy/tool_catalog.py",
        "mcp_tool_calls.py",
    )
    return {
        name: hashlib.sha256((root / "src/codex_plugin_scanner/guard" / name).read_bytes()).hexdigest()
        for name in names
    }


def write_checkpoint(output: Path, report: dict[str, Any]) -> None:
    # Readers see either the prior complete checkpoint or the next one.
    temporary = output.with_suffix(output.suffix + ".pending")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    os.replace(temporary, output)


@contextmanager
def performance_lock(lock_file: Path | None):
    """Serialize one case at a time so independent work can use the host."""
    if lock_file is None:
        yield
        return
    import fcntl

    with lock_file.open("a") as descriptor:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)


def run_matrix_common(
    *,
    case_runner: Callable[..., dict[str, Any]],
    schema: str,
    samples: int,
    output: Path,
    lock_file: Path | None = None,
    resume: bool = False,
) -> dict[str, Any]:
    """Alternating cache blocks followed by separate attribution/correctness runs."""
    cases: list[dict[str, Any]] = []
    for block in range(5):
        for catalog_size in (10, 100, 1000):
            for uncached in (False, True) if block % 2 == 0 else (True, False):
                cases.append({"block": block, "catalog_size": catalog_size, "uncached": uncached})
    cases.extend({"payload_bytes": size} for size in (16384, 131072))
    cases.extend(
        {"profile": True, "payload_bytes": size, "samples": min(samples, 20)} for size in (1024, 16384, 131072)
    )
    cases.extend(
        [
            {"profile": True, "catalog_size": 1000, "samples": min(samples, 20)},
            {"profile": True, "child_delay_ms": 20, "samples": min(samples, 20)},
            {"profile": True, "refresh_every": 5, "samples": min(samples, 20)},
            *[{"profile": True, "approval": approval, "samples": 3} for approval in ("accept", "cancel", "invalidate")],
        ]
    )
    report: dict[str, Any] = {
        "schema": schema,
        "qualification": False,
        "platform": platform.system(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "percentile_estimator": "nearest_rank",
        "remote_network": "loopback_helper_separate_from_stdio",
        "runtime_sources_sha256": runtime_source_identity(),
        "cases": [],
        "limitations": [
            "source_route_not_installed_cli",
            "c1_only",
            "single_host_diagnostic",
            "memory_samples_are_not_absolute_peak",
            "profile_timings_are_not_qualification",
            "human_wait_is_synthetic_client_delay",
            "uncached_is_counterfactual_not_release",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    completed_at_resume = 0
    if resume:
        existing = json.loads(output.read_text())
        for key in ("schema", "platform", "architecture", "python", "runtime_sources_sha256"):
            if existing.get(key) != report[key]:
                raise ValueError("mcp_benchmark_incompatible_resume_metadata")
        if any(existing.get(key) is not None for key in ("failed_case", "failed_remote_case")):
            raise ValueError("mcp_benchmark_resume_requires_failed_attempt_resolution")
        completed_at_resume = len(existing.get("cases", []))
        if completed_at_resume > len(cases):
            raise ValueError("mcp_benchmark_resume_exceeds_schedule")
        defaults = {name: parameter.default for name, parameter in inspect.signature(case_runner).parameters.items()}
        for completed, scheduled in zip(existing["cases"], cases, strict=False):
            expected = {**defaults, "samples": samples, **scheduled}
            block = expected.pop("block", None)
            if completed.get("fixture") != expected or completed.get("block") != block:
                raise ValueError("mcp_benchmark_resume_fixture_mismatch")
            if completed.get("correctness", {}).get("errors") != 0:
                raise ValueError("mcp_benchmark_resume_contains_failed_case")
        report = existing
        report.setdefault("resumed_after_case_counts", []).append(completed_at_resume)
    report["measurement_lock"] = "per_case_POSIX_flock" if lock_file is not None else "caller_managed"
    for index, case in enumerate(cases):
        if index < completed_at_resume:
            continue
        options = {"samples": samples, **case}
        block = options.pop("block", None)
        try:
            with performance_lock(lock_file):
                result = case_runner(**options)
        except BenchmarkCaseError as error:
            report["failed_case"] = {"case": index + 1, "block": block, "fixture": options, **error.evidence}
            report["completed_cases"] = len(report["cases"])
            write_checkpoint(output, report)
            raise
        result["block"] = block
        report["cases"].append(result)
        report["completed_cases"] = len(report["cases"])
        write_checkpoint(output, report)
        print(
            json.dumps(
                {
                    "case": index + 1,
                    "total": len(cases),
                    "fixture": result["fixture"],
                    "roundtrip_p95_ms": result["client_roundtrip_ms"]["p95"],
                    "errors": result["correctness"]["errors"],
                }
            ),
            file=sys.stderr,
            flush=True,
        )
    comparisons = []
    for block in range(5):
        for catalog_size in (10, 100, 1000):
            pair = [
                case
                for case in report["cases"]
                if case["block"] == block and case["fixture"]["catalog_size"] == catalog_size
            ]
            cached = next(case for case in pair if not case["fixture"]["uncached"])
            uncached = next(case for case in pair if case["fixture"]["uncached"])
            if (
                cached["correctness"]["exact_response_trace_sha256"]
                != uncached["correctness"]["exact_response_trace_sha256"]
            ):
                raise RuntimeError("mcp_benchmark_cache_mode_trace_mismatch")
            if cached["correctness"] != uncached["correctness"]:
                raise RuntimeError("mcp_benchmark_cache_mode_decision_mismatch")
            comparisons.append(
                {
                    "exact_decision_notification_generation_parity": True,
                    "block": block,
                    "catalog_size": catalog_size,
                    "exact_trace_parity": True,
                    "cached_roundtrip_p95_ms": cached["client_roundtrip_ms"]["p95"],
                    "uncached_roundtrip_p95_ms": uncached["client_roundtrip_ms"]["p95"],
                    "cached_tree_cpu_ms_per_call": cached["tree_cpu_ms_per_call"],
                    "uncached_tree_cpu_ms_per_call": uncached["tree_cpu_ms_per_call"],
                }
            )
    report.setdefault("remote_cases", [])
    for delay in (0, 20):
        if any(case["fixture"]["server_delay_ms"] == delay for case in report["remote_cases"]):
            continue
        try:
            with performance_lock(lock_file):
                remote_result = run_remote_case(samples=min(samples, 20), server_delay_ms=delay)
        except Exception as error:
            report["failed_remote_case"] = {"server_delay_ms": delay, "reason": type(error).__name__, "errors": 1}
            write_checkpoint(output, report)
            raise
        report["remote_cases"].append(remote_result)
        write_checkpoint(output, report)
    report["cache_comparisons"] = comparisons
    report["completed_cases"] = len(cases)
    write_checkpoint(output, report)
    return report
