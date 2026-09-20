"""Shared one-case MCP profiler orchestration."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scripts.profile_guard_mcp_fixture import BenchmarkCaseError, summarize
    from scripts.profile_guard_mcp_worker import tree_sample
else:
    from profile_guard_mcp_fixture import BenchmarkCaseError, summarize
    from profile_guard_mcp_worker import tree_sample


def run_case_common(
    *,
    catalog_size: int = 100,
    payload_bytes: int = 1024,
    samples: int = 100,
    profile: bool = False,
    uncached: bool = False,
    child_delay_ms: float = 0,
    approval: str = "none",
    approval_delay_ms: float = 30,
    refresh_every: int = 0,
    compact_result: bool = False,
    payload_kind: str = "ascii",
    native_text_helper: Path | None = None,
    native_minimum_characters: int = 256 * 1024,
    preparation_variant: str,
    fixture_arguments_provider: Callable[[], Callable[[int, str, int], dict[str, Any]]],
    preparation_pilot: bool = False,
) -> dict[str, Any]:
    """Complete ordinary local proxy path; abort on a mismatched result or ID."""
    # Import the client reader before timing worker startup.
    from codex_plugin_scanner.guard.proxy.framing import retire_reader
    from codex_plugin_scanner.guard.proxy.stdio import _readline_with_timeout

    with tempfile.TemporaryDirectory(prefix="guard-mcp-profile-") as directory:
        root = Path(directory)
        spec = {
            "catalog_size": catalog_size,
            "payload_bytes": payload_bytes,
            "samples": samples,
            "profile": profile,
            "uncached": uncached,
            "child_delay_ms": child_delay_ms,
            "approval": approval,
            "approval_delay_ms": approval_delay_ms,
            "refresh_every": refresh_every,
            "compact_result": compact_result,
            "payload_kind": payload_kind,
            "native_text_helper": str(native_text_helper) if native_text_helper is not None else None,
            "native_minimum_characters": native_minimum_characters,
            f"{preparation_variant}_preparation_pilot": preparation_pilot,
            "worker_output": str(root / "worker.json"),
        }
        config_path = root / "config.json"
        config_path.write_text(json.dumps(spec))
        started = time.perf_counter_ns()
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).with_name("profile_guard_mcp_worker.py")),
                "--variant",
                preparation_variant,
                "--config",
                str(config_path),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            bufsize=1,
            start_new_session=os.name == "posix",
        )
        assert process.stdin and process.stdout
        client_stdin = process.stdin
        timings: list[float] = []
        memory: list[dict[str, float]] = []
        startup: dict[str, float] = {}
        notifications: Counter[str] = Counter()
        accepted = cancelled = invalidated = 0
        trace = hashlib.sha256()
        generation = 0
        forwarded_ids: list[Any] = []
        attempted_tools = 0
        largest_client_frame_bytes = 0
        stage = "initialize"

        def send(message: dict[str, Any]) -> None:
            nonlocal largest_client_frame_bytes
            encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n"
            largest_client_frame_bytes = max(largest_client_frame_bytes, len(encoded.encode()))
            client_stdin.write(encoded)
            client_stdin.flush()

        def read(timeout_seconds: float = 30) -> dict[str, Any]:
            line = _readline_with_timeout(process.stdout, timeout_seconds=timeout_seconds, source="benchmark_client")
            if not line:
                raise RuntimeError("mcp_benchmark_unexpected_eof")
            return json.loads(line)

        def response_for(request_id: Any) -> dict[str, Any]:
            pending_approval = None
            deadline = time.monotonic() + 30
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("mcp_benchmark_response_deadline")
                message = read(remaining)
                method = message.get("method")
                if method == "elicitation/create":
                    if approval == "invalidate":
                        pending_approval = message["id"]
                        send({"jsonrpc": "2.0", "method": "benchmark/refresh", "params": {}})
                        continue
                    time.sleep(approval_delay_ms / 1000)
                    action = (
                        {"action": "cancel"}
                        if approval == "cancel"
                        else {"action": "accept", "content": {"decision": "approve"}}
                    )
                    send({"jsonrpc": "2.0", "id": message["id"], "result": action})
                    continue
                if method:
                    notifications[method] += 1
                    if pending_approval is not None and method == "notifications/tools/list_changed":
                        time.sleep(approval_delay_ms / 1000)
                        send(
                            {
                                "jsonrpc": "2.0",
                                "id": pending_approval,
                                "result": {"action": "accept", "content": {"decision": "approve"}},
                            }
                        )
                        pending_approval = None
                    continue
                if type(message.get("id")) is not type(request_id) or message.get("id") != request_id:
                    raise RuntimeError("mcp_benchmark_response_id_mismatch")
                return message

        try:
            send(
                {
                    "jsonrpc": "2.0",
                    "id": "initialize",
                    "method": "initialize",
                    "params": {"capabilities": {"elicitation": {}}},
                }
            )
            response_for("initialize")
            startup["spawn_to_initialize_ms"] = (time.perf_counter_ns() - started) / 1e6
            stage = "initial_catalog"
            list_started = time.perf_counter_ns()
            send({"jsonrpc": "2.0", "id": "catalog", "method": "tools/list", "params": {}})
            catalog = response_for("catalog")
            if len(catalog.get("result", {}).get("tools", [])) != catalog_size:
                raise RuntimeError("mcp_benchmark_catalog_count_mismatch")
            startup["initial_catalog_ms"] = (time.perf_counter_ns() - list_started) / 1e6
            memory.append(tree_sample(process))
            for index in range(samples + 1):
                if refresh_every and index and index % refresh_every == 0:
                    stage = "catalog_refresh"
                    send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {}})
                    send({"jsonrpc": "2.0", "method": "benchmark/refresh", "params": {}})
                    notification = read()
                    if notification.get("method") != "notifications/tools/list_changed":
                        raise RuntimeError("mcp_benchmark_refresh_notification_missing")
                    notifications[notification["method"]] += 1
                    generation += 1
                    send({"jsonrpc": "2.0", "id": "catalog", "method": "tools/list", "params": {}})
                    response_for("catalog")
                request_id: str | int = f"call-{index}" if index % 2 else index
                arguments = fixture_arguments_provider()(payload_bytes, payload_kind, index)
                payload = arguments["text"]
                params = {"name": "echo_0", "arguments": arguments}
                # The declared review policy exercises real elicitation for an ordinary tool.
                stage = "tool_call"
                before = time.perf_counter_ns()
                attempted_tools += 1
                send({"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params})
                response = response_for(request_id)
                timings.append((time.perf_counter_ns() - before) / 1e6)
                if approval in {"cancel", "invalidate"}:
                    error = response.get("error", {})
                    if error.get("code") != -32001:
                        raise RuntimeError("mcp_benchmark_expected_block_missing")
                    if approval == "invalidate":
                        if error.get("data", {}).get("guardPolicyAction") != "require-reapproval":
                            raise RuntimeError("mcp_benchmark_catalog_invalidation_failed")
                        invalidated += 1
                    else:
                        cancelled += 1
                    trace.update(json.dumps({"id": request_id, "code": error["code"]}).encode())
                else:
                    if compact_result:
                        digest = hashlib.sha256(
                            json.dumps(
                                params["arguments"], sort_keys=True, ensure_ascii=False, separators=(",", ":")
                            ).encode()
                        ).hexdigest()
                        expected_result = {
                            "content": [{"type": "text", "text": digest}],
                            "structuredContent": {
                                "arguments_sha256": digest,
                                "payload_utf8_bytes": len(payload.encode()),
                                "generation": generation,
                            },
                            "_meta": {"synthetic": True},
                        }
                    else:
                        expected_result = {
                            "content": [{"type": "text", "text": payload}],
                            "structuredContent": {"text": payload, "generation": generation},
                            "_meta": {"synthetic": True},
                        }
                    expected = {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": expected_result,
                    }
                    if response != expected:
                        raise RuntimeError("mcp_benchmark_complete_result_mismatch")
                    trace.update(json.dumps(response, sort_keys=True, separators=(",", ":")).encode())
                    forwarded_ids.append(request_id)
                    accepted += 1
                memory.append(tree_sample(process))
            stage = "session_cleanup"
            process.stdin.close()
            return_code = process.wait(timeout=30)
            if return_code != 0:
                raise RuntimeError(f"mcp_benchmark_proxy_exit_{return_code}")
            worker = json.loads((root / "worker.json").read_text())
            child = json.loads((root / "child.json").read_text())
            if child["forwarded_ids"] != forwarded_ids:
                raise RuntimeError("mcp_benchmark_forwarding_count_or_order_mismatch")
            if len(worker["observations"]) != samples + 1:
                raise RuntimeError("mcp_benchmark_observation_count_mismatch")
            if worker["quiet_barrier_seconds"] != 0.005:
                raise RuntimeError("mcp_benchmark_prewrite_barrier_changed")
            warm = worker["observations"][1:]
            phase_names = sorted({name for row in warm for name in row["phases"]})
            return {
                "fixture": {
                    key: value for key, value in spec.items() if key not in {"worker_output", "native_text_helper"}
                },
                "boundary": "MCP_STDIO_CLIENT_THROUGH_SERVE_AND_CHILD",
                "qualification": False,
                "stderr_policy": "discarded_in_child_no_capture_backpressure",
                "loaded_runtime_sha256": worker["loaded_runtime_sha256"],
                "native_text_pilot": worker["native_text_pilot"],
                f"{preparation_variant}_preparation_pilot": worker[f"{preparation_variant}_preparation_pilot"],
                **(
                    {"loaded_adapter_sha256": worker["loaded_adapter_sha256"]}
                    if preparation_variant == "streaming"
                    else {}
                ),
                "startup": {**startup, "guard_imports_ms": worker["imports_ms"]},
                "cold_first_tool_ms": timings[0],
                "client_roundtrip_ms": summarize(timings[1:]),
                "proxy_handle_ms": summarize([row["wall_ms"] for row in warm]),
                "parent_cpu_ms": summarize([row["parent_cpu_ms"] for row in warm]),
                "child_tool_cpu_ms": summarize(child["tool_cpu_ms"][1:]),
                "child_declared_wait_ms": summarize(child["declared_wait_ms"][1:]),
                "tree_cpu_ms_per_call": (memory[-1]["cpu_ms"] - memory[0]["cpu_ms"]) / (samples + 1),
                "memory": {
                    "sampling": "parent_plus_recursive_children_after_catalog_and_each_response",
                    "samples": len(memory),
                    "max_processes": max(row["processes"] for row in memory),
                    "rss_max_bytes": max(row["rss_bytes"] for row in memory),
                    "uss_max_bytes": max(row["uss_bytes"] for row in memory),
                    "uss_after_catalog_bytes": memory[0]["uss_bytes"],
                    "uss_final_bytes": memory[-1]["uss_bytes"],
                    "worker_peak_rss_bytes": worker["worker_peak_rss_bytes"],
                    "worker_peak_rss_scope": "OS_RUSAGE_SELF_whole_worker_including_imports_and_transient_requests",
                },
                "exclusive_phases": {
                    name: {
                        "wall_ms": summarize([row["phases"].get(name, {}).get("wall_ms", 0) for row in warm]),
                        "thread_cpu_ms": summarize(
                            [row["phases"].get(name, {}).get("thread_cpu_ms", 0) for row in warm]
                        ),
                        "calls": sum(row["phases"].get(name, {}).get("calls", 0) for row in warm),
                    }
                    for name in phase_names
                },
                "all_session_phases": worker["all_phases"],
                "correctness": {
                    "accepted": accepted,
                    "cancelled": cancelled,
                    "invalidated": invalidated,
                    "notifications": dict(notifications),
                    "errors": 0,
                    "exact_response_trace_sha256": trace.hexdigest(),
                    "forwarded_ids_exact": True,
                    "quiet_barrier_seconds": 0.005,
                    "largest_client_frame_utf8_bytes": largest_client_frame_bytes,
                    "decisions": dict(Counter(row["decision"] for row in worker["observations"])),
                    "catalog_generations": sorted({row["catalog_generation"] for row in worker["observations"]}),
                },
            }
        except (Exception, KeyboardInterrupt) as error:
            code = str(error)
            # Allow a terminal proxy response to finish its bounded cleanup and
            # persist the worker's helper evidence before inspecting the files.
            if process.poll() is None:
                with suppress(OSError):
                    process.stdin.close()
                with suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=2)
            failed_worker = {}
            if (root / "worker.json").is_file():
                with suppress(OSError, ValueError):
                    failed_worker = json.loads((root / "worker.json").read_text())
            child_forwarded = []
            with suppress(OSError, ValueError):
                child_forwarded = [
                    json.loads(line) for line in (root / "child.forwarded.jsonl").read_text().splitlines()
                ]
            raise BenchmarkCaseError(
                {
                    "stage": stage,
                    "reason": type(error).__name__,
                    "failure_code": code if code.startswith("mcp_benchmark_") else type(error).__name__,
                    "expected_tool_requests": samples + 1,
                    "attempted_tool_requests": attempted_tools,
                    "observed_tool_responses": len(timings),
                    "accepted": accepted,
                    "cancelled": cancelled,
                    "invalidated": invalidated,
                    "notifications": dict(notifications),
                    "errors": 1,
                    "native_text_pilot": failed_worker.get("native_text_pilot"),
                    f"{preparation_variant}_preparation_pilot": failed_worker.get(
                        f"{preparation_variant}_preparation_pilot"
                    ),
                    **(
                        {"loaded_adapter_sha256": failed_worker.get("loaded_adapter_sha256")}
                        if preparation_variant == "streaming"
                        else {}
                    ),
                    "worker_failure": failed_worker.get("worker_failure"),
                    "worker_exit_code": process.poll(),
                    "observed_child_forwarded_count": len(child_forwarded),
                }
            ) from error
        finally:
            if process.poll() is None:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait(timeout=10)
            retire_reader(process.stdout)
            process.stdout.close()
