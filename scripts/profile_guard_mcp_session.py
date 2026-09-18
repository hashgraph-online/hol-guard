#!/usr/bin/env python3
"""Measure the actual MCP serve route using synthetic client and child pipes.

Run under the shared performance-measurement.lock. Uninstrumented timings and
instrumented exclusive phase attribution use separate, fresh processes. The
uncached mode is a diagnostic counterfactual, not a released baseline or Rust.
No credential, argument, path, receipt body, or catalog text is exported.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import inspect
import json
import math
import os
import platform
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

_CHILD = r"""
import hashlib, json, sys, time
from pathlib import Path
size, delay, output = int(sys.argv[1]), float(sys.argv[2]), Path(sys.argv[3])
compact_result = sys.argv[4] == 'true'
generation = 0
calls = []
waits = []
cpu = []
def send(value):
    print(json.dumps(value, separators=(',', ':'), ensure_ascii=False), flush=True)
for line in sys.stdin:
    message = json.loads(line)
    method = message.get('method')
    if method == 'benchmark/refresh':
        generation += 1
        send({'jsonrpc': '2.0', 'method': 'notifications/tools/list_changed', 'params': {}})
        continue
    if 'id' not in message:
        continue
    if method == 'tools/list':
        result = {'tools': [{'name': 'echo_' + str(i), 'description': 'Echo text version ' + str(generation),
                  'inputSchema': {'type': 'object', 'properties': {'text': {'type': 'string'}}},
                  'outputSchema': {'type': 'object'}, 'annotations': {'readOnlyHint': True}}
                 for i in range(size)]}
    elif method == 'tools/call':
        start_cpu = time.process_time_ns()
        with output.with_suffix('.forwarded.jsonl').open('a') as journal:
            journal.write(json.dumps(message['id']) + '\n')
        start_wait = time.perf_counter_ns()
        if delay:
            time.sleep(delay)
        waits.append((time.perf_counter_ns() - start_wait) / 1e6)
        arguments = message['params']['arguments']
        text = arguments['text']
        if compact_result:
            digest = hashlib.sha256(json.dumps(arguments, sort_keys=True, ensure_ascii=False,
                                                separators=(',', ':')).encode()).hexdigest()
            result = {'content': [{'type': 'text', 'text': digest}],
                      'structuredContent': {'arguments_sha256': digest, 'payload_utf8_bytes': len(text.encode()),
                                            'generation': generation}, '_meta': {'synthetic': True}}
        else:
            result = {'content': [{'type': 'text', 'text': text}],
                      'structuredContent': {'text': text, 'generation': generation},
                      '_meta': {'synthetic': True}}
        calls.append(message['id'])
        send({'jsonrpc': '2.0', 'method': 'notifications/progress',
              'params': {'progressToken': message['id'], 'progress': 1, 'total': 1}})
        send({'jsonrpc': '2.0', 'id': message['id'], 'result': result})
        cpu.append((time.process_time_ns() - start_cpu) / 1e6)
        continue
    else:
        result = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}},
                  'serverInfo': {'name': 'synthetic', 'version': '1'}}
    send({'jsonrpc': '2.0', 'id': message['id'], 'result': result})
output.write_text(json.dumps({'forwarded_ids': calls, 'declared_wait_ms': waits, 'tool_cpu_ms': cpu}))
"""


class BenchmarkCaseError(RuntimeError):
    """A bounded, non-sensitive failed-cell record survives scratch cleanup."""

    def __init__(self, evidence: dict[str, Any]) -> None:
        self.evidence = evidence
        super().__init__("mcp_benchmark_case_failed")


def fixture_arguments(payload_bytes: int, payload_kind: str, index: int) -> dict[str, Any]:
    """Bound synthetic text and decoded-container controls by their wire size."""
    if payload_kind in {"ascii", "unicode"}:
        text = (
            "€" * (payload_bytes // 3) + "x" * (payload_bytes % 3) if payload_kind == "unicode" else "x" * payload_bytes
        )
        return {"text": text, "sample": index}
    if payload_kind == "dense-integers":
        return {"text": "", "sample": index, "values": [0] * max(1, (payload_bytes - 256) // 2)}
    if payload_kind == "nested-records":
        record = {"k": [0, 1.0, None, False]}
        item_bytes = len(json.dumps(record, separators=(",", ":"))) + 1
        return {"text": "", "sample": index, "values": [record] * max(1, (payload_bytes - 256) // item_bytes)}
    if payload_kind == "nested-text":
        value: object = "x" * max(1, payload_bytes - 256)
        for _ in range(8):
            value = [value]
        return {"text": "", "sample": index, "values": value}
    raise ValueError("mcp_benchmark_unknown_payload_kind")


class Phases:
    """Exclusive main-thread wall/CPU attribution; nested costs are subtracted."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.owner = threading.get_ident()
        self.stack: list[list[Any]] = []
        self.values: dict[str, list[float]] = {}
        self.calls: Counter[str] = Counter()

    @contextmanager
    def phase(self, name: str):
        if not self.enabled or threading.get_ident() != self.owner:
            yield
            return
        frame = [time.perf_counter_ns(), time.thread_time_ns(), 0, 0]
        self.stack.append(frame)
        try:
            yield
        finally:
            wall = time.perf_counter_ns() - frame[0]
            cpu = time.thread_time_ns() - frame[1]
            self.stack.pop()
            value = self.values.setdefault(name, [0.0, 0.0])
            value[0] += (wall - frame[2]) / 1e6
            value[1] += (cpu - frame[3]) / 1e6
            self.calls[name] += 1
            if self.stack:
                self.stack[-1][2] += wall
                self.stack[-1][3] += cpu

    def wrap(self, owner: Any, name: str, phase: str) -> None:
        original = getattr(owner, name)

        @functools.wraps(original)
        def measured(*args: Any, **kwargs: Any):
            with self.phase(phase):
                return original(*args, **kwargs)

        setattr(owner, name, measured)

    def snapshot(self) -> dict[str, Any]:
        return {
            name: {"wall_ms": value[0], "thread_cpu_ms": value[1], "calls": self.calls[name]}
            for name, value in sorted(self.values.items())
        }


def _summary(values: list[float]) -> dict[str, float | int]:
    if not values:
        return {"count": 0}
    ordered = sorted(values)
    return {
        "count": len(values),
        "mean": statistics.mean(values),
        "p50": statistics.median(values),
        "p95": ordered[math.ceil(len(values) * 0.95) - 1],
        "p99": ordered[math.ceil(len(values) * 0.99) - 1],
        "max": ordered[-1],
    }


def _worker(config_path: Path) -> int:
    spec = json.loads(config_path.read_text())
    started = time.perf_counter_ns()
    from codex_plugin_scanner.guard import mcp_tool_calls as calls
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy, framing, tool_catalog
    from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime
    from codex_plugin_scanner.guard.store import GuardStore

    imports_ms = (time.perf_counter_ns() - started) / 1e6
    phases = Phases(spec["profile"])
    native_pilot = None
    owned_pilot = None
    if spec.get("owned_preparation_pilot"):
        import guard_mcp_owned_preparation_pilot as owned_adapter
        from guard_mcp_owned_preparation_pilot import OwnedPreparationPilot
        from guard_mcp_owned_preparation_pilot import install_adapter as install_owned_adapter

        owned_pilot = OwnedPreparationPilot()
        install_owned_adapter(runtime, owned_pilot)
        if spec["profile"]:
            phases.wrap(owned_pilot, "own_request", "owned_message_snapshot")
            phases.wrap(owned_adapter, "_exact_binding", "owned_input_binding")
            phases.wrap(calls, "_build_tool_call_hash_for_categories", "request_identity")
            phases.wrap(calls, "_evaluate_current_tool_call_for_categories", "policy")
            phases.wrap(calls, "_evaluate_tool_call_with_current", "policy")
    if spec.get("native_text_helper"):
        from guard_mcp_text_facts_pilot import TextFactsPilot, install_adapter

        native_pilot = TextFactsPilot(
            Path(spec["native_text_helper"]),
            minimum_characters=spec["native_minimum_characters"],
        )
        install_adapter(calls, native_pilot)
        if spec["profile"]:
            phases.wrap(native_pilot, "classify", "native_text_ipc")
    if spec["uncached"]:
        runtime._tool_catalog_fingerprint = runtime._uncached_tool_catalog_fingerprint
    if spec["profile"]:
        for name in ("dumps", "loads"):
            phases.wrap(json, name, "serialization")
        phases.wrap(runtime, "_tool_catalog_fingerprint", "catalog_hash")
        phases.wrap(calls, "_tool_call_risk_category_set", "classification")
        if hasattr(calls, "_tool_call_risk_snapshot"):
            phases.wrap(calls, "_tool_call_risk_snapshot", "facts_snapshot")
        phases.wrap(runtime, "evaluate_tool_call", "policy")
        phases.wrap(runtime, "build_tool_call_hash", "request_identity")
        phases.wrap(runtime, "allow_tool_call", "receipt_and_result")
        phases.wrap(runtime, "block_tool_call", "receipt_and_result")

    class MeasuredProxy(CodexMcpGuardProxy):
        def _start_process(self):
            with phases.phase("child_startup"):
                return super()._start_process()

        def _next_child_output_frame(self, *args, **kwargs):
            name = "child_wait" if kwargs.get("required") else "drain_poll"
            if kwargs.get("timeout_seconds") == runtime._TOOLS_CALL_PREWRITE_QUIET_SECONDS:
                name = "prewrite_quiet_barrier"
            with phases.phase(name):
                return super()._next_child_output_frame(*args, **kwargs)

        def _request_inline_approval(self, *args, **kwargs):
            with phases.phase("inline_approval_wait"):
                return super()._request_inline_approval(*args, **kwargs)

        def _write_message(self, *args, **kwargs):
            with phases.phase("pipe_write"):
                return super()._write_message(*args, **kwargs)

        def _capture_tools_catalog(self, *args, **kwargs):
            with phases.phase("catalog_capture"):
                return super()._capture_tools_catalog(*args, **kwargs)

        def _handle_message(self, **kwargs):
            wall, cpu = time.perf_counter_ns(), time.process_time_ns()
            before = phases.snapshot()
            with phases.phase("other_guard"):
                response, event = super()._handle_message(**kwargs)
            if kwargs["message"].get("method") == "tools/call":
                after = phases.snapshot()
                delta = {
                    name: {key: value - before.get(name, {}).get(key, 0) for key, value in values.items()}
                    for name, values in after.items()
                }
                observations.append(
                    {
                        "wall_ms": (time.perf_counter_ns() - wall) / 1e6,
                        "parent_cpu_ms": (time.process_time_ns() - cpu) / 1e6,
                        "phases": delta,
                        "decision": event.get("decision"),
                        "catalog_generation": self._tool_catalog_generation,
                        "catalog_state": self._tool_catalog_state,
                    }
                )
            return response, event

    observations: list[dict[str, Any]] = []
    root = config_path.parent
    home, workspace, guard_home = root / "home", root / "workspace", root / "guard"
    for path in (home, workspace, guard_home):
        path.mkdir()
    context = HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="review" if spec["approval"] != "none" else "warn",
        approval_surface_policy="never-auto-open",
    )
    with phases.phase("proxy_construction"):
        proxy = MeasuredProxy(
            server_name="synthetic",
            command=[
                sys.executable,
                "-u",
                "-c",
                _CHILD,
                str(spec["catalog_size"]),
                str(spec["child_delay_ms"] / 1000),
                str(root / "child.json"),
                "true" if spec["compact_result"] else "false",
            ],
            context=context,
            store=GuardStore(guard_home),
            config=config,
            current_config_provider=lambda: config,
            source_scope="project",
            config_path=str(workspace / ".mcp.json"),
        )
    worker_failure = None
    try:
        exit_code = proxy.serve()
    except Exception as error:
        exit_code = 1
        worker_failure = type(error).__name__
    finally:
        if native_pilot is not None:
            native_pilot.close()
    worker_peak_rss_bytes = None
    if sys.platform in {"linux", "darwin"}:
        import resource

        worker_peak_rss_bytes = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (
            1024 if sys.platform == "linux" else 1
        )
    Path(spec["worker_output"]).write_text(
        json.dumps(
            {
                "imports_ms": imports_ms,
                "observations": observations,
                "all_phases": phases.snapshot(),
                "exit_code": exit_code,
                "worker_failure": worker_failure,
                "native_text_pilot": native_pilot.evidence() if native_pilot is not None else None,
                "owned_preparation_pilot": owned_pilot.evidence() if owned_pilot is not None else None,
                "quiet_barrier_seconds": runtime._TOOLS_CALL_PREWRITE_QUIET_SECONDS,
                "worker_peak_rss_bytes": worker_peak_rss_bytes,
                "loaded_runtime_sha256": {
                    name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
                    for name, module in (
                        ("proxy/runtime_mcp.py", runtime),
                        ("mcp_tool_calls.py", calls),
                        ("proxy/framing.py", framing),
                        ("proxy/tool_catalog.py", tool_catalog),
                    )
                },
            }
        )
    )
    return exit_code


def _tree_sample(process: subprocess.Popen[str]) -> dict[str, float]:
    import psutil

    parent = psutil.Process(process.pid)
    members = [parent, *parent.children(recursive=True)]
    rss = uss = cpu = 0.0
    for member in members:
        try:
            memory = member.memory_full_info()
            rss += memory.rss
            uss += memory.uss
            times = member.cpu_times()
            cpu += times.user + times.system
        except psutil.NoSuchProcess:
            continue
    return {"rss_bytes": rss, "uss_bytes": uss, "cpu_ms": cpu * 1000, "processes": len(members)}


def run_case(
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
    owned_preparation_pilot: bool = False,
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
            "owned_preparation_pilot": owned_preparation_pilot,
            "worker_output": str(root / "worker.json"),
        }
        config_path = root / "config.json"
        config_path.write_text(json.dumps(spec))
        started = time.perf_counter_ns()
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--worker", str(config_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            bufsize=1,
            start_new_session=os.name == "posix",
        )
        assert process.stdin and process.stdout
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
            process.stdin.write(encoded)
            process.stdin.flush()

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
            memory.append(_tree_sample(process))
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
                arguments = fixture_arguments(payload_bytes, payload_kind, index)
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
                memory.append(_tree_sample(process))
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
                "owned_preparation_pilot": worker["owned_preparation_pilot"],
                "startup": {**startup, "guard_imports_ms": worker["imports_ms"]},
                "cold_first_tool_ms": timings[0],
                "client_roundtrip_ms": _summary(timings[1:]),
                "proxy_handle_ms": _summary([row["wall_ms"] for row in warm]),
                "parent_cpu_ms": _summary([row["parent_cpu_ms"] for row in warm]),
                "child_tool_cpu_ms": _summary(child["tool_cpu_ms"][1:]),
                "child_declared_wait_ms": _summary(child["declared_wait_ms"][1:]),
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
                        "wall_ms": _summary([row["phases"].get(name, {}).get("wall_ms", 0) for row in warm]),
                        "thread_cpu_ms": _summary(
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
                    "owned_preparation_pilot": failed_worker.get("owned_preparation_pilot"),
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


def run_remote_case(*, samples: int, server_delay_ms: float, payload_bytes: int = 1024) -> dict[str, Any]:
    """The shipped HTTP helper against loopback, not the draft hosted proxy."""
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from codex_plugin_scanner.guard.proxy.remote import RemoteGuardProxy

    server_waits: list[float] = []
    requests_seen: list[Any] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
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
            "remote_roundtrip_ms": _summary(wall[1:]),
            "client_thread_cpu_ms": _summary(cpu[1:]),
            "declared_server_wait_ms": _summary(server_waits[1:]),
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


def run_matrix(*, samples: int, output: Path, lock_file: Path | None = None, resume: bool = False) -> dict[str, Any]:
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
        "schema": "hol-guard-mcp-stdio-rebaseline.v1",
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
        defaults = {name: parameter.default for name, parameter in inspect.signature(run_case).parameters.items()}
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
                result = run_case(**options)
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--lock-file", type=Path)
    parser.add_argument("--catalog-size", type=int, default=100)
    parser.add_argument("--payload-bytes", type=int, default=1024)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--uncached", action="store_true")
    parser.add_argument("--child-delay-ms", type=float, default=0)
    parser.add_argument("--approval", choices=("none", "accept", "cancel", "invalidate"), default="none")
    parser.add_argument("--approval-delay-ms", type=float, default=30)
    parser.add_argument("--refresh-every", type=int, default=0)
    parser.add_argument("--compact-result", action="store_true")
    parser.add_argument("--payload-kind", choices=("ascii", "unicode"), default="ascii")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.worker:
        return _worker(args.worker)
    payload_limit = 4 * 1024 * 1024 - 512 if args.compact_result else 131072
    if not (1 <= args.catalog_size <= 1000 and 1 <= args.payload_bytes <= payload_limit and 1 <= args.samples <= 10000):
        parser.error(f"catalog must be 1..1000, payload 1..{payload_limit}, samples 1..10000")
    if not (0 <= args.child_delay_ms <= 1000 and 0 <= args.approval_delay_ms <= 1000 and args.refresh_every >= 0):
        parser.error("delays must be 0..1000 ms; refresh interval must be nonnegative")
    if args.matrix:
        if args.json is None:
            parser.error("--matrix requires --json for per-case checkpoints")
        result = run_matrix(samples=args.samples, output=args.json, lock_file=args.lock_file, resume=args.resume)
        print(json.dumps({"completed_cases": result["completed_cases"], "qualification": False}))
        return 0
    if args.resume:
        parser.error("--resume requires --matrix")
    with performance_lock(args.lock_file):
        result = run_case(
            **{
                key: value
                for key, value in vars(args).items()
                if key not in {"worker", "matrix", "json", "resume", "lock_file"}
            }
        )
    result.update(
        {
            "schema": "hol-guard-mcp-stdio-profile.v1",
            "platform": platform.system(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "percentile_estimator": "nearest_rank",
            "remote_network": "not_measured_local_stdio_only",
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
    )
    encoded = json.dumps(result, indent=2) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
