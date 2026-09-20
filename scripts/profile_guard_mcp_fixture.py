"""Shared synthetic MCP fixture and phase accounting."""

from __future__ import annotations

import functools
import json
import math
import statistics
import threading
import time
from collections import Counter
from contextlib import contextmanager
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


def summarize(values: list[float]) -> dict[str, float | int]:
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
