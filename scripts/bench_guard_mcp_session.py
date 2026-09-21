#!/usr/bin/env python3
"""Time synthetic MCP tool calls through the real stdio proxy and child.

The boundary includes policy lookup, catalog identity, forwarding, child wait,
and receipt persistence. It excludes the outer installed CLI bootstrap. The
per-call result must prove successful forwarding; aggregate output has no raw
arguments, filesystem paths, or payloads. Run matching baseline and candidate
packages in alternating blocks on the same host before comparing results.
"""

from __future__ import annotations

import argparse
import json
import math
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy
from codex_plugin_scanner.guard.store import GuardStore

_CHILD = """
import json, sys
count = int(sys.argv[1])
for line in sys.stdin:
    message = json.loads(line)
    method = message.get('method')
    if method == 'tools/list':
        result = {'tools': [{'name': 'echo_' + str(i), 'description': 'Echo text',
                  'inputSchema': {'type': 'object', 'properties': {'text': {'type': 'string'}}},
                  'outputSchema': {'type': 'object'}, 'annotations': {'readOnlyHint': True}}
                 for i in range(count)]}
    elif method == 'tools/call':
        result = {'content': [{'type': 'text', 'text': 'ok'}]}
    else:
        result = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}},
                  'serverInfo': {'name': 'synthetic', 'version': '1'}}
    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': result}), flush=True)
"""


class TimedProxy(CodexMcpGuardProxy):
    samples_ms: list[float]
    cpu_ms: list[float]

    def _handle_message(self, **kwargs: Any) -> Any:
        started, cpu_started = time.perf_counter(), time.process_time()
        response, event = super()._handle_message(**kwargs)
        elapsed, cpu = time.perf_counter() - started, time.process_time() - cpu_started
        if kwargs["message"].get("method") == "tools/call":
            if not isinstance(response, dict) or response.get("result", {}).get("content") != [
                {"type": "text", "text": "ok"}
            ]:
                raise RuntimeError("mcp_benchmark_forwarding_failed")
            self.samples_ms.append(elapsed * 1000)
            self.cpu_ms.append(cpu * 1000)
        return response, event


def _summary(values: list[float]) -> dict[str, int | float]:
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "p50_ms": statistics.median(ordered),
        "p95_ms": ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)],
        "p99_ms": ordered[max(0, math.ceil(len(ordered) * 0.99) - 1)],
        "max_ms": ordered[-1],
    }


def run(*, catalog_size: int, samples: int) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="guard-mcp-bench-") as temporary:
        root = Path(temporary)
        home, workspace, guard_home = root / "home", root / "workspace", root / "guard"
        for path in (home, workspace, guard_home):
            path.mkdir()
        context = HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)
        proxy = TimedProxy(
            server_name="synthetic",
            command=[sys.executable, "-u", "-c", _CHILD, str(catalog_size)],
            context=context,
            store=GuardStore(guard_home),
            config=GuardConfig(guard_home=guard_home, workspace=workspace),
            source_scope="project",
            config_path=str(workspace / ".mcp.json"),
        )
        proxy.samples_ms, proxy.cpu_ms = [], []
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            *[
                {"jsonrpc": "2.0", "id": i + 3, "method": "tools/call", "params": {"name": "echo_0", "arguments": {}}}
                for i in range(samples + 1)
            ],
        ]
        started = time.perf_counter()
        proxy.run_session(messages)
        total_ms = (time.perf_counter() - started) * 1000
        if len(proxy.samples_ms) != samples + 1:
            raise RuntimeError("mcp_benchmark_sample_count_failed")
        return {
            "schema": "hol-guard-mcp-session-benchmark.v1",
            "boundary": "MCP_PROXY_SESSION",
            "qualification": False,
            "platform": platform.system(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "catalog_size": catalog_size,
            "warm": _summary(proxy.samples_ms[1:]),
            "parent_cpu": _summary(proxy.cpu_ms[1:]),
            "cold_first_tool_ms": proxy.samples_ms[0],
            "session_total_ms": total_ms,
            "errors": 0,
            "percentile_estimator": "nearest-rank",
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog-size", type=int, default=100)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if not 1 <= args.catalog_size <= 10000 or not 1 <= args.samples <= 10000:
        parser.error("catalog size and samples must be in 1..10000")
    result = run(catalog_size=args.catalog_size, samples=args.samples)
    encoded = json.dumps(result, indent=2) + "\n"
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
