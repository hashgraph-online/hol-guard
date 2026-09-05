"""Bounded synthetic ingress helpers for the installed native SLO proof."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from codex_plugin_scanner.guard.daemon.hook_process_capacity import process_tree_rss_bytes
from scripts.native_slo_contract import SAFE_ROUTE_NAMES

_MAX_CASES = 2_048
_SIZE_BYTES = {"1k": 1 * 1024, "250k": 250 * 1024, "1m": 1 * 1024 * 1024, "5m": 5 * 1024 * 1024}
# The daemon reserves 250 ms of an explicit hook hint for transport and uses
# a conservative 750 ms service estimate until it has warm samples. Keep the
# synthetic ingress budget above that admission floor so the SLO measures the
# native decision rather than an intentionally expired scheduler admission.
_SLO_REMAINING_MS = 4_000
_OWNERSHIP_CONTRACT = Path(__file__).resolve().parents[1] / "docs/guard/contracts/hook-data-plane-ownership.v2.json"


@dataclass(frozen=True, slots=True)
class Observation:
    harness: str
    event: str
    size_class: str
    latency_ms: float
    route: str
    allowed: bool
    # True only when the adapter returned an explicit bounded-capacity result;
    # a generic native fail-safe must not be mistaken for accepted overload.
    overloaded: bool = False


@dataclass(frozen=True, slots=True)
class ProcessResources:
    """Current resident resources for one process tree."""

    rss_bytes: int
    threads: int
    file_descriptors: int


def _single_process_rss_bytes(pid: int) -> int:
    if os.name == "nt":
        return 0
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ("/bin/ps", "-p", str(pid), "-o", "rss="),
                capture_output=True,
                text=True,
                check=False,
                timeout=1,
            )
            value = result.stdout.strip().split()
            return int(value[0]) * 1024 if value else 0
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return 0
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                value = line.split()[1]
                return int(value) * 1024
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def _process_threads(pid: int) -> int:
    if os.name == "nt":
        return 0
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ("/bin/ps", "-M", "-p", str(pid)),
                capture_output=True,
                text=True,
                check=False,
                timeout=1,
            )
            lines = result.stdout.splitlines()
            return max(0, len(lines) - 1)
        except (OSError, subprocess.TimeoutExpired):
            return 0
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("Threads:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def _process_file_descriptors(pid: int) -> int:
    if os.name == "nt":
        return 0
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ("/usr/sbin/lsof", "-p", str(pid), "-Fn"),
                capture_output=True,
                text=True,
                check=False,
                timeout=1,
            )
            return sum(line.startswith("n") for line in result.stdout.splitlines()) if result.returncode == 0 else 0
        except (OSError, subprocess.TimeoutExpired):
            return 0
    try:
        return len(list(Path(f"/proc/{pid}/fd").iterdir()))
    except OSError:
        return 0


def process_resources(pid: int | None = None) -> ProcessResources | None:
    """Measure current RSS (including descendants), threads, and descriptors."""

    resolved_pid = os.getpid() if pid is None else pid
    if resolved_pid <= 0:
        return None
    tree_rss_bytes = process_tree_rss_bytes((resolved_pid,))
    if tree_rss_bytes is None or tree_rss_bytes <= 0:
        # Linux soak evidence must account for every daemon worker.  A root
        # process reading is not an equivalent measurement, so report the
        # resource as unavailable when process-tree enumeration is missing.
        # Other supported POSIX platforms retain their existing root fallback.
        if sys.platform.startswith("linux"):
            return None
        rss_bytes = _single_process_rss_bytes(resolved_pid)
    else:
        rss_bytes = tree_rss_bytes
    threads = _process_threads(resolved_pid)
    file_descriptors = _process_file_descriptors(resolved_pid)
    if rss_bytes <= 0:
        return None
    return ProcessResources(rss_bytes, threads, file_descriptors)


def route_matrix() -> tuple[tuple[str, str], ...]:
    payload = json.loads(_OWNERSHIP_CONTRACT.read_text(encoding="utf-8"))
    routes = payload.get("harness_routes") if isinstance(payload, dict) else None
    if not isinstance(routes, dict):
        raise RuntimeError("native_installed_slo_failed: harness route contract missing")
    selected: list[tuple[str, str]] = []
    for harness, route in sorted(routes.items()):
        if not isinstance(harness, str) or not isinstance(route, dict):
            continue
        for event, key in (("PreToolUse", "pre_tool_use"), ("PostToolUse", "post_tool_use")):
            route_name = route.get(key)
            if isinstance(route_name, str) and route_name.startswith("installed_"):
                selected.append((harness, event))
    if not selected:
        raise RuntimeError("native_installed_slo_failed: installed route corpus is empty")
    return tuple(selected[:_MAX_CASES])


def payload(event: str, size_class: str = "1k") -> dict[str, object]:
    if event == "PreToolUse":
        return {
            "hook_event_name": event,
            "tool_name": "Bash",
            "tool_input": {"command": "printf guard"},
            "guard_remaining_ms": _SLO_REMAINING_MS,
        }
    target = _SIZE_BYTES[size_class]
    text = "const guard_value = 1;\n" * max(1, target // len("const guard_value = 1;\n"))
    return {
        "hook_event_name": event,
        "tool_name": "Read",
        "tool_response": [{"type": "text", "text": text}],
        "guard_remaining_ms": _SLO_REMAINING_MS,
    }


def source_payloads(workspace: Path) -> dict[str, Mapping[str, object]]:
    """Create bounded local source fixtures for the large content classes."""

    unit = "const guard_value = 1;\n"
    payloads: dict[str, Mapping[str, object]] = {}
    for size_class, target in (("250k", 250 * 1024), ("1m", 1 * 1024 * 1024), ("5m", 5 * 1024 * 1024)):
        content = (unit * ((target + len(unit) - 1) // len(unit))).encode("utf-8")[:target]
        path = workspace / f"native-slo-{size_class}.txt"
        path.write_bytes(content)
        payloads[size_class] = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(path)},
            "guard_remaining_ms": _SLO_REMAINING_MS,
            "guard_source_ref": {
                "version": 1,
                "path": str(path),
                "output_sha256": hashlib.sha256(content).hexdigest(),
                "output_chars": len(content.decode("utf-8")),
                "tool_input_path": str(path),
            },
        }
    return payloads


def process_rss_bytes(pid: int | None = None) -> int:
    """Return current process-tree RSS in bytes, never historical max RSS."""

    resources = process_resources(pid)
    return resources.rss_bytes if resources is not None else 0


def route_counts(metrics: Mapping[str, object]) -> Counter[str]:
    raw = metrics.get("routes")
    if not isinstance(raw, Mapping):
        return Counter()
    return Counter({str(key): int(value) for key, value in raw.items() if isinstance(value, int)})


def route_delta(before: Counter[str], after: Counter[str]) -> str:
    changed = [route for route in SAFE_ROUTE_NAMES if after[route] > before[route]]
    return changed[0] if len(changed) == 1 else "native_fail_safe"


def is_allowed(event: str, response: Mapping[str, object]) -> bool:
    if response.get("decision") == "allow":
        return response.get("model_output_action", "allow_original") != "block"
    if event == "PreToolUse":
        specific = response.get("hookSpecificOutput")
        return isinstance(specific, Mapping) and specific.get("permissionDecision") == "allow"
    specific = response.get("hookSpecificOutput")
    return isinstance(specific, Mapping) and response.get("policy_action", "allow") in {"allow", "warn"}


__all__ = [
    "Observation",
    "ProcessResources",
    "is_allowed",
    "payload",
    "process_resources",
    "process_rss_bytes",
    "route_counts",
    "route_delta",
    "route_matrix",
    "source_payloads",
]
