"""Runtime transport and resource helpers for the bounded daemon stress run."""

from __future__ import annotations

import http.client
import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass, field
from http.client import HTTPResponse
from pathlib import Path
from typing import Literal, cast

from codex_plugin_scanner.guard.daemon.discovery import load_authenticated_daemon_state
from codex_plugin_scanner.guard.daemon.manager import guard_daemon_process_count
from scripts.native_slo_adapter import process_resources

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_HEALTH_PROBE_ATTEMPTS = 2
_HEALTH_PROBE_TOTAL_TIMEOUT_SECONDS = 1.0
_HEALTH_PROBE_ATTEMPT_TIMEOUT_SECONDS = _HEALTH_PROBE_TOTAL_TIMEOUT_SECONDS / _HEALTH_PROBE_ATTEMPTS


@dataclass
class StressExecution:
    """Mutable aggregate state for one stress run."""

    daemon_url: str
    endpoint: str
    auth_token: str
    initial_pid: int
    guard_home: Path
    latencies_ms: list[float] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    health_checks: int = 0
    health_failures: int = 0
    transient_health_failures: int = 0
    pid_stable: bool = True
    process_count: int | None = None
    rss_baseline_bytes: int = 0
    rss_peak_bytes: int = 0
    max_threads: int = 0
    max_file_descriptors: int = 0


def process_tree_resources(pid: int) -> tuple[int, int, int] | None:
    """Read current aggregate process-tree resources without retaining command data."""

    resources = process_resources(pid)
    if resources is None:
        return None
    return resources.rss_bytes, resources.threads, resources.file_descriptors


def wait_for_process_resources(pid: int, *, timeout_seconds: float = 2.0) -> tuple[int, int, int] | None:
    """Wait briefly for a newly spawned daemon to publish measurable resources."""

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        resources = process_tree_resources(pid)
        if resources is not None:
            return resources
        time.sleep(0.01)
    return process_tree_resources(pid)


def stabilized_process_resources(pid: int) -> tuple[int, int, int] | None:
    """Capture a post-warmup ceiling so lazy worker startup is not counted as a leak."""

    samples: list[tuple[int, int, int]] = []
    for _ in range(3):
        resources = wait_for_process_resources(pid)
        if resources is not None:
            samples.append(resources)
        time.sleep(0.1)
    if not samples:
        return None
    return (
        max(sample[0] for sample in samples),
        max(sample[1] for sample in samples),
        max(sample[2] for sample in samples),
    )


def healthz_details(execution: StressExecution) -> Mapping[str, object] | None:
    """Read the authenticated bounded capacity report for one stress daemon."""

    request = urllib.request.Request(
        f"{execution.daemon_url}/v1/healthz/details",
        headers={"X-Guard-Token": execution.auth_token},
        method="GET",
    )
    try:
        with cast(HTTPResponse, urllib.request.urlopen(request, timeout=1)) as response:
            body = response.read(_MAX_RESPONSE_BYTES + 1)
    except (OSError, urllib.error.URLError):
        return None
    if len(body) > _MAX_RESPONSE_BYTES:
        return None
    try:
        payload = cast(object, json.loads(body.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return cast(Mapping[str, object], payload) if isinstance(payload, Mapping) else None


def worker_capacity(details: Mapping[str, object] | None) -> tuple[int, int, int, int, int] | None:
    """Extract only bounded worker-capacity counts from the health report."""

    if details is None:
        return None
    workers = details.get("hook_workers")
    if not isinstance(workers, Mapping):
        return None
    values = tuple(workers.get(name) for name in ("configured", "target", "workers", "ready", "busy"))
    if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in values):
        return None
    return cast(tuple[int, int, int, int, int], values)


def stress_request(endpoint: str, auth_token: str) -> float:
    """Issue one bounded synthetic hook request and return its latency."""

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo stress"},
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": auth_token},
        method="POST",
    )
    started = time.monotonic()
    with cast(HTTPResponse, urllib.request.urlopen(request, timeout=6)) as response:
        body = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(body) > _MAX_RESPONSE_BYTES:
        raise RuntimeError("Hook response exceeded the bounded stress limit.")
    payload = cast(object, json.loads(body.decode("utf-8")))
    if not isinstance(payload, dict):
        raise RuntimeError("Hook response was not an object.")
    return (time.monotonic() - started) * 1000


def stress_warmup(endpoint: str, auth_token: str, count: int) -> None:
    """Run a bounded request wave before the measured stress batches."""

    with ThreadPoolExecutor(max_workers=count) as executor:
        futures = [executor.submit(stress_request, endpoint, auth_token) for _ in range(count)]
        for future in futures:
            future.result(timeout=6)


def record_resources(execution: StressExecution, resources: tuple[int, int, int] | None) -> None:
    if resources is None:
        return
    execution.rss_peak_bytes = max(execution.rss_peak_bytes, resources[0])
    execution.max_threads = max(execution.max_threads, resources[1])
    execution.max_file_descriptors = max(execution.max_file_descriptors, resources[2])


HealthProbeStatus = Literal["ready", "transient", "unhealthy"]


def health_probe_status(daemon_url: str) -> HealthProbeStatus:
    """Classify one liveness probe without leaking diagnostic text.

    Explicit unhealthy or malformed payloads are authoritative. Only transport
    and retryable admission failures may consume the bounded retry budget.
    """

    deadline = time.monotonic() + _HEALTH_PROBE_TOTAL_TIMEOUT_SECONDS
    for attempt in range(_HEALTH_PROBE_ATTEMPTS):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "transient"
        timeout = min(_HEALTH_PROBE_ATTEMPT_TIMEOUT_SECONDS, remaining)
        try:
            with cast(
                HTTPResponse,
                urllib.request.urlopen(f"{daemon_url}/healthz", timeout=timeout),
            ) as response:
                if getattr(response, "status", 200) != 200:
                    return "unhealthy"
                body = response.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            with suppress(Exception):
                _ = exc.read()
            # Bounded admission answers busy hook batches with retryable 503.
            if exc.code == 503:
                if attempt + 1 < _HEALTH_PROBE_ATTEMPTS:
                    continue
                return "transient"
            return "unhealthy"
        except (http.client.IncompleteRead, OSError, urllib.error.URLError):
            if attempt + 1 < _HEALTH_PROBE_ATTEMPTS:
                continue
            return "transient"
        except Exception:
            return "unhealthy"

        if not isinstance(body, bytes) or len(body) > _MAX_RESPONSE_BYTES:
            return "unhealthy"
        try:
            payload = cast(object, json.loads(body.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return "unhealthy"
        if not isinstance(payload, dict) or cast(dict[object, object], payload).get("ok") is not True:
            return "unhealthy"
        if time.monotonic() > deadline:
            return "transient"
        return "ready"
    return "transient"


def health_is_ready(daemon_url: str) -> bool:
    """Return true when the daemon published an authoritative healthy payload."""

    return health_probe_status(daemon_url) == "ready"


def pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def sample_stress_runtime(execution: StressExecution) -> None:
    execution.health_checks += 1
    status = health_probe_status(execution.daemon_url)
    if status == "unhealthy":
        execution.health_failures += 1
    elif status == "transient":
        execution.transient_health_failures += 1
    record_resources(execution, process_tree_resources(execution.initial_pid))


def collect_batch(
    execution: StressExecution,
    futures: list[Future[float]],
    *,
    retain_latencies: bool = True,
) -> None:
    for future in futures:
        try:
            latency = future.result()
            if retain_latencies:
                execution.latencies_ms.append(latency)
        except Exception as error:
            execution.errors.append(type(error).__name__)


def run_stress_batches(execution: StressExecution, request_count: int) -> None:
    max_workers = min(request_count, 32)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for start in range(0, request_count, max_workers):
            futures = [
                executor.submit(stress_request, execution.endpoint, execution.auth_token)
                for _ in range(min(max_workers, request_count - start))
            ]
            while not all(future.done() for future in futures):
                sample_stress_runtime(execution)
                time.sleep(0.05)
            collect_batch(execution, futures)


def update_pid_stability(execution: StressExecution, guard_home: Path) -> None:
    state = load_authenticated_daemon_state(guard_home)
    execution.pid_stable = (
        execution.pid_stable
        and state is not None
        and state.get("pid") == execution.initial_pid
        and pid_is_running(execution.initial_pid)
    )


def settle_stress_runtime(execution: StressExecution, guard_home: Path, settle_seconds: float) -> None:
    deadline = time.monotonic() + settle_seconds
    while time.monotonic() < deadline:
        sample_stress_runtime(execution)
        update_pid_stability(execution, guard_home)
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))


def finalize_stress_runtime(execution: StressExecution, guard_home: Path) -> None:
    sample_stress_runtime(execution)
    update_pid_stability(execution, guard_home)
    execution.process_count = guard_daemon_process_count(guard_home)
    record_resources(execution, process_tree_resources(execution.initial_pid))


__all__ = [
    "StressExecution",
    "collect_batch",
    "finalize_stress_runtime",
    "health_is_ready",
    "health_probe_status",
    "healthz_details",
    "pid_is_running",
    "process_tree_resources",
    "record_resources",
    "run_stress_batches",
    "sample_stress_runtime",
    "settle_stress_runtime",
    "stabilized_process_resources",
    "stress_request",
    "stress_warmup",
    "update_pid_stability",
    "wait_for_process_resources",
    "worker_capacity",
]
