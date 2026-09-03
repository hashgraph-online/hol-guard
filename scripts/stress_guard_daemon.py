#!/usr/bin/env python3
"""Exercise a fresh Guard daemon against a populated local store."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

from codex_plugin_scanner.guard.daemon.discovery import load_authenticated_daemon_state  # noqa: E402
from codex_plugin_scanner.guard.daemon.lifecycle_journal import load_daemon_lifecycle_events  # noqa: E402
from codex_plugin_scanner.guard.daemon.manager import (  # noqa: E402
    ensure_guard_daemon,
    guard_daemon_retirement_is_complete,
    load_guard_daemon_auth_token,
    retire_all_guard_daemons_for_home,
)
from codex_plugin_scanner.guard.native_runtime import native_runtime_status  # noqa: E402
from codex_plugin_scanner.guard.store import GuardStore  # noqa: E402
from scripts.native_slo_contract import clear_proof_environment, proof_environment_violations  # noqa: E402
from scripts.stress_guard_daemon_runtime import StressExecution as _StressExecution  # noqa: E402
from scripts.stress_guard_daemon_runtime import collect_batch as _collect_batch  # noqa: E402
from scripts.stress_guard_daemon_runtime import finalize_stress_runtime as _finalize_stress_runtime  # noqa: E402
from scripts.stress_guard_daemon_runtime import health_is_ready as _health_is_ready  # noqa: E402
from scripts.stress_guard_daemon_runtime import healthz_details as _healthz_details  # noqa: E402
from scripts.stress_guard_daemon_runtime import pid_is_running as _pid_is_running  # noqa: E402
from scripts.stress_guard_daemon_runtime import run_stress_batches as _run_stress_batches  # noqa: E402
from scripts.stress_guard_daemon_runtime import sample_stress_runtime as _sample_stress_runtime  # noqa: E402
from scripts.stress_guard_daemon_runtime import settle_stress_runtime as _settle_stress_runtime  # noqa: E402
from scripts.stress_guard_daemon_runtime import stabilized_process_resources as _stabilized_resources  # noqa: E402
from scripts.stress_guard_daemon_runtime import stress_request as _stress_request  # noqa: E402
from scripts.stress_guard_daemon_runtime import stress_warmup as _stress_warmup  # noqa: E402
from scripts.stress_guard_daemon_runtime import update_pid_stability as _update_pid_stability  # noqa: E402
from scripts.stress_guard_daemon_runtime import worker_capacity as _worker_capacity  # noqa: E402

_SOAK_MIN_REQUESTS = 100_000
_SOAK_MIN_RECEIPTS = 250_000
_SOAK_MAX_THREADS = 128
_SOAK_MAX_FILE_DESCRIPTORS = 512
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_WARMUP_CONCURRENCY = 64
_CAPACITY_STABILIZATION_TIMEOUT_SECONDS = 45.0
_DAEMON_SHUTDOWN_TIMEOUT_SECONDS = 20.0


@dataclass(frozen=True, slots=True)
class StressResult:
    requests: int
    receipts: int
    responses: int
    errors: int
    p95_ms: float
    max_ms: float
    health_checks: int
    health_failures: int
    pid_stable: bool
    daemon_process_count: int | None
    max_hook_latency_ms: float
    database_bytes: int
    lifecycle_events: tuple[str, ...]
    max_threads: int
    max_file_descriptors: int
    rss_baseline_bytes: int
    rss_peak_bytes: int
    rss_growth: float

    @property
    def passed(self) -> bool:
        return (
            self.responses == self.requests
            and self.errors == 0
            and self.health_checks > 0
            and self.health_failures == 0
            and self.pid_stable
            and self.daemon_process_count == 1
            and self.max_ms < self.max_hook_latency_ms
        )

    @property
    def soak_passed(self) -> bool:
        """Apply the bounded 100k soak contract to a completed run."""

        return (
            self.passed
            and self.requests >= _SOAK_MIN_REQUESTS
            and self.receipts >= _SOAK_MIN_RECEIPTS
            and self.rss_baseline_bytes > 0
            and self.rss_growth <= 0.10
            and 0 < self.max_threads <= _SOAK_MAX_THREADS
            and 0 < self.max_file_descriptors <= _SOAK_MAX_FILE_DESCRIPTORS
        )


def _count_fixture_receipts(store: GuardStore) -> int:
    """Return the committed fixture count; never trust the requested count alone."""

    connection = sqlite3.connect(store.path, timeout=30)
    try:
        row = connection.execute("select count(*) from runtime_receipts where receipt_id like 'stress-%'").fetchone()
    finally:
        connection.close()
    if not row or not isinstance(row[0], int):
        raise RuntimeError("Could not verify the stress receipt fixture.")
    return row[0]


def _stop_native_runtime(guard_home: Path) -> None:
    """Stop the exact package-bound resident before its temporary state is removed."""

    status = native_runtime_status()
    identity = status.identity
    if identity is None:
        return
    try:
        _ = subprocess.run(
            (
                str(identity.path),
                "resident-stop",
                "--state-dir",
                str(guard_home / "native-runtime"),
            ),
            check=False,
            capture_output=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        # The stress result is still evaluated from the daemon's observed
        # state. Never allow cleanup diagnostics to mask that result.
        return


def _request_graceful_daemon_stop(guard_home: Path) -> None:
    """Let the daemon close worker-owned streams before retirement fallback."""

    if os.name == "nt":
        return
    state = load_authenticated_daemon_state(guard_home)
    pid = state.get("pid") if isinstance(state, Mapping) else None
    if not isinstance(pid, int) or pid <= 0 or not _pid_is_running(pid):
        return
    try:
        os.kill(pid, signal.SIGINT)
    except OSError:
        return
    deadline = time.monotonic() + _DAEMON_SHUTDOWN_TIMEOUT_SECONDS
    while _pid_is_running(pid) and time.monotonic() < deadline:
        time.sleep(0.05)


def _cleanup_stress_runtime(guard_home: Path) -> bool:
    """Stop resident streams first, then contain the daemon and its workers."""

    _stop_native_runtime(guard_home)
    _request_graceful_daemon_stop(guard_home)
    _ = retire_all_guard_daemons_for_home(guard_home)
    return guard_daemon_retirement_is_complete(guard_home)


def seed_receipts(store: GuardStore, *, count: int) -> None:
    """Populate the high-volume receipt table in one bounded fixture transaction."""

    if count <= 0:
        return
    connection = sqlite3.connect(store.path, timeout=30)
    try:
        _ = connection.execute(
            """
            with recursive fixture(value) as (
              select 1
              union all
              select value + 1 from fixture where value < ?
            )
            insert into runtime_receipts (
              receipt_id,
              harness,
              artifact_id,
              artifact_hash,
              policy_decision,
              changed_capabilities_json,
              provenance_summary,
              timestamp
            )
            select
              printf('stress-%09d', value),
              'stress',
              'stress-artifact',
              printf('%064d', value),
              'allow',
              '[]',
              'stress-fixture',
              '2026-07-25T00:00:00+00:00'
            from fixture
            """,
            (count,),
        )
        connection.commit()
    finally:
        connection.close()


def _stabilize_full_worker_capacity(execution: _StressExecution) -> None:
    """Fill the bounded daemon worker pool before taking the RSS baseline."""

    initial_capacity = _worker_capacity(_healthz_details(execution))
    if initial_capacity is None:
        raise RuntimeError("Stress daemon did not publish authenticated worker capacity.")
    configured, initial_target, _workers, _ready, _busy = initial_capacity
    if not 1 <= configured <= _WARMUP_CONCURRENCY:
        raise RuntimeError("Stress daemon published an invalid worker capacity.")
    if not 1 <= initial_target <= configured:
        raise RuntimeError("Stress daemon published an invalid worker target.")
    deadline = time.monotonic() + _CAPACITY_STABILIZATION_TIMEOUT_SECONDS
    with ThreadPoolExecutor(max_workers=_WARMUP_CONCURRENCY) as executor:
        while time.monotonic() < deadline:
            current = _worker_capacity(_healthz_details(execution))
            if current is not None:
                current_configured, target, workers, ready, busy = current
                if (
                    current_configured == configured
                    and target >= initial_target
                    and workers == target
                    and ready == target
                    and busy == 0
                ):
                    return
            futures = [
                executor.submit(_stress_request, execution.endpoint, execution.auth_token)
                for _ in range(_WARMUP_CONCURRENCY)
            ]
            while not all(future.done() for future in futures):
                _sample_stress_runtime(execution)
                _update_pid_stability(execution, execution.guard_home)
                time.sleep(0.05)
            _collect_batch(execution, futures, retain_latencies=False)
            execution.errors.clear()
    raise RuntimeError("Stress daemon did not reach full worker capacity before the bounded deadline.")


def _initialize_stress_resources(execution: _StressExecution) -> None:
    resources = _stabilized_resources(execution.initial_pid)
    if resources is None:
        return
    execution.rss_baseline_bytes = resources[0]
    execution.rss_peak_bytes = resources[0]
    execution.max_threads = resources[1]
    execution.max_file_descriptors = resources[2]


def _prepare_stress_execution(root: Path, receipt_count: int) -> tuple[GuardStore, _StressExecution, Path]:
    guard_home = root / "guard-home"
    home = root / "home"
    workspace = root / "workspace"
    home.mkdir()
    workspace.mkdir()
    store = GuardStore(guard_home, prime_policy_integrity=False)
    seed_receipts(store, count=receipt_count)
    committed_receipts = _count_fixture_receipts(store)
    if committed_receipts != receipt_count:
        raise RuntimeError(f"Stress fixture count mismatch: requested={receipt_count} committed={committed_receipts}.")
    daemon_url = ensure_guard_daemon(guard_home, home_dir=home)
    state = load_authenticated_daemon_state(guard_home)
    auth_token = load_guard_daemon_auth_token(guard_home)
    if state is None or auth_token is None:
        raise RuntimeError("Fresh daemon did not publish authenticated state.")
    query = urllib.parse.urlencode({"guard-home": guard_home, "home": home, "workspace": workspace})
    execution = _StressExecution(
        daemon_url=daemon_url,
        endpoint=f"{daemon_url}/v1/hooks/pi?{query}",
        auth_token=auth_token,
        initial_pid=cast(int, state["pid"]),
        guard_home=guard_home,
    )
    return store, execution, guard_home


def _stress_result(
    execution: _StressExecution,
    store: GuardStore,
    guard_home: Path,
    *,
    request_count: int,
    receipt_count: int,
    max_hook_latency_ms: float,
) -> StressResult:
    latencies = sorted(execution.latencies_ms)
    p95_index = min(len(latencies) - 1, int(len(latencies) * 0.95))
    events = load_daemon_lifecycle_events(guard_home)
    return StressResult(
        requests=request_count,
        receipts=receipt_count,
        responses=len(latencies),
        errors=len(execution.errors),
        p95_ms=round(latencies[p95_index], 2) if latencies else 0.0,
        max_ms=round(max(latencies), 2) if latencies else 0.0,
        health_checks=execution.health_checks,
        health_failures=execution.health_failures,
        pid_stable=execution.pid_stable,
        daemon_process_count=execution.process_count,
        max_hook_latency_ms=max_hook_latency_ms,
        database_bytes=store.path.stat().st_size,
        lifecycle_events=tuple(str(event["event"]) for event in events),
        max_threads=execution.max_threads,
        max_file_descriptors=execution.max_file_descriptors,
        rss_baseline_bytes=execution.rss_baseline_bytes,
        rss_peak_bytes=execution.rss_peak_bytes,
        rss_growth=(
            round(max(0, execution.rss_peak_bytes - execution.rss_baseline_bytes) / execution.rss_baseline_bytes, 6)
            if execution.rss_baseline_bytes
            else 0.0
        ),
    )


def run_stress(
    *,
    request_count: int,
    receipt_count: int,
    settle_seconds: float,
    max_hook_latency_ms: float = 4_500.0,
) -> StressResult:
    if request_count <= 0:
        raise ValueError("request_count must be positive")
    if receipt_count < 0:
        raise ValueError("receipt_count must be non-negative")
    if settle_seconds < 0:
        raise ValueError("settle_seconds must be non-negative")
    if max_hook_latency_ms <= 0:
        raise ValueError("max_hook_latency_ms must be positive")

    with tempfile.TemporaryDirectory(prefix="hol-guard-daemon-stress-") as temporary:
        root = Path(temporary)
        store, execution, guard_home = _prepare_stress_execution(root, receipt_count)
        try:
            execution.health_checks += 1
            if not _health_is_ready(execution.endpoint.split("/v1/", 1)[0]):
                execution.health_failures += 1
            warmup_count = min(_WARMUP_CONCURRENCY, max(4, request_count))
            _stress_warmup(execution.endpoint, execution.auth_token, warmup_count)
            if request_count >= _SOAK_MIN_REQUESTS:
                _stabilize_full_worker_capacity(execution)
            _initialize_stress_resources(execution)
            _run_stress_batches(execution, request_count)
            _settle_stress_runtime(execution, guard_home, settle_seconds)
            _finalize_stress_runtime(execution, guard_home)
        finally:
            _ = _cleanup_stress_runtime(guard_home)
        return _stress_result(
            execution,
            store,
            guard_home,
            request_count=request_count,
            receipt_count=receipt_count,
            max_hook_latency_ms=max_hook_latency_ms,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--requests", type=int, default=50)
    _ = parser.add_argument("--receipts", type=int, default=250_000)
    _ = parser.add_argument("--settle-seconds", type=float, default=60.0)
    _ = parser.add_argument("--max-hook-latency-ms", type=float, default=4_500.0)
    _ = parser.add_argument("--enforce-soak", action="store_true")
    _ = parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.enforce_soak:
        if args.requests < _SOAK_MIN_REQUESTS or args.receipts < _SOAK_MIN_RECEIPTS:
            parser.error("--enforce-soak requires at least 100000 requests and 250000 receipts")
        _ = clear_proof_environment()
        violations = proof_environment_violations()
        if violations:
            parser.error(f"native proof environment is not clean: {', '.join(violations)}")
    result = run_stress(
        request_count=cast(int, args.requests),
        receipt_count=cast(int, args.receipts),
        settle_seconds=cast(float, args.settle_seconds),
        max_hook_latency_ms=cast(float, args.max_hook_latency_ms),
    )
    payload = {**asdict(result), "passed": result.passed, "soak_passed": result.soak_passed}
    rendered = json.dumps(payload, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.write_text(rendered + "\n", encoding="utf-8")
    return 0 if (result.soak_passed if args.enforce_soak else result.passed) else 1


if __name__ == "__main__":
    raise SystemExit(main())
