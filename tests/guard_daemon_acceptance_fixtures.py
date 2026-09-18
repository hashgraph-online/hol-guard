"""Deterministic workload fixtures for the daemon admission acceptance gate."""

from __future__ import annotations

import http.client
import importlib
import json
import os
import resource
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict, cast
from unittest.mock import patch

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.coverage_ci import under_coverage_scale

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "guard-daemon-acceptance" / "workloads.json"


class ClientSpec(TypedDict):
    harness: str
    client: str
    requests: int
    concurrency: int


class WorkloadSpec(TypedDict):
    id: str
    clients: list[ClientSpec]
    secret_stride: int


class SoakSpec(TypedDict):
    id: str
    duration_seconds: int
    steady_requests_per_second: int
    burst_concurrency: int
    opt_in: bool


@dataclass(frozen=True, slots=True)
class WorkloadResult:
    fixture_id: str
    requests: int
    routine_allowed: int
    secrets_denied: int
    capacity_denials: int
    generic_failures: int
    pid_stable: bool
    workers_stable: bool
    queue_bounded: bool
    rss_growth_bytes: int
    p95_ms: float
    p99_ms: float
    browser_launches: int
    inbox_requests: int
    dispatch_counts: dict[str, int]
    failure_reasons: dict[str, int]
    transport_counts: dict[str, int]
    failure_stages: dict[str, int]


def load_correctness_workloads() -> tuple[WorkloadSpec, ...]:
    payload = cast(dict[str, object], json.loads(FIXTURE_PATH.read_text(encoding="utf-8")))
    return tuple(cast(list[WorkloadSpec], payload["correctness"]))


def load_soak_workload() -> WorkloadSpec:
    payload = cast(dict[str, object], json.loads(FIXTURE_PATH.read_text(encoding="utf-8")))
    soak = cast(SoakSpec, payload["soak"])
    return {
        "id": soak["id"],
        "clients": [
            {
                "harness": "pi",
                "client": "pi-soak",
                "requests": soak["duration_seconds"] * soak["steady_requests_per_second"],
                "concurrency": soak["burst_concurrency"],
            }
        ],
        "secret_stride": 10,
    }


def load_adversarial_nodeids() -> tuple[str, ...]:
    payload = cast(dict[str, object], json.loads(FIXTURE_PATH.read_text(encoding="utf-8")))
    return tuple(cast(list[str], payload["adversarial_nodeids"]))


def assert_adversarial_nodeids_resolve() -> None:
    for nodeid in load_adversarial_nodeids():
        module_path, separator, function_name = nodeid.partition("::")
        if not separator or not module_path.startswith("tests/") or not module_path.endswith(".py"):
            raise AssertionError(f"invalid adversarial nodeid: {nodeid}")
        module_name = module_path.removesuffix(".py").replace("/", ".")
        module = importlib.import_module(module_name)
        if not hasattr(module, function_name):
            raise AssertionError(f"missing adversarial nodeid: {nodeid}")


def run_clients(
    clients: list[ClientSpec], review: Callable[[str, str, int], None], *, request_timeout_seconds: float
) -> None:
    """Retain each client's declared concurrency throughout a mixed workload."""

    def lane(client: ClientSpec, first: int) -> None:
        for index in range(first, client["requests"], client["concurrency"]):
            review(client["harness"], client["client"], index)

    workers = sum(min(client["concurrency"], client["requests"]) for client in clients)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            (executor.submit(lane, client, first), len(range(first, client["requests"], client["concurrency"])))
            for client in clients
            for first in range(min(client["concurrency"], client["requests"]))
        ]
        for future, requests in futures:
            future.result(timeout=request_timeout_seconds * requests)


def run_workload(spec: WorkloadSpec, *, root: Path) -> WorkloadResult:
    """Run a bounded workload through authenticated production hook endpoints."""

    request_count = sum(client["requests"] for client in spec["clients"])
    guard_home = root / "guard-home"
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=0)
    daemon.start()
    daemon_state = cast(
        dict[str, object],
        json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8")),
    )
    target = max(1, int(daemon._server.hook_process_runner.stats()["target"]))
    if not daemon._server.hook_process_runner.wait_for_capacity(
        minimum_workers=target,
        timeout_seconds=15,
    ):
        raise RuntimeError("production hook workers did not become ready")
    initial_pid = os.getpid()
    initial_workers = threading.active_count()
    initial_rss = _rss_bytes()
    initial_inbox = len(store.list_approval_requests(status=None, limit=None))
    outcomes: Counter[str] = Counter()
    dispatch: Counter[str] = Counter()
    failure_reasons: Counter[str] = Counter()
    failure_stages: Counter[str] = Counter()
    transport_counts: Counter[str] = Counter()
    latencies_ms: list[float] = []
    lock = threading.Lock()
    remaining_ms = str(int(10_000 * under_coverage_scale(3.0)))
    review_timeout_seconds = 30 * under_coverage_scale(3.0)

    def record_transport(name: str) -> None:
        with lock:
            transport_counts[name] += 1

    def retry_admission(status: int, reason: str, *, lane: str, attempt: int, deadline: float) -> bool:
        # parse_request refuses this request before hook dispatch. Never replay
        # an evaluated response, a generic 503, or an ambiguous transport fault.
        if not is_pre_dispatch_refusal(status, reason):
            return False
        record_transport(f"{lane}_admission_refusals")
        if attempt != 0 or time.monotonic() + 0.025 >= deadline:
            return False
        record_transport(f"{lane}_admission_retries")
        time.sleep(0.025)
        return True

    def review(harness: str, client: str, index: int) -> None:
        started = time.monotonic()
        transport_deadline = started + 12
        secret_request = index % spec["secret_stride"] == 0
        output = (
            "token=sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE" if secret_request else "routine documentation"
        )
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"path": "src/secret.txt" if secret_request else "docs/readme.md"},
            "tool_response": [{"type": "text", "text": output}],
            "stdout": output,
            "session_id": client,
            "guard_remaining_ms": int(remaining_ms),
        }
        query = (
            f"guard-home={urllib.parse.quote(str(guard_home))}&"
            f"home={urllib.parse.quote(str(root))}&"
            f"workspace={urllib.parse.quote(str(workspace))}"
        )
        failure_stage = "request_setup"
        try:
            if harness in {"codex", "claude-code"}:
                result = None
                for attempt in range(2):
                    failure_stage = "identity_challenge"
                    nonce = secrets.token_hex(32)
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", daemon.port, timeout=max(0.001, transport_deadline - time.monotonic())
                    )
                    try:
                        record_transport("challenge_attempts")
                        connection.request(
                            "POST",
                            "/v1/daemon/identity-challenge",
                            body=json.dumps(
                                {
                                    "protocol_version": 1,
                                    "nonce": nonce,
                                    "state_id": daemon_state["state_id"],
                                    "hook_event": "PostToolUse",
                                }
                            ).encode(),
                            headers={"Content-Type": "application/json", "Connection": "keep-alive"},
                        )
                        challenge_response = connection.getresponse()
                        challenge_body = challenge_response.read()
                        if retry_admission(
                            challenge_response.status,
                            challenge_response.reason,
                            lane="challenge",
                            attempt=attempt,
                            deadline=transport_deadline,
                        ):
                            continue
                        if challenge_response.status != 200:
                            raise RuntimeError(f"challenge-status-{challenge_response.status}")
                        challenge = cast(dict[str, object], json.loads(challenge_body))
                        failure_stage = "hook_exchange"
                        if connection.sock is not None:
                            connection.sock.settimeout(max(0.001, transport_deadline - time.monotonic()))
                        record_transport("hook_attempts")
                        connection.request(
                            "POST",
                            f"/v1/hooks/{harness}?{query}",
                            body=json.dumps(payload).encode(),
                            headers={
                                "Connection": "close",
                                "Content-Type": "application/json",
                                "X-Guard-Token": daemon._server.auth_token,
                                "X-Guard-Daemon-Nonce": nonce,
                                "X-Guard-Daemon-Proof": str(challenge["proof"]),
                                "X-Guard-Remaining-Ms": remaining_ms,
                            },
                        )
                        hook_response = connection.getresponse()
                        hook_body = hook_response.read()
                        if retry_admission(
                            hook_response.status,
                            hook_response.reason,
                            lane="hook",
                            attempt=attempt,
                            deadline=transport_deadline,
                        ):
                            continue
                        if hook_response.status != 200:
                            raise RuntimeError(f"hook-status-{hook_response.status}")
                        result = cast(dict[str, object], json.loads(hook_body))
                        break
                    finally:
                        connection.close()
                if result is None:
                    raise RuntimeError("codex-review-unavailable")
            else:
                failure_stage = "hook_exchange"
                request = urllib.request.Request(
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/{harness}?{query}",
                    data=json.dumps(payload).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "X-Guard-Token": daemon._server.auth_token,
                        "X-Guard-Remaining-Ms": remaining_ms,
                    },
                    method="POST",
                )
                for attempt in range(2):
                    record_transport("hook_attempts")
                    try:
                        with urllib.request.urlopen(
                            request, timeout=max(0.001, transport_deadline - time.monotonic())
                        ) as response:
                            result = cast(dict[str, object], json.loads(response.read()))
                        break
                    except urllib.error.HTTPError as error:
                        error.close()
                        if not retry_admission(
                            error.code,
                            str(error.reason),
                            lane="hook",
                            attempt=attempt,
                            deadline=transport_deadline,
                        ):
                            raise
            failure_stage = "response_classification"
            blocked = _response_blocks_action(result)
            reason_code = result.get("reason_code")
            outcome = (
                str(reason_code)
                if isinstance(reason_code, str) and reason_code.startswith("daemon_hook_")
                else "secret_denied"
                if secret_request and blocked
                else "routine_allowed"
                if not secret_request and not blocked
                else "generic_failure"
            )
            with lock:
                dispatch[harness] += 1
                if outcome == "generic_failure" or outcome.startswith("daemon_hook_"):
                    failure_reasons[str(result.get("reason_code", result.get("decision", "unexpected-response")))] += 1
        except Exception as error:
            outcome = "generic_failure"
            with lock:
                error_key = (
                    f"HTTPError:{error.code}"
                    if isinstance(error, urllib.error.HTTPError)
                    else f"{type(error).__name__}:{error}"
                )
                failure_reasons[error_key] += 1
                failure_stages[failure_stage] += 1
        elapsed_ms = (time.monotonic() - started) * 1000
        with lock:
            outcomes[outcome] += 1
            latencies_ms.append(elapsed_ms)

    browser_calls: list[str] = []
    try:
        with patch(
            "codex_plugin_scanner.guard.daemon.server.open_browser_url",
            side_effect=lambda url: browser_calls.append(str(url)) or False,
        ):
            run_clients(spec["clients"], review, request_timeout_seconds=review_timeout_seconds)
        worker_stats = daemon._server.hook_process_runner.stats()
        scheduler_stats = daemon._server.runtime_hook_scheduler.stats()
        final_inbox = len(store.list_approval_requests(status=None, limit=None))
    finally:
        daemon.stop()

    ordered = sorted(latencies_ms)
    return WorkloadResult(
        fixture_id=spec["id"],
        requests=request_count,
        routine_allowed=outcomes["routine_allowed"],
        secrets_denied=outcomes["secret_denied"],
        capacity_denials=sum(value for key, value in outcomes.items() if key.startswith("daemon_hook_")),
        generic_failures=outcomes["generic_failure"],
        pid_stable=os.getpid() == initial_pid,
        workers_stable=(
            worker_stats["workers"] <= worker_stats["configured"]
            and worker_stats["failures"] == 0
            and worker_stats["restarts"] == 0
            and threading.active_count() <= initial_workers + 1
        ),
        queue_bounded=(
            scheduler_stats["queued"] <= scheduler_stats["queued_limit"] and scheduler_stats["retained_bytes"] == 0
        ),
        rss_growth_bytes=max(0, _rss_bytes() - initial_rss),
        p95_ms=_percentile(ordered, 0.95),
        p99_ms=_percentile(ordered, 0.99),
        browser_launches=len(browser_calls),
        inbox_requests=max(0, final_inbox - initial_inbox),
        dispatch_counts=dict(dispatch),
        failure_reasons=dict(failure_reasons),
        transport_counts=dict(transport_counts),
        failure_stages=dict(failure_stages),
    )


def is_pre_dispatch_refusal(status: int, reason: str) -> bool:
    return status == 503 and reason == "Guard daemon request capacity reached"


def _response_blocks_action(result: dict[str, object]) -> bool:
    if result.get("decision") in {"deny", "block", "ask"} or result.get("continue") is False:
        return True
    hook_output = result.get("hookSpecificOutput")
    if not isinstance(hook_output, dict):
        return False
    if hook_output.get("permissionDecision") in {"deny", "block", "ask"}:
        return True
    decision = hook_output.get("decision")
    return isinstance(decision, dict) and decision.get("behavior") in {"deny", "block", "ask"}


def _percentile(ordered: list[float], fraction: float) -> float:
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(len(ordered) * fraction)))
    return round(ordered[index], 3)


def _rss_bytes() -> int:
    maximum_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(maximum_rss if os.uname().sysname == "Darwin" else maximum_rss * 1024)
