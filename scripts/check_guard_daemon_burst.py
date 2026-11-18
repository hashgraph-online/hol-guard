"""Check that a daemon stays responsive under a burst of concurrent hooks.

Starts a fresh daemon, sends ``--hooks`` hook requests at once while polling
``/healthz``, then sends one more hook. The daemon passes when:

* every hook gets an HTTP answer, with no refused or timed-out connection;
* every answer arrives within ``--max-hook-seconds``, so a hook the daemon
  could not review is told so near its deadline instead of hanging;
* ``/healthz`` keeps answering within ``--max-health-seconds`` during the burst;
* the hook sent after the burst is reviewed normally.

A burst larger than the review capacity is expected to shed load: hooks may
be answered with a capacity or deadline fail-safe. What must not happen is a
daemon that stops answering.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import http.client
import json
import resource
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

from scripts import stress_guard_daemon as stress  # noqa: E402

SHED_CODES = (
    # Capacity and deadline fail-safes are expected under an intentional burst.
    "daemon_hook_queue_capacity",
    "daemon_hook_deadline_exhausted",
    "daemon_hook_queue_bytes",
    "native_hook_worker_unavailable",
    "native_review_deadline_exceeded",
)
HOOK_BODY = json.dumps(
    {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "echo burst"}}
).encode()


@dataclass
class BurstResult:
    hooks: int
    wall_seconds: float = 0.0
    outcomes: dict[str, int] = field(default_factory=dict)
    hook_max_seconds: float = 0.0
    hook_p50_seconds: float = 0.0
    health_samples: int = 0
    health_failures: int = 0
    health_max_seconds: float = 0.0
    after_burst: str = ""
    after_burst_seconds: float = 0.0
    failures: list[str] = field(default_factory=list)


def _send_hook(endpoint: str, token: str, timeout: float) -> tuple[str, float]:
    request = urllib.request.Request(
        endpoint,
        data=HOOK_BODY,
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            kind = _reply_kind(response.read()) if response.status == 200 else f"http{response.status}"
    except urllib.error.HTTPError as error:
        kind = f"http{error.code}"
    except urllib.error.URLError as error:
        kind = f"connection:{type(error.reason).__name__}"
    except (OSError, http.client.HTTPException) as error:
        kind = f"connection:{type(error).__name__}"
    return kind, time.monotonic() - started


def _reply_kind(body: bytes) -> str:
    """``reviewed`` for a normal allow of the burst's harmless command, the
    shed code for a capacity fail-safe, and ``fail-safe:<code>`` otherwise."""

    try:
        reply = json.loads(body)
    except ValueError:
        return "unreadable"
    if not isinstance(reply, dict):
        return "unreadable"
    code = reply.get("reason_code")
    if code in SHED_CODES:
        return str(code)
    if reply.get("decision") == "allow" and code != "harness_not_managed":
        return "reviewed"
    return f"fail-safe:{code}"


def _poll_health(url: str, stop: threading.Event, samples: list[tuple[float, bool]]) -> None:
    while not stop.is_set():
        started = time.monotonic()
        try:
            with urllib.request.urlopen(f"{url}/healthz", timeout=15) as response:
                response.read()
                ok = response.status == 200
        except (urllib.error.URLError, OSError, http.client.HTTPException):
            ok = False
        samples.append((time.monotonic() - started, ok))
        time.sleep(0.05)


def run_burst(hooks: int, *, max_hook_seconds: float, max_health_seconds: float) -> BurstResult:
    result = BurstResult(hooks=hooks)
    with tempfile.TemporaryDirectory(prefix="hol-guard-burst-", ignore_cleanup_errors=True) as temporary:
        _store, execution, guard_home = stress._prepare_stress_execution(Path(temporary), 0)
        try:
            stress._wait_until_health_ready(execution.daemon_url)
            stress._wait_until_daemon_lifecycle_ready(guard_home)
            stress._stress_warmup(execution.endpoint, execution.auth_token, 8)
            outcomes: collections.Counter[str] = collections.Counter()
            latencies: list[float] = []
            lock = threading.Lock()
            start = threading.Barrier(hooks)
            client_timeout = max_hook_seconds * 3

            def hook() -> None:
                try:
                    start.wait()
                except threading.BrokenBarrierError:
                    return
                kind, elapsed = _send_hook(execution.endpoint, execution.auth_token, client_timeout)
                with lock:
                    outcomes[kind] += 1
                    latencies.append(elapsed)

            stop = threading.Event()
            samples: list[tuple[float, bool]] = []
            prober = threading.Thread(target=_poll_health, args=(execution.daemon_url, stop, samples))
            prober.start()
            threads = [threading.Thread(target=hook) for _ in range(hooks)]
            started = time.monotonic()
            launched: list[threading.Thread] = []
            try:
                for thread in threads:
                    thread.start()
                    launched.append(thread)
            except BaseException:
                start.abort()
                raise
            finally:
                for thread in launched:
                    thread.join()
                stop.set()
                prober.join()
            result.wall_seconds = round(time.monotonic() - started, 2)
            result.after_burst, after_elapsed = _send_hook(execution.endpoint, execution.auth_token, client_timeout)
            result.after_burst_seconds = round(after_elapsed, 2)
        finally:
            with contextlib.suppress(OSError):
                stress._cleanup_stress_runtime(guard_home)
    latencies.sort()
    result.outcomes = dict(outcomes)
    result.hook_max_seconds = round(latencies[-1], 2)
    result.hook_p50_seconds = round(latencies[len(latencies) // 2], 2)
    result.health_samples = len(samples)
    result.health_failures = sum(1 for _elapsed, ok in samples if not ok)
    result.health_max_seconds = round(max((elapsed for elapsed, _ok in samples), default=0.0), 2)
    answered = sum(count for kind, count in outcomes.items() if kind == "reviewed" or kind in SHED_CODES)
    if answered != hooks:
        unanswered = {kind: count for kind, count in outcomes.items() if kind != "reviewed" and kind not in SHED_CODES}
        result.failures.append(f"{hooks - answered} hooks got no review or fail-safe answer: {unanswered}")
    if result.hook_max_seconds > max_hook_seconds:
        result.failures.append(f"slowest hook took {result.hook_max_seconds}s, limit {max_hook_seconds}s")
    if not samples:
        result.failures.append("no health check finished during the burst")
    if result.health_failures:
        result.failures.append(f"{result.health_failures} of {result.health_samples} health checks failed")
    if result.health_max_seconds > max_health_seconds:
        result.failures.append(f"slowest health check took {result.health_max_seconds}s, limit {max_health_seconds}s")
    if result.after_burst != "reviewed":
        result.failures.append(f"the hook after the burst was answered {result.after_burst!r}, not reviewed")
    if result.after_burst_seconds > max_hook_seconds:
        result.failures.append(
            f"the hook after the burst took {result.after_burst_seconds}s, limit {max_hook_seconds}s",
        )
    return result


def _raise_open_file_limit(needed: int) -> None:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = min(hard, max(soft, needed))
    if wanted > soft:
        resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    _ = parser.add_argument("--hooks", type=int, default=1000)
    _ = parser.add_argument("--max-hook-seconds", type=float, default=10.0)
    _ = parser.add_argument("--max-health-seconds", type=float, default=5.0)
    _ = parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    _raise_open_file_limit(args.hooks * 4 + 256)
    result = run_burst(
        args.hooks,
        max_hook_seconds=args.max_hook_seconds,
        max_health_seconds=args.max_health_seconds,
    )
    payload = json.dumps(asdict(result), indent=2)
    print(payload)
    if args.json:
        args.json.write_text(payload + "\n", encoding="utf-8")
    for failure in result.failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if result.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
