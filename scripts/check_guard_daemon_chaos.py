"""Check that the daemon recovers from injected faults and records why it stopped.

Each scenario starts a fresh daemon in its own temporary Guard home, injects
one fault, and checks the result:

* ``sigkill-during-burst``: hooks keep arriving while the daemon is killed
  with SIGKILL. Every hook that fails calls the hook recovery path
  (``daemon-manage recover``), as a harness hook does. The daemon passes when
  hooks are reviewed again within ``--max-recovery-seconds``, exactly one
  daemon serves the home afterwards, the killed daemon has an
  ``unclean_exit_detected`` record from its successor, no hook was answered
  without a decision, and no connection failed outside the outage.
* ``sigterm-is-recorded``: the daemon is sent SIGTERM. It must record
  ``exiting`` with reason ``signal_term`` before it stops, and recovery must
  serve again within the same limit with exactly one daemon.
* ``closed-stderr-launch``: the runtime is started with stdout and stderr
  pipes whose read ends are already closed, as a departed caller leaves them,
  using a subcommand that fails. It must exit with code 2, not die on a
  signal, and leave exactly one readable record in ``logs/runtime-failures.jsonl``.

CI has no Desktop app, so recovery here comes only from the hook recovery path.
"""

from __future__ import annotations

import argparse
import contextlib
import http.client
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

from codex_plugin_scanner.guard.native_daemon_manage import (  # noqa: E402
    load_authenticated_daemon_state,
    load_daemon_lifecycle_events,
    load_guard_daemon_auth_token,
    load_guard_daemon_url,
    recover_guard_daemon_after_hook_failure,
)
from scripts import check_guard_daemon_burst as burst  # noqa: E402
from scripts import guard_daemon_chaos_runtime as runtime_faults  # noqa: E402
from scripts import guard_daemon_chaos_starts as starts  # noqa: E402
from scripts import stress_guard_daemon as stress  # noqa: E402

HOOK_WORKERS = 8
HOOK_TIMEOUT_SECONDS = 5.0
RECOVERY_LOCK_TIMEOUT_SECONDS = 15.0
LIFECYCLE_EVENT_LIMIT = 200
EXIT_WAIT_SECONDS = 10.0
SETTLE_SECONDS = 1.0
MAX_REASONS = 5
MAX_REASON_CHARS = 240
# Not a review of the hook. Only connection failures are expected while the
# daemon is down; a daemon that answers must decide (no HTTP error, no empty reply).
UNDECIDED = ("unreadable", "no-decision", "fail-safe:harness_not_managed")


def _is_undecided(kind: str) -> bool:
    return kind in UNDECIDED or kind.startswith("http")


@dataclass
class ScenarioResult:
    name: str
    passed: bool = False
    seconds_to_serve_again: float | None = None
    daemons_after: int = 0
    exit_records: list[str] = field(default_factory=list)
    outcomes: dict[str, int] = field(default_factory=dict)
    fail_safe_reasons: dict[str, int] = field(default_factory=dict)
    recoveries: int = 0
    leftover_processes: int = 0
    failures: list[str] = field(default_factory=list)


@dataclass
class ChaosResult:
    scenarios: list[ScenarioResult] = field(default_factory=list)


def _processes() -> list[tuple[int, list[str]]]:
    command = ("ps", "-axo", "pid=,command=")
    listing = subprocess.run(command, check=True, capture_output=True, text=True, timeout=10).stdout
    processes: list[tuple[int, list[str]]] = []
    for line in listing.splitlines():
        pid, _, command = line.strip().partition(" ")
        if pid.isdigit():
            processes.append((int(pid), command.split()))
    return processes


def _daemon_pids(guard_home: Path) -> list[int]:
    """Pids of ``daemon-serve`` processes started for exactly this home."""

    home = str(guard_home)
    pids: list[int] = []
    for pid, argv in _processes():
        if "daemon-serve" not in argv or "--guard-home" not in argv:
            continue
        index = argv.index("--guard-home")
        if index + 1 < len(argv) and argv[index + 1] == home:
            pids.append(pid)
    return pids


def _scenario_processes(root: Path) -> list[int]:
    """Pids naming this scenario's fresh ``mkdtemp`` root, which only this check's processes can name."""

    own = os.getpid()
    marker = str(root)
    return [pid for pid, argv in _processes() if pid != own and any(marker in arg for arg in argv)]


def _kill_scenario_processes(root: Path) -> int:
    pids = _scenario_processes(root)
    for pid in pids:
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGKILL)
    return len(pids)


def _wait_for_exit(pid: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not stress._pid_is_running(pid):
            return True
        time.sleep(0.05)
    return not stress._pid_is_running(pid)


def _events_for(guard_home: Path, pid: int) -> list[dict[str, object]]:
    events = load_daemon_lifecycle_events(guard_home, limit=LIFECYCLE_EVENT_LIMIT)
    return [event for event in events if event.get("pid") == pid]


def _exit_records(guard_home: Path, pid: int) -> list[str]:
    records: list[str] = []
    for event in _events_for(guard_home, pid):
        name = str(event.get("event", ""))
        if name in ("exiting", "unclean_exit_detected", "retirement_requested", "death_observed"):
            reason = event.get("reason")
            records.append(f"{name}:{reason}" if reason else name)
    return records


def _send_hook(endpoint: str, token: str) -> tuple[str, str]:
    """The burst check's reply kind, and the reason a fail-safe reply gave."""

    request = urllib.request.Request(
        endpoint,
        data=burst.HOOK_BODY,
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=HOOK_TIMEOUT_SECONDS) as response:
            body = response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        body = error.read()
        status = error.code
    except urllib.error.URLError as error:
        return f"connection:{type(error.reason).__name__}", ""
    except (OSError, http.client.HTTPException) as error:
        return f"connection:{type(error).__name__}", ""
    if status != 200:
        return f"http{status}", ""
    kind = burst._reply_kind(body)
    if kind == "reviewed":
        return kind, ""
    try:
        reply = json.loads(body)
    except ValueError:
        return kind, ""
    if not isinstance(reply, dict):
        return kind, ""
    reason = reply.get("reason")
    reason_text = str(reason)[:MAX_REASON_CHARS] if reason else ""
    decision = reply.get("decision")
    if not isinstance(decision, str) or not decision:
        return "no-decision", reason_text
    return kind, reason_text


def _names(record: str, expected: str) -> bool:
    """``expected`` is an event name, or an event name and reason."""

    return record == expected or record.startswith(f"{expected}:")


class _HookTraffic:
    """Hooks sent by several workers until stopped; a failed hook recovers.

    Each worker reads the current endpoint and token before every hook, so it
    follows the daemon a recovery starts.
    """

    def __init__(self, guard_home: Path, home: Path, query: str) -> None:
        self.guard_home = guard_home
        self.home = home
        self.query = query
        self.outcomes: Counter[str] = Counter()
        self.recoveries = 0
        self.fail_safe_reasons: Counter[str] = Counter()
        self.recovery_errors: Counter[str] = Counter()
        self.stray_failures: Counter[str] = Counter()
        self.fault_at: float | None = None
        self.stopped_at: float | None = None
        self.served_again_at: float | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads = [threading.Thread(target=self._work) for _ in range(HOOK_WORKERS)]

    def start(self) -> None:
        for thread in self._threads:
            thread.start()

    def stop(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join()

    def mark_fault(self) -> None:
        with self._lock:
            self.fault_at = time.monotonic()

    def mark_stopped(self) -> None:
        """Only a hook sent after the faulted daemon exits counts as recovery."""
        with self._lock:
            self.stopped_at = time.monotonic()

    def _target(self) -> tuple[str, str] | None:
        url = load_guard_daemon_url(self.guard_home)
        token = load_guard_daemon_auth_token(self.guard_home)
        if url is None or token is None:
            return None
        return f"{url}/v1/hooks/pi?{self.query}", token

    def _recover(self) -> None:
        try:
            _ = recover_guard_daemon_after_hook_failure(
                self.guard_home,
                home_dir=self.home,
                failure_kind="transport-failure",
                recovery_lock_timeout_seconds=RECOVERY_LOCK_TIMEOUT_SECONDS,
            )
        except Exception as error:  # every failure is counted and reported
            with self._lock:
                self.recovery_errors[type(error).__name__] += 1
        with self._lock:
            self.recoveries += 1

    def _work(self) -> None:
        while not self._stop.is_set():
            target = self._target()
            if target is None:
                self._recover()
                continue
            sent_at = time.monotonic()
            kind, reason = _send_hook(target[0], target[1])
            with self._lock:
                self.outcomes[kind] += 1
                if reason:
                    self.fail_safe_reasons[reason] += 1
                after_stop = self.stopped_at is not None and sent_at > self.stopped_at
                if kind == "reviewed" and after_stop and self.served_again_at is None:
                    self.served_again_at = time.monotonic()
                # Only the outage may break a connection: not before the fault or after serving again.
                served = self.served_again_at
                outside = self.fault_at is None or (served is not None and sent_at > served)
                if kind.startswith("connection:") and outside:
                    self.stray_failures[kind] += 1
            if kind.startswith("connection:"):
                self._recover()


def _check_recovered(
    result: ScenarioResult,
    traffic: _HookTraffic,
    guard_home: Path,
    stopped_pid: int,
    *,
    max_recovery_seconds: float,
) -> None:
    fault_at = traffic.fault_at
    served_at = traffic.served_again_at
    if fault_at is None or served_at is None:
        result.failures.append("no hook was reviewed after the faulted daemon stopped")
    else:
        result.seconds_to_serve_again = round(served_at - fault_at, 2)
        if result.seconds_to_serve_again > max_recovery_seconds:
            result.failures.append(
                f"hooks were reviewed again after {result.seconds_to_serve_again}s, limit {max_recovery_seconds}s",
            )
    result.outcomes = dict(traffic.outcomes)
    result.fail_safe_reasons = dict(traffic.fail_safe_reasons.most_common(MAX_REASONS))
    result.recoveries = traffic.recoveries
    undecided = {kind: count for kind, count in traffic.outcomes.items() if _is_undecided(kind)}
    if undecided:
        result.failures.append(f"hooks were answered without a decision: {undecided}")
    if traffic.recovery_errors:
        result.failures.append(f"hook recovery failed: {dict(traffic.recovery_errors)}")
    if traffic.stray_failures:
        result.failures.append(f"connections failed outside the outage: {dict(traffic.stray_failures)}")
    time.sleep(SETTLE_SECONDS)
    daemons = _daemon_pids(guard_home)
    result.daemons_after = len(daemons)
    if len(daemons) != 1:
        result.failures.append(f"{len(daemons)} daemons serve the home after recovery, expected exactly one")
    if stopped_pid in daemons:
        result.failures.append("the stopped daemon is still running")
    state = load_authenticated_daemon_state(guard_home)
    published = state.get("pid") if state is not None else None
    if published not in daemons:
        result.failures.append("the published daemon is not the one serving the home")


def _run_fault(
    name: str,
    fault: Callable[[int], None],
    expected_records: tuple[str, ...],
    *,
    max_recovery_seconds: float,
) -> ScenarioResult:
    result = ScenarioResult(name=name)
    root = Path(tempfile.mkdtemp(prefix="hol-guard-chaos-"))
    try:
        _store, execution, guard_home = stress._prepare_stress_execution(root, 0)
        try:
            stress._wait_until_health_ready(execution.daemon_url)
            stress._wait_until_daemon_lifecycle_ready(guard_home)
            stress._stress_warmup(execution.endpoint, execution.auth_token, 8)
            query = execution.endpoint.partition("?")[2]
            traffic = _HookTraffic(guard_home, root / "home", query)
            traffic.start()
            try:
                time.sleep(1.0)
                traffic.mark_fault()
                fault(execution.initial_pid)
                if _wait_for_exit(execution.initial_pid, EXIT_WAIT_SECONDS):
                    traffic.mark_stopped()
                else:
                    result.failures.append(f"the daemon did not stop within {EXIT_WAIT_SECONDS}s of the fault")
                deadline = time.monotonic() + max_recovery_seconds + RECOVERY_LOCK_TIMEOUT_SECONDS
                while traffic.served_again_at is None and time.monotonic() < deadline:
                    time.sleep(0.1)
                time.sleep(SETTLE_SECONDS)
            finally:
                traffic.stop()
            _check_recovered(
                result,
                traffic,
                guard_home,
                execution.initial_pid,
                max_recovery_seconds=max_recovery_seconds,
            )
            result.exit_records = _exit_records(guard_home, execution.initial_pid)
            if not any(_names(record, expected) for record in result.exit_records for expected in expected_records):
                result.failures.append(
                    f"the stopped daemon has no {' or '.join(expected_records)} record: {result.exit_records}",
                )
        finally:
            with contextlib.suppress(OSError):
                stress._cleanup_stress_runtime(guard_home)
    except Exception as error:  # a scenario that cannot run fails, it is not skipped
        result.failures.append(f"scenario could not run: {type(error).__name__}: {error}")
    finally:
        result.leftover_processes = _kill_scenario_processes(root)
        shutil.rmtree(root, ignore_errors=True)
    result.passed = not result.failures
    return result


def _sigkill(pid: int) -> None:
    os.kill(pid, signal.SIGKILL)


def _sigterm(pid: int) -> None:
    os.kill(pid, signal.SIGTERM)


def run_closed_stderr_launch(runtime: Path) -> ScenarioResult:
    result = ScenarioResult(name="closed-stderr-launch")
    try:
        _closed_stderr_launch(runtime, result)
    except Exception as error:  # a scenario that cannot run fails, it is not skipped
        result.failures.append(f"scenario could not run: {type(error).__name__}: {error}")
    result.passed = not result.failures
    return result


def _failure_code(line: str) -> str:
    try:
        record = json.loads(line)
    except ValueError:
        return "unreadable"
    code = record.get("code") if isinstance(record, dict) else None
    return code if isinstance(code, str) and code else "unreadable"


def _closed_stderr_launch(runtime: Path, result: ScenarioResult) -> None:
    with tempfile.TemporaryDirectory(prefix="hol-guard-chaos-") as temporary:
        guard_home = Path(temporary)
        reader, writer = os.pipe()
        os.close(reader)
        try:
            completed = subprocess.run(
                (str(runtime), "not-a-runtime-command", "--guard-home", str(guard_home)),
                stdin=subprocess.DEVNULL,
                stdout=writer,
                stderr=writer,
                env={"PATH": os.environ.get("PATH", "")},
                check=False,
                timeout=30,
            )
        finally:
            os.close(writer)
        if completed.returncode < 0:
            result.failures.append(f"the runtime died on signal {-completed.returncode}")
        elif completed.returncode != 2:
            result.failures.append(f"the runtime exited with {completed.returncode}, expected 2")
        log = guard_home / "logs" / "runtime-failures.jsonl"
        try:
            lines = [line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
        except OSError:
            lines = []
        result.exit_records = [_failure_code(line) for line in lines]
        if len(lines) != 1:
            result.failures.append(f"{len(lines)} failed-launch records, expected exactly one")
        elif result.exit_records == ["unreadable"]:
            result.failures.append("the failed-launch record has no readable code")


def run_chaos(runtime: Path, *, max_recovery_seconds: float) -> ChaosResult:
    result = ChaosResult()
    result.scenarios.append(
        _run_fault(
            "sigkill-during-burst",
            _sigkill,
            # The launcher finding the daemon gone, or the next daemon finding no record: whichever is first.
            ("death_observed", "unclean_exit_detected"),
            max_recovery_seconds=max_recovery_seconds,
        ),
    )
    result.scenarios.append(
        _run_fault(
            "sigterm-is-recorded",
            _sigterm,
            ("exiting:signal_term",),
            max_recovery_seconds=max_recovery_seconds,
        ),
    )
    result.scenarios.append(run_closed_stderr_launch(runtime))
    result.scenarios.extend(starts.run_start_scenarios())
    result.scenarios.extend(runtime_faults.run_runtime_scenarios(max_recovery_seconds=max_recovery_seconds))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    _ = parser.add_argument("--runtime", type=Path, default=os.environ.get("HOL_GUARD_NATIVE_BINARY"))
    _ = parser.add_argument("--max-recovery-seconds", type=float, default=10.0)
    _ = parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.runtime is None:
        parser.error("--runtime or HOL_GUARD_NATIVE_BINARY is required")
    # Scenarios start and recover daemons through the environment's runtime: pin the one under test.
    args.runtime = args.runtime.resolve(strict=True)
    os.environ["HOL_GUARD_NATIVE_BINARY"] = str(args.runtime)
    result = run_chaos(args.runtime, max_recovery_seconds=args.max_recovery_seconds)
    payload = json.dumps(asdict(result), indent=2)
    print(payload)
    if args.json:
        args.json.write_text(payload + "\n", encoding="utf-8")
    failed = False
    for scenario in result.scenarios:
        for failure in scenario.failures:
            failed = True
            print(f"FAIL {scenario.name}: {failure}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
