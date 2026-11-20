"""Start scenarios for ``scripts/check_guard_daemon_chaos.py``: a dead launch, and many starters.

* ``stale-pending-receipt``: a start is killed, with its runtime and the
  daemon it launched, after it wrote its launch receipt and before it handed
  the daemon off. The receipt is left behind naming a dead process. The next
  start must clear it and serve, with no repair command.
* ``parallel-starts``: the daemon is killed, one start begins, and while its
  launch is held mid-handoff the other starters arrive one after another,
  half through ``ensure`` and half through hook recovery, as Desktop, hooks
  and the CLI do. Every starter must get the same daemon, and exactly one new
  daemon may publish itself.
* ``mixed-runtime-starts``: the daemon is killed and starters from two
  runtime identities arrive together, each in its own process, as a
  long-lived caller that predates an in-place update does next to fresh
  ones. The first is the older runtime. Its daemon may be retired once, by a
  current starter; after that no starter may retire a daemon, so the two
  identities never take turns replacing each other's daemons. One daemon,
  carrying the current runtime's identity, must serve.

The first two scenarios hold the launch mid-handoff by stopping (``SIGSTOP``) the
daemon it launched as soon as that daemon appears: the launcher then waits
with its receipt in force, so the window does not depend on timing. Both then
check that the starters' address is the one served. Every scenario sends a
hook, which must be reviewed.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol

from codex_plugin_scanner.guard.native_daemon_manage import _lifecycle_events as lifecycle_snapshot
from codex_plugin_scanner.guard.native_daemon_manage import (
    current_guard_daemon_runtime_fingerprint,
    ensure_guard_daemon,
    load_authenticated_daemon_state,
    load_authenticated_guard_daemon_pending_launch,
    load_daemon_lifecycle_events,
    load_guard_daemon_auth_token,
    load_guard_daemon_url,
    recover_guard_daemon_after_hook_failure,
)
from scripts import check_guard_daemon_chaos as chaos
from scripts import stress_guard_daemon as stress

STARTERS = 20
MIXED_STARTERS = 10
STARTER_SPACING_SECONDS = 0.1
START_TIMEOUT_SECONDS = 60.0
RECEIPT_WAIT_SECONDS = 30.0
MAX_ERROR_CHARS = 240

# Run in a child process so that the whole start, runtime included, can be killed mid-launch.
_CHILD_START = """
import sys
from pathlib import Path
from typing import Protocol
from codex_plugin_scanner.guard.native_daemon_manage import ensure_guard_daemon
ensure_guard_daemon(Path(sys.argv[1]), home_dir=Path(sys.argv[2]), background_maintenance=False)
"""

# A start under a given runtime identity. The fingerprint cache is the identity a start sends with its
# request; an empty argument leaves it to be computed, as the current runtime's.
_CHILD_RUNTIME_START = """
import sys
from pathlib import Path
from typing import Protocol
from codex_plugin_scanner.guard import native_daemon_manage
if sys.argv[3]:
    native_daemon_manage._runtime_fingerprint_cache = sys.argv[3]
if sys.argv[5]:
    Path(sys.argv[5]).touch()
url = native_daemon_manage.ensure_guard_daemon(
    Path(sys.argv[1]), home_dir=Path(sys.argv[2]), start_timeout=float(sys.argv[4]), background_maintenance=False
)
print(url)
"""


def _wait_for(condition: Callable[[], bool], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return condition()


def _receipt(guard_home: Path) -> dict[str, object] | None:
    """The signed launch receipt in force. A cleared receipt is a tombstone, which reads as none."""

    return load_authenticated_guard_daemon_pending_launch(guard_home)


def _launched_daemon(guard_home: Path, excluded: set[int]) -> int | None:
    """Wait for a daemon this home's launch started, other than ``excluded``."""

    found: list[int] = []

    def appeared() -> bool:
        found.extend(pid for pid in chaos._daemon_pids(guard_home) if pid not in excluded)
        return bool(found)

    return found[0] if _wait_for(appeared, RECEIPT_WAIT_SECONDS) else None


def _process_tree(root_pid: int) -> list[int]:
    """``root_pid`` and every process descended from it, parents first."""

    listing = subprocess.run(("ps", "-axo", "pid=,ppid="), check=True, capture_output=True, text=True, timeout=10)
    children: dict[int, list[int]] = {}
    for line in listing.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0].isdigit() and fields[1].isdigit():
            children.setdefault(int(fields[1]), []).append(int(fields[0]))
    tree = [root_pid]
    for pid in tree:
        tree.extend(children.get(pid, ()))
    return tree


def _publishers(guard_home: Path) -> list[int]:
    """Pids that recorded ``published``, oldest first."""

    return _published(load_daemon_lifecycle_events(guard_home, limit=chaos.LIFECYCLE_EVENT_LIMIT))


def _start(guard_home: Path, home: Path) -> str:
    return ensure_guard_daemon(
        guard_home,
        home_dir=home,
        start_timeout=START_TIMEOUT_SECONDS,
        background_maintenance=False,
    )


def _recover(guard_home: Path, home: Path) -> str:
    return recover_guard_daemon_after_hook_failure(
        guard_home,
        home_dir=home,
        failure_kind="transport-failure",
        recovery_lock_timeout_seconds=START_TIMEOUT_SECONDS,
    )


def _error_text(error: BaseException) -> str:
    return f"{type(error).__name__}: {error}"[:MAX_ERROR_CHARS]


def check_serving(
    result: chaos.ScenarioResult, guard_home: Path, query: str, *, stopped: set[int], agreed: str | None
) -> None:
    """Exactly one daemon serves the home, it is the published one at the starters' address, and it reviews a hook."""

    time.sleep(chaos.SETTLE_SECONDS)
    daemons = chaos._daemon_pids(guard_home)
    result.daemons_after = len(daemons)
    if len(daemons) != 1:
        result.failures.append(f"{len(daemons)} daemons serve the home, expected exactly one")
    if stopped & set(daemons):
        result.failures.append("a stopped daemon is still running")
    state = load_authenticated_daemon_state(guard_home)
    if (state.get("pid") if state is not None else None) not in daemons:
        result.failures.append("the published daemon is not the one serving the home")
    url = load_guard_daemon_url(guard_home)
    token = load_guard_daemon_auth_token(guard_home)
    if url is None or token is None:
        result.failures.append("no daemon address or token was published")
        return
    if agreed is not None and agreed.rstrip("/") != url.rstrip("/"):
        result.failures.append("the starts answered with a daemon address that is not the one serving the home")
    kind, reason = chaos._send_hook(f"{url}/v1/hooks/pi?{query}", token)
    result.outcomes = {kind: 1}
    if kind != "reviewed":
        result.failures.append(f"the hook after the start was not reviewed: {kind} {reason}".rstrip())


def judge_starts(
    result: chaos.ScenarioResult,
    answers: list[str],
    errors: list[str],
    new_publishers: list[int],
) -> None:
    """Every starter got the same daemon, and only one new daemon published itself."""

    if errors:
        result.failures.append(f"{len(errors)} of {len(answers) + len(errors)} starts failed: {errors[0]}")
    if len(set(answers)) > 1:
        result.failures.append(f"the starts answered with {len(set(answers))} different daemons")
    if len(new_publishers) != 1:
        result.failures.append(f"{len(new_publishers)} new daemons published themselves, expected exactly one")


def _scenario(name: str, body: Callable[[chaos.ScenarioResult, Path, Path, str, int], None]) -> chaos.ScenarioResult:
    result = chaos.ScenarioResult(name=name)
    root = Path(tempfile.mkdtemp(prefix="hol-guard-chaos-"))
    try:
        _store, execution, guard_home = stress._prepare_stress_execution(root, 0)
        try:
            stress._wait_until_health_ready(execution.daemon_url)
            stress._wait_until_daemon_lifecycle_ready(guard_home)
            query = execution.endpoint.partition("?")[2]
            body(result, guard_home, root / "home", query, execution.initial_pid)
        finally:
            with contextlib.suppress(OSError):
                stress._cleanup_stress_runtime(guard_home)
    except Exception as error:  # a scenario that cannot run fails, it is not skipped
        result.failures.append(f"scenario could not run: {_error_text(error)}")
    finally:
        result.leftover_processes = chaos._kill_scenario_processes(root)
        shutil.rmtree(root, ignore_errors=True)
    result.passed = not result.failures
    return result


def _kill_daemon(result: chaos.ScenarioResult, pid: int) -> bool:
    os.kill(pid, signal.SIGKILL)
    if chaos._wait_for_exit(pid, chaos.EXIT_WAIT_SECONDS):
        return True
    result.failures.append(f"the daemon did not stop within {chaos.EXIT_WAIT_SECONDS}s of SIGKILL")
    return False


def _stale_pending_receipt(
    result: chaos.ScenarioResult, guard_home: Path, home: Path, query: str, initial_pid: int
) -> None:
    if not _kill_daemon(result, initial_pid):
        return
    launch = subprocess.Popen(
        (sys.executable, "-c", _CHILD_START, str(guard_home), str(home)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    launched: list[int] = []
    written = False
    try:
        daemon = _launched_daemon(guard_home, {initial_pid})
        if daemon is not None:
            launched.append(daemon)
            # A stopped daemon never publishes, so the launcher waits mid-handoff with its receipt in force.
            os.kill(daemon, signal.SIGSTOP)
            written = _wait_for(lambda: _receipt(guard_home) is not None, RECEIPT_WAIT_SECONDS)
    finally:
        # The start, the runtime it runs, and anything they launched, all descended from this check's child.
        doomed = _process_tree(launch.pid)
        for pid in (*doomed, *launched):
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGKILL)
        _ = launch.wait(timeout=chaos.EXIT_WAIT_SECONDS)
    if not launched:
        result.failures.append(f"the interrupted start launched no daemon within {RECEIPT_WAIT_SECONDS}s")
        return
    if not written:
        result.failures.append(f"the interrupted start wrote no launch receipt within {RECEIPT_WAIT_SECONDS}s")
        return
    if not all(chaos._wait_for_exit(pid, chaos.EXIT_WAIT_SECONDS) for pid in {*doomed, *launched}):
        result.failures.append("the interrupted start or its daemon did not stop")
        return
    if _receipt(guard_home) is None:
        result.failures.append("the interrupted start left no launch receipt behind")
        return
    started = time.monotonic()
    try:
        url = _start(guard_home, home)
    except Exception as error:  # the start under test must not fail
        result.failures.append(f"the start after the interrupted launch failed: {_error_text(error)}")
        return
    result.seconds_to_serve_again = round(time.monotonic() - started, 2)
    if _receipt(guard_home) is not None:
        result.failures.append("the start left a launch receipt behind")
    result.exit_records = chaos._exit_records(guard_home, initial_pid)
    check_serving(result, guard_home, query, stopped={initial_pid, *launched}, agreed=url)


def _parallel_starts(result: chaos.ScenarioResult, guard_home: Path, home: Path, query: str, initial_pid: int) -> None:
    if not _kill_daemon(result, initial_pid):
        return
    before = set(_publishers(guard_home))
    answers: list[str] = []
    errors: list[str] = []
    lock = threading.Lock()

    def run(index: int) -> None:
        try:
            url = (_start if index % 2 == 0 else _recover)(guard_home, home)
        except Exception as error:  # every failed start is counted and reported
            with lock:
                errors.append(_error_text(error))
            return
        with lock:
            answers.append(url)

    started = time.monotonic()
    threads = [threading.Thread(target=run, args=(index,)) for index in range(STARTERS)]
    threads[0].start()
    daemon = _launched_daemon(guard_home, {initial_pid})
    try:
        if daemon is None:
            result.failures.append(f"the first start launched no daemon within {RECEIPT_WAIT_SECONDS}s")
        else:
            # Hold the first launch mid-handoff, so every other starter arrives while its receipt is in force.
            os.kill(daemon, signal.SIGSTOP)
            if not _wait_for(lambda: _receipt(guard_home) is not None, RECEIPT_WAIT_SECONDS):
                result.failures.append(f"the first start wrote no launch receipt within {RECEIPT_WAIT_SECONDS}s")
        for thread in threads[1:]:
            thread.start()
            time.sleep(STARTER_SPACING_SECONDS)
    finally:
        if daemon is not None:
            with contextlib.suppress(OSError):
                os.kill(daemon, signal.SIGCONT)
    for thread in threads:
        thread.join()
    result.seconds_to_serve_again = round(time.monotonic() - started, 2)
    result.recoveries = len(answers)
    new_publishers = [pid for pid in _publishers(guard_home) if pid not in before]
    judge_starts(result, answers, errors, new_publishers)
    check_serving(result, guard_home, query, stopped={initial_pid}, agreed=answers[0] if answers else None)


def _journal(guard_home: Path) -> tuple[list[dict[str, object]], str]:
    """One read of the lifecycle journal and its status: ``ok`` only when every record was read."""

    return lifecycle_snapshot(guard_home, limit=chaos.LIFECYCLE_EVENT_LIMIT, incident=False)


def _published(events: list[dict[str, object]]) -> list[int]:
    """Pids that recorded ``published`` in ``events``, oldest first."""

    pids: list[int] = []
    for event in events:
        pid = event.get("pid")
        if event.get("event") == "published" and isinstance(pid, int) and pid not in pids:
            pids.append(pid)
    return pids


class _Polled(Protocol):
    def poll(self) -> int | None: ...


def _waiting_in_ensure(starters: Sequence[tuple[_Polled, Path]]) -> bool:
    """Whether a starter that got past start-up into ``ensure`` (its marker exists) is still running."""

    return any(marker.exists() and start.poll() is None for start, marker in starters)


def _retirements(events: list[dict[str, object]], pids: list[int]) -> list[int]:
    """Each ``retirement_requested`` record in ``events`` for one of ``pids``, by pid."""

    return [
        pid
        for event in events
        if event.get("event") == "retirement_requested" and isinstance(pid := event.get("pid"), int) and pid in pids
    ]


def _runtime_start(
    guard_home: Path, home: Path, fingerprint: str, entered: Path | None = None
) -> subprocess.Popen[str]:
    """Start ``ensure`` in a child; the child touches ``entered``, when given, just before it calls ``ensure``."""

    return subprocess.Popen(
        (
            sys.executable,
            "-c",
            _CHILD_RUNTIME_START,
            str(guard_home),
            str(home),
            fingerprint,
            str(START_TIMEOUT_SECONDS),
            str(entered) if entered is not None else "",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )


def _mixed_runtime_starts(
    result: chaos.ScenarioResult, guard_home: Path, home: Path, query: str, initial_pid: int
) -> None:
    current = current_guard_daemon_runtime_fingerprint()
    older = ("0" if current[0] != "0" else "1") + current[1:]
    if not _kill_daemon(result, initial_pid):
        return
    before = set(_publishers(guard_home))
    started = time.monotonic()
    starts = [_runtime_start(guard_home, home, older)]
    # The older runtime launches first. Its daemon is held mid-handoff, with its launch receipt in force, while the
    # other starters arrive, so a current starter must meet the older launch rather than find it already published.
    older_daemon = _launched_daemon(guard_home, {initial_pid})
    overlapped = False
    try:
        if older_daemon is None:
            result.failures.append(f"the older runtime's start launched no daemon within {RECEIPT_WAIT_SECONDS}s")
        else:
            os.kill(older_daemon, signal.SIGSTOP)
            if not _wait_for(lambda: _receipt(guard_home) is not None, RECEIPT_WAIT_SECONDS):
                result.failures.append(
                    f"the older runtime's start wrote no launch receipt within {RECEIPT_WAIT_SECONDS}s"
                )
        markers = home / ".chaos-current-starters"
        markers.mkdir(exist_ok=True)
        current_starts: list[tuple[subprocess.Popen[str], Path]] = []
        for index in range(1, MIXED_STARTERS):
            if index % 2 == 1:
                entered = markers / f"{index}.entered"
                starts.append(_runtime_start(guard_home, home, "", entered))
                current_starts.append((starts[-1], entered))
            else:
                starts.append(_runtime_start(guard_home, home, older))
            time.sleep(STARTER_SPACING_SECONDS)
        if older_daemon is not None:
            # Keep the older daemon frozen until every current starter is past interpreter start-up and inside
            # ensure, then a little longer. One still running after that is waiting on the held launch.
            _wait_for(
                lambda: all(marker.exists() or start.poll() is not None for start, marker in current_starts),
                RECEIPT_WAIT_SECONDS,
            )
            time.sleep(chaos.SETTLE_SECONDS)
            overlapped = _waiting_in_ensure(current_starts)
    finally:
        if older_daemon is not None:
            with contextlib.suppress(OSError):
                os.kill(older_daemon, signal.SIGCONT)

    def current_serves() -> bool:
        state = load_authenticated_daemon_state(guard_home)
        return state is not None and state.get("runtime_fingerprint") == current

    # The older starters above can all settle on the first daemon before a current one replaces it, so one more
    # older start waits for the current daemon and must leave it serving.
    if _wait_for(current_serves, START_TIMEOUT_SECONDS):
        starts.append(_runtime_start(guard_home, home, older))
    else:
        result.failures.append(f"no current-runtime daemon published within {START_TIMEOUT_SECONDS}s")
    answers: list[str] = []
    errors: list[str] = []
    for start in starts:
        try:
            stdout, stderr = start.communicate(timeout=START_TIMEOUT_SECONDS + chaos.EXIT_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            start.kill()
            _ = start.communicate()
            errors.append(f"a start did not finish within {START_TIMEOUT_SECONDS}s")
            continue
        if start.returncode == 0 and stdout.strip():
            answers.append(stdout.strip())
        else:
            errors.append((stderr.strip().splitlines() or [f"exit {start.returncode}"])[-1][:MAX_ERROR_CHARS])
    result.seconds_to_serve_again = round(time.monotonic() - started, 2)
    result.recoveries = len(answers)
    events, journal = _journal(guard_home)
    new_publishers = [pid for pid in _published(events) if pid not in before]
    state = load_authenticated_daemon_state(guard_home)
    judge_mixed_starts(
        result,
        errors,
        len(starts),
        new_publishers,
        _retirements(events, new_publishers),
        current=state is not None and state.get("runtime_fingerprint") == current,
        overlapped=overlapped,
        journal=journal,
    )
    check_serving(result, guard_home, query, stopped={initial_pid}, agreed=None)


def judge_mixed_starts(
    result: chaos.ScenarioResult,
    errors: list[str],
    starters: int,
    new_publishers: list[int],
    retired: list[int],
    *,
    current: bool,
    overlapped: bool = True,
    journal: str = "ok",
) -> None:
    """Every start served; only the older runtime's first daemon may be retired, once; the current runtime serves.

    The verdict also needs a current starter that met the older launch mid-handoff, and a journal read in full:
    a journal that could not be read proves no retirement count.
    """

    if journal != "ok":
        result.failures.append(
            f"the lifecycle journal could not be read in full ({journal}), so retirements are unproven"
        )
    if not overlapped:
        result.failures.append("no current-runtime start overlapped the older runtime's held launch")
    if errors:
        result.failures.append(f"{len(errors)} of {starters} starts failed: {errors[0]}")
    if len(new_publishers) > 2:
        result.failures.append(
            f"{len(new_publishers)} new daemons published themselves, expected the older runtime's and at most one more"
        )
    if len(retired) > 1 or any(pid != new_publishers[0] for pid in retired):
        result.failures.append(
            f"the starters retired {len(retired)} daemons: the two runtimes replaced each other's daemons"
        )
    if not current:
        result.failures.append("the daemon serving the home does not carry the current runtime's identity")


def run_start_scenarios() -> list[chaos.ScenarioResult]:
    return [
        _scenario("stale-pending-receipt", _stale_pending_receipt),
        _scenario("parallel-starts", _parallel_starts),
        _scenario("mixed-runtime-starts", _mixed_runtime_starts),
    ]
