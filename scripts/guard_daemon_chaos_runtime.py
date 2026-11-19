"""Runtime scenarios for ``scripts/check_guard_daemon_chaos.py``: the resident dies, and the runtime changes.

* ``resident-sigkill``: hooks keep arriving while the home's native resident
  (``serve-managed``) is killed with SIGKILL. Its supervisor must start a new
  resident, hooks must be reviewed again within ``--max-recovery-seconds``,
  and the daemon must keep serving: a resident's death never replaces it.
* ``runtime-swap``: the daemon is started by an older runtime, as one is
  after a Guard update lands under it, and hooks keep arriving while a start
  from the current runtime runs, as Desktop or the CLI does after an update.
  The old daemon must be retired with a recorded cause, hooks must be reviewed
  again within the same limit, exactly one daemon must serve, it must carry
  the current runtime's identity, and a further start must keep it.

In both, no hook may be answered without a decision and no connection may
fail outside the outage.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from codex_plugin_scanner.guard import native_daemon_manage
from codex_plugin_scanner.guard.native_daemon_manage import (
    current_guard_daemon_runtime_fingerprint,
    ensure_guard_daemon,
    load_authenticated_daemon_state,
)
from scripts import check_guard_daemon_chaos as chaos
from scripts import stress_guard_daemon as stress

START_TIMEOUT_SECONDS = 60.0
RESIDENT_COMMAND = "serve-managed"


def _resident_pids(guard_home: Path) -> list[int]:
    """Pids of ``serve-managed`` residents whose state directory is this home's."""

    state_dir = os.path.realpath(guard_home / "native-runtime")
    pids: list[int] = []
    for pid, argv in chaos._processes():
        if len(argv) < 2 or argv[1] != RESIDENT_COMMAND or "--state-dir" not in argv:
            continue
        index = argv.index("--state-dir")
        if index + 1 < len(argv) and os.path.realpath(argv[index + 1]) == state_dir:
            pids.append(pid)
    return pids


def _same_daemon(before: dict[str, object] | None, after: dict[str, object] | None) -> bool:
    """Whether two authenticated states name one daemon. A home keeps its port, so a replacement can
    publish the same URL; the pid and the state id tell daemons apart."""

    if before is None or after is None:
        return False
    return all(before.get(key) is not None and before.get(key) == after.get(key) for key in ("pid", "state_id"))


def _wait_for(condition: Callable[[], bool], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.1)
    return condition()


def _under_traffic(
    name: str,
    fault: Callable[[chaos.ScenarioResult, chaos._HookTraffic, Path, Path, int], int | None],
    *,
    max_recovery_seconds: float,
    older_runtime: bool = False,
    keeps_daemon: bool = False,
) -> chaos.ScenarioResult:
    """Start a daemon in a temporary home, send hooks, and inject ``fault``.

    ``fault`` returns the pid of the process it stopped, or ``None`` after
    recording why it could not inject the fault. With ``older_runtime`` the
    daemon is started under another runtime identity than the current one.
    With ``keeps_daemon`` the first daemon must still be the only one serving
    once the traffic and the settle period are over.
    """

    result = chaos.ScenarioResult(name=name)
    root = Path(tempfile.mkdtemp(prefix="hol-guard-chaos-"))
    try:
        if older_runtime:
            # A second Guard install cannot be built here, so the older runtime is this one with another
            # identity. The cache is the identity every start in this process sends with its request.
            current = current_guard_daemon_runtime_fingerprint()
            native_daemon_manage._runtime_fingerprint_cache = ("0" if current[0] != "0" else "1") + current[1:]
        try:
            _store, execution, guard_home = stress._prepare_stress_execution(root, 0)
        finally:
            # Recomputed on the next read: the current runtime's identity.
            native_daemon_manage._runtime_fingerprint_cache = None
        try:
            stress._wait_until_health_ready(execution.daemon_url)
            stress._wait_until_daemon_lifecycle_ready(guard_home)
            stress._stress_warmup(execution.endpoint, execution.auth_token, 8)
            traffic = chaos._HookTraffic(guard_home, root / "home", execution.endpoint.partition("?")[2])
            traffic.start()
            try:
                time.sleep(1.0)
                stopped = fault(result, traffic, guard_home, root / "home", execution.initial_pid)
                deadline = time.monotonic() + max_recovery_seconds + chaos.RECOVERY_LOCK_TIMEOUT_SECONDS
                while stopped is not None and traffic.served_again_at is None and time.monotonic() < deadline:
                    time.sleep(0.1)
                time.sleep(chaos.SETTLE_SECONDS)
            finally:
                traffic.stop()
            if stopped is not None and keeps_daemon and chaos._daemon_pids(guard_home) != [execution.initial_pid]:
                result.failures.append("the daemon was replaced after the fault, it must keep serving")
            if stopped is not None:
                chaos._check_recovered(result, traffic, guard_home, stopped, max_recovery_seconds=max_recovery_seconds)
            result.exit_records = chaos._exit_records(guard_home, execution.initial_pid)
        finally:
            with contextlib.suppress(OSError):
                stress._cleanup_stress_runtime(guard_home)
    except Exception as error:  # a scenario that cannot run fails, it is not skipped
        result.failures.append(f"scenario could not run: {type(error).__name__}: {error}")
    finally:
        result.leftover_processes = chaos._kill_scenario_processes(root)
        shutil.rmtree(root, ignore_errors=True)
    result.passed = not result.failures
    return result


def _kill_resident(
    result: chaos.ScenarioResult, traffic: chaos._HookTraffic, guard_home: Path, _home: Path, initial_pid: int
) -> int | None:
    residents = _resident_pids(guard_home)
    if len(residents) != 1:
        result.failures.append(f"{len(residents)} residents serve the home before the fault, expected exactly one")
        return None
    traffic.mark_fault()
    os.kill(residents[0], signal.SIGKILL)
    if not chaos._wait_for_exit(residents[0], chaos.EXIT_WAIT_SECONDS):
        result.failures.append(f"the resident did not stop within {chaos.EXIT_WAIT_SECONDS}s of SIGKILL")
        return None
    traffic.mark_stopped()
    if not _wait_for(lambda: bool(set(_resident_pids(guard_home)) - set(residents)), chaos.EXIT_WAIT_SECONDS):
        result.failures.append(f"no new resident served the home within {chaos.EXIT_WAIT_SECONDS}s of the kill")
    if chaos._daemon_pids(guard_home) != [initial_pid]:
        result.failures.append("the resident's death replaced the daemon")
    return residents[0]


def _start_current_runtime(
    result: chaos.ScenarioResult, traffic: chaos._HookTraffic, guard_home: Path, home: Path, initial_pid: int
) -> int | None:
    traffic.mark_fault()
    try:
        url = ensure_guard_daemon(guard_home, home_dir=home, start_timeout=START_TIMEOUT_SECONDS)
    except Exception as error:  # the start under test must not fail
        result.failures.append(f"the start from the current runtime failed: {type(error).__name__}: {error}"[:240])
        return None
    if not chaos._wait_for_exit(initial_pid, chaos.EXIT_WAIT_SECONDS):
        result.failures.append(f"the older runtime's daemon did not stop within {chaos.EXIT_WAIT_SECONDS}s")
        return None
    traffic.mark_stopped()
    records = chaos._exit_records(guard_home, initial_pid)
    if not any(chaos._names(record, "retirement_requested") for record in records):
        result.failures.append("the older runtime's daemon has no retirement_requested record")
    state = load_authenticated_daemon_state(guard_home)
    if state is None or state.get("runtime_fingerprint") != current_guard_daemon_runtime_fingerprint():
        result.failures.append("the daemon serving the home does not carry the current runtime's identity")
    try:
        again = ensure_guard_daemon(guard_home, home_dir=home, start_timeout=START_TIMEOUT_SECONDS)
    except Exception as error:  # a settled home must not refuse a start
        result.failures.append(f"a start after the swap failed: {type(error).__name__}: {error}"[:240])
    else:
        if again != url or not _same_daemon(state, load_authenticated_daemon_state(guard_home)):
            result.failures.append("a start after the swap replaced the current runtime's daemon")
    return initial_pid


def run_runtime_scenarios(*, max_recovery_seconds: float) -> list[chaos.ScenarioResult]:
    return [
        _under_traffic(
            "resident-sigkill", _kill_resident, max_recovery_seconds=max_recovery_seconds, keeps_daemon=True
        ),
        _under_traffic(
            "runtime-swap", _start_current_runtime, max_recovery_seconds=max_recovery_seconds, older_runtime=True
        ),
    ]
