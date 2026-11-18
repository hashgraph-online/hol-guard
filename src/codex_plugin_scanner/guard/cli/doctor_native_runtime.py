"""Privacy-safe native availability diagnostics, separate from hook readiness."""

from __future__ import annotations

import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any, Literal

from typing_extensions import NotRequired, TypedDict

from ..command_probes import command_probes_enabled
from ..native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY
from ..native_resident_watchdog import published_process_alive, published_resident_process
from ..resident_state_prune import probe_owner_lock
from .doctor_native_diagnosis import native_runtime_diagnosis, native_runtime_message
from .doctor_native_lifecycle import native_resident_lifecycle


class _NativeAvailabilityFields(TypedDict):
    mode: Literal["off", "shadow", "auto", "force", "unknown"]
    available: bool | None
    compatible: bool | None
    reason_code: str
    evaluation_verified: Literal[False]


class NativeAvailabilityResult(_NativeAvailabilityFields, total=False):
    message: str


_MAX_STATE_BYTES = 64 * 1024
# ``O_BINARY`` exists only on Windows and ``O_NOFOLLOW`` only where the platform
# has it; a missing flag is simply not requested.
_STATE_OPEN_FLAGS = (
    os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
)


def _read_state_json(path: Path) -> object | None:
    """Read a bounded JSON object out of resident state, or ``None``.

    Resident state lives under the Guard home, which is not a trust boundary a
    report may block on: a FIFO, a device or a symlink left at one of these
    paths would otherwise park this read forever or send it somewhere else.
    The open refuses to follow a link and never blocks, the descriptor is
    checked to be a regular file before a byte is read, and every refusal --
    a missing file, a wrong kind of file, damaged JSON -- reads the same as
    absence, because that is what a report can honestly say about it.
    """

    try:
        descriptor = os.open(path, _STATE_OPEN_FLAGS)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return json.loads(handle.read(_MAX_STATE_BYTES + 1)[:_MAX_STATE_BYTES])
    except (OSError, ValueError):
        return None
    finally:
        os.close(descriptor)


def _published_generations(state_base: Path, runtime_sha256: str) -> tuple[int, bool]:
    """Count the generations published for this runtime and say whether one is live.

    Liveness follows the same rule the resident watchdog applies: a published
    pid counts only while it is still the process the state file named, so a
    reused pid in state nobody cleaned up is not a running resident.

    Reads only the resident state files; it starts and stops nothing.
    """

    generations = 0
    live = False
    for state_path in state_base.glob("resident-v3-*/generation-*.json"):
        state = _read_state_json(state_path)
        if not isinstance(state, dict) or state.get("runtime_sha256") != runtime_sha256:
            continue
        generations += 1
        published = published_resident_process(state)
        if published is not None and published_process_alive(*published):
            live = True
    return generations, live


def _resident_owned_elsewhere(state_base: Path, runtime_sha256: str) -> bool:
    """True when a process holds the home-wide owner lock and no live resident runs this runtime.

    Reads only the lock and the resident state files; it never takes the lock
    for longer than the probe and never starts or stops a resident.
    """

    if probe_owner_lock(state_base) is not False:
        return False
    return not _published_generations(state_base, runtime_sha256)[1]


def _passive_runtime_sha256() -> str | None:
    """Hash the first valid runtime binary without running it."""

    from ..native_binary_identity import validate_native_binary
    from ..native_runtime import _runtime_candidates

    for candidate in _runtime_candidates():
        identity = validate_native_binary(candidate)
        if identity is not None:
            return identity.sha256
    return None


def _owner_busy(guard_home: Path | None, runtime_sha256: str | None) -> bool:
    return (
        guard_home is not None
        and runtime_sha256 is not None
        and _resident_owned_elsewhere(guard_home / NATIVE_RUNTIME_STATE_DIRECTORY, runtime_sha256)
    )


def _with_reason(result: NativeAvailabilityResult, reason: str) -> NativeAvailabilityResult:
    result["reason_code"] = reason
    message = native_runtime_message(reason)
    if message is not None:
        result["message"] = message
    return result


def _passive_availability(guard_home: Path | None) -> NativeAvailabilityResult:
    """Answer as far as reading the installed files allows, without running them.

    Installation is decidable passively: a runtime binary either validates
    against its recorded identity or it does not, so ``available`` is a real
    answer rather than a null one. Compatibility is not decidable this way,
    because the capabilities a build reports can only be read from the build
    itself, so it stays null and the message names that limit.
    """

    from ..native_runtime import native_mode

    runtime_sha256 = _passive_runtime_sha256()
    result: NativeAvailabilityResult = {
        # ``native_mode`` reads the environment only; it starts nothing.
        "mode": native_mode(),
        "available": runtime_sha256 is not None,
        "compatible": None,
        "reason_code": "native_status_probe_skipped",
        "evaluation_verified": False,
    }
    # The owner lock and the binary hash are read without running anything.
    if _owner_busy(guard_home, runtime_sha256):
        return _with_reason(result, "native_resident_owner_busy")
    return _with_reason(result, "native_status_probe_skipped")


def doctor_native_availability(guard_home: Path | None = None) -> NativeAvailabilityResult:
    """Report native availability, never a failure the caller did not let us check."""
    # This only queries the passive scope; its command metadata is not emitted.
    if not command_probes_enabled():
        return _passive_availability(guard_home)

    from ..native_runtime import native_runtime_status

    try:
        status = native_runtime_status()
    except (OSError, RuntimeError, ValueError):
        return {
            "mode": "unknown",
            "available": False,
            "compatible": False,
            "reason_code": "native_status_probe_failed",
            "evaluation_verified": False,
        }
    reason = status.reason
    # Native status reasons are fixed lowercase codes, not arbitrary probe text.
    if not re.fullmatch(r"[a-z0-9_.-]{1,96}", reason):
        reason = "native_status_reason_unavailable"
    result: NativeAvailabilityResult = {
        "mode": status.mode,
        "available": status.available,
        "compatible": status.compatible,
        "reason_code": reason,
        "evaluation_verified": False,
    }
    identity = status.identity
    if _owner_busy(guard_home, identity.sha256 if identity is not None else None):
        reason = "native_resident_owner_busy"
    return _with_reason(result, reason)


class NativeResidentPresence(TypedDict):
    """What the on-disk resident state says, without starting or stopping anything."""

    live: bool | None
    owner_lock_held: bool | None
    generations: int
    # The serving resident's own answer about itself, present only when one was
    # already running, the caller allowed command probes, and it answered. Its
    # absence is not a fault: it says the question went unanswered or was never
    # asked, never that the resident is unhealthy.
    serving: NotRequired[dict[str, Any] | None]


def native_resident_presence(guard_home: Path | None, runtime_sha256: str | None) -> NativeResidentPresence:
    """Report whether a resident for this runtime is already running on this account.

    Unlike the admission and health counters, which only ever describe the
    current process, this reads the files every Guard install on the account
    shares, so a separate CLI invocation sees the same answer the hook does.
    """

    if guard_home is None or runtime_sha256 is None:
        return {"live": None, "owner_lock_held": None, "generations": 0}
    state_base = guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
    owner_lock = probe_owner_lock(state_base)
    generations, live = _published_generations(state_base, runtime_sha256)
    return {
        "live": live,
        # ``probe_owner_lock`` returns None when it could not tell.
        "owner_lock_held": None if owner_lock is None else owner_lock is False,
        "generations": generations,
    }


class NativeResidentRestart(TypedDict):
    """What the shared restart budget says about respawning this runtime."""

    # True while the budget refuses the next spawn outright.
    paced: bool
    attempts: int
    retry_in_seconds: float


_RESTART_BUDGET_SCHEMA = "hol-guard-resident-restart-budget.v1"
# The runtime paces a crash loop with bounded exponential backoff, so a pause
# longer than its own maximum is not a wait this runtime wrote. Reporting the
# bound beats printing a year from a file that was damaged or forged.
_MAX_RETRY_SECONDS = 30.0
# The runtime counts restarts inside a rolling window and resets the counter
# once it closes (``resident_restart_budget.rs``), so attempts from a window
# that has already expired are not attempts "in this window".
_RESTART_WINDOW_MS = 60_000
# The runtime writes ``attempts`` as a u32 and the millisecond stamps as u64.
# JSON has no such bound, and a value past it reaches this file only from a
# damaged or forged budget; arithmetic on one raises instead of reporting.
_MAX_U32 = 2**32 - 1
_MAX_U64 = 2**64 - 1


def _budget_counter(value: object, bound: int) -> int | None:
    """A non-negative integer the runtime could have written, or ``None``.

    ``bool`` is an ``int`` in Python and none of these fields is ever written
    as one, so a boolean is as wrong here as a string.
    """

    if not isinstance(value, int) or isinstance(value, bool):
        return None
    if value < 0 or value > bound:
        return None
    return value


def native_resident_restart(guard_home: Path | None, runtime_sha256: str | None) -> NativeResidentRestart | None:
    """What the shared restart budget says, read without taking its lock.

    The budget is the one piece of circuit state every Guard process on the
    account shares. The runtime writes it when a resident dies, and while its
    pause is still running every spawn is refused with
    ``native_resident_restart_circuit_open`` -- which fails the hook closed on
    a host whose install is perfect. A report built only from installed files
    calls that host healthy, so this reads the budget too.

    The lock is deliberately left alone. A reader that waits on it competes
    with the spawn path it is describing, and a budget one write out of date
    still names the right fault. ``None`` means there is nothing to say: no
    resident of this runtime has ever been restarted in this home, or what is
    in that place is not a budget this runtime wrote.

    Reading it here rather than asking the runtime for it is the point: the
    pause exists precisely because the runtime will not start, and both callers
    promise never to launch it. Nothing is decided from what is read -- the
    budget stays the runtime's to write and to spend.
    """

    if guard_home is None or runtime_sha256 is None:
        return None
    scope = guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / f"resident-v3-{runtime_sha256[:16]}"
    budget = _read_state_json(scope / "restart-budget.json")
    if not isinstance(budget, dict) or budget.get("schema") != _RESTART_BUDGET_SCHEMA:
        return None
    attempts = _budget_counter(budget.get("attempts"), _MAX_U32)
    circuit_until_ms = _budget_counter(budget.get("circuit_until_ms"), _MAX_U64)
    window_start_ms = _budget_counter(budget.get("window_start_ms"), _MAX_U64)
    if attempts is None or circuit_until_ms is None or window_start_ms is None:
        return None
    now = time.time()
    # The runtime clears the counter on the next spawn after the window closes,
    # so reporting the stale number would name attempts that no longer count
    # against the next restart.
    if now * 1000 - window_start_ms >= _RESTART_WINDOW_MS:
        attempts = 0
    remaining = circuit_until_ms / 1000 - now
    if remaining <= 0:
        return {"paced": False, "attempts": attempts, "retry_in_seconds": 0.0}
    return {
        "paced": True,
        "attempts": attempts,
        "retry_in_seconds": round(min(remaining, _MAX_RETRY_SECONDS), 1),
    }


def native_runtime_section(
    guard_home: Path | None,
    *,
    repair: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build the ``native_runtime`` payload doctor reports and ``runtime status`` prints.

    Every field here is read from a passive probe, the installed binary's
    identity, shared resident state, or process-local counters. Nothing is evaluated and no verdict is
    produced: the native resident remains the only authority.
    """

    from .update_commands import bundled_native_runtime_report

    availability = doctor_native_availability(guard_home)
    runtime_sha256 = _passive_runtime_sha256()
    resident = native_resident_presence(guard_home, runtime_sha256)
    restart = native_resident_restart(guard_home, runtime_sha256)
    # Only ever asked of a resident that is already serving, and only where the
    # caller allows command probes: reading the runtime's feature list runs the
    # binary, which `guard runtime status` and the global doctor promise not to
    # do. The question itself rides the resident's reserved control lane, so a
    # busy resident answers it too: a published pid alone cannot tell a wedged
    # resident from a working one.
    asks_the_resident = command_probes_enabled()
    if resident["live"] is True and guard_home is not None and asks_the_resident:
        from ..native_resident_health import native_resident_health

        resident["serving"] = native_resident_health(guard_home=guard_home)
    section: dict[str, object] = {
        "availability": availability,
        "resident": resident,
    }
    # Shared, unlike the counters above: the pause the budget records refuses
    # every process on the account, so this answer is the hook's answer too.
    if restart is not None:
        section["restart"] = restart
    # A reason code is the runtime layer's word for its own decision. When that
    # decision leaves protection off, the report also has to say what is wrong
    # and what fixes it, which the code itself never does.
    # A pause and a live resident coexist: the runtime arms the next pause on
    # the same spawn it allows, so for as long as that deadline runs there can
    # be a resident serving every hook. Only a pause with nothing serving
    # leaves the host enforcing nothing, and only that is worth diagnosing.
    diagnosis = native_runtime_diagnosis(
        availability["reason_code"],
        available=availability["available"],
        restart_paced=restart is not None and restart["paced"] and resident["live"] is not True,
    )
    if diagnosis is not None:
        section["diagnosis"] = diagnosis
    bundled_runtime = bundled_native_runtime_report()
    if bundled_runtime is not None:
        section["bundled"] = bundled_runtime
    # Shared and historical, unlike every counter above: the journal covers the
    # whole account's residents over the last day, so a report written while
    # everything is up still says the install has been failing all morning.
    lifecycle = native_resident_lifecycle(guard_home)
    if lifecycle is not None:
        section["lifecycle"] = lifecycle
    # The catalog refresh and authority loops back off while they fail, so a
    # quiet daemon.log can mean "waiting to retry". This says which.
    background_loops = _background_loops(guard_home)
    if background_loops is not None:
        section["background_loops"] = background_loops
    if repair is not None:
        section["repair"] = repair
    return section


def _background_loops(guard_home: Path | None) -> list[dict[str, object]] | None:
    """Each background loop's state from the runtime's ledger, when it can say."""

    if guard_home is None:
        return None
    if not command_probes_enabled():
        return None
    from ..runtime_health.background_loop_gate import loop_status

    return loop_status(guard_home)
