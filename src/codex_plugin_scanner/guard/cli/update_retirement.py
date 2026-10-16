"""Retiring the native resident before an update or a removal."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from ..native_resident_client import _state_files, retire_native_resident_for_update
from ..native_runtime import _bundled_runtime_candidate, _isolated_environment, _runtime_candidates

NATIVE_RESIDENT_RETIREMENT_ATTEMPTS = 3
NATIVE_RESIDENT_RETIREMENT_TIMEOUT_SECONDS = 6.0
NATIVE_RESIDENT_RETIREMENT_RETRY_DELAY_SECONDS = 0.5


def retire_with_retry(
    retire: Callable[[float], bool],
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Run one retirement attempt per round until it succeeds or rounds run out.

    Other agent sessions keep using the resident during an update, so one
    attempt can meet a held lease lock, a lease that is still being written,
    or a resident that a hook just started. Retirement is authenticated and
    idempotent, so a short bounded retry is safe and still fails closed.
    Unexpected errors propagate to the caller on the first attempt.
    """

    for attempt in range(NATIVE_RESIDENT_RETIREMENT_ATTEMPTS):
        if attempt:
            sleep(NATIVE_RESIDENT_RETIREMENT_RETRY_DELAY_SECONDS)
        if retire(NATIVE_RESIDENT_RETIREMENT_TIMEOUT_SECONDS):
            return True
    return False


def resident_stop_executable() -> Path:
    """The runtime binary whose resident state this home would stop.

    Forced native mode can point ``HOL_GUARD_NATIVE_BINARY`` at an override.
    Stopping the bundled binary instead looks in a different resident scope, so
    the override's resident keeps running through uninstall.
    """

    for candidate in _runtime_candidates():
        if candidate.is_file():
            return candidate
    return _bundled_runtime_candidate()


def retire_native_resident_for_home(guard_home: Path) -> bool:
    """Stop this Guard home's native resident while its runtime is still intact.

    Both callers need it gone for the same reason: the resident is a long-lived
    process holding the runtime executable. An update has to replace that file,
    and a removal has to delete it — on Windows neither is possible while the
    process is alive, so a resident left running survives the command that was
    supposed to end it.
    """

    executable = resident_stop_executable()
    # An install with no bundled binary and no resident state has nothing to
    # stop. Launching the missing file only produces a false "may keep running"
    # warning after several retries.
    if not executable.is_file() and _resident_state_absent(guard_home):
        return True
    try:
        return retire_with_retry(
            lambda timeout_seconds: retire_native_resident_for_update(
                executable=executable,
                guard_home=guard_home,
                environment=_isolated_environment(),
                timeout_seconds=timeout_seconds,
            ),
            sleep=time.sleep,
        )
    except Exception:
        # A failed preflight must leave the current installation untouched.
        return False


def _resident_state_absent(guard_home: Path) -> bool:
    state_dir = guard_home.expanduser().resolve() / "native-runtime"
    try:
        return not _state_files(state_dir, strict=True)
    except (OSError, RuntimeError):
        return False
