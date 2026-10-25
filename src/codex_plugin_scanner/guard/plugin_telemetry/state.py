"""Consent and the device secret for plugin install counts.

Both live in the Guard home. Counts are off until the user runs
``hol-guard telemetry plugins on``. The device secret only keys the weekly
counting hashes and never leaves the machine; turning counts off deletes it,
so turning them on again starts a new, unlinkable series.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from ..mdm.file_lock import acquire_file_lock, release_file_lock

SETTINGS_FILE = "plugin-telemetry.json"
SECRET_FILE = "plugin-telemetry.key"
LOCK_FILE = "plugin-telemetry.lock"
_SECRET_BYTES = 32
_LOCK_WAIT_SECONDS = 10.0
_LOCK_POLL_SECONDS = 0.05


class TelemetryStateBusyError(RuntimeError):
    """Another Guard process held the plugin telemetry state for too long."""


@contextmanager
def state_lock(guard_home: Path) -> Iterator[None]:
    """Serialize consent, key and week changes across the CLI and the daemon.

    The lock is held only while the state files change, never across a
    network call, so ``off`` never waits on a send in flight.
    """

    guard_home.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    with open(guard_home / LOCK_FILE, "a+b") as handle:
        while True:
            try:
                acquire_file_lock(handle)
                break
            except OSError as error:
                if time.monotonic() >= deadline:
                    raise TelemetryStateBusyError("plugin telemetry state is busy") from error
                time.sleep(_LOCK_POLL_SECONDS)
        try:
            yield
        finally:
            release_file_lock(handle)


@dataclass(frozen=True)
class TelemetryState:
    enabled: bool
    last_week: str | None


def read_state(guard_home: Path) -> TelemetryState:
    try:
        payload = json.loads((guard_home / SETTINGS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return TelemetryState(enabled=False, last_week=None)
    if not isinstance(payload, dict):
        return TelemetryState(enabled=False, last_week=None)
    last_week = payload.get("lastWeek")
    return TelemetryState(
        enabled=payload.get("enabled") is True,
        last_week=last_week if isinstance(last_week, str) else None,
    )


def write_state(guard_home: Path, state: TelemetryState) -> None:
    guard_home.mkdir(parents=True, exist_ok=True)
    target = guard_home / SETTINGS_FILE
    temporary = target.with_name(f"{SETTINGS_FILE}.tmp")
    temporary.write_text(
        json.dumps({"enabled": state.enabled, "lastWeek": state.last_week}, sort_keys=True),
        encoding="utf-8",
    )
    os.replace(temporary, target)


def read_secret(guard_home: Path) -> str | None:
    """The hex device secret, or None when there is no valid one."""

    try:
        value = (guard_home / SECRET_FILE).read_text(encoding="ascii").strip()
    except (OSError, ValueError):
        return None
    if len(value) != _SECRET_BYTES * 2 or any(character not in "0123456789abcdef" for character in value):
        return None
    return value


def ensure_secret(guard_home: Path) -> str:
    """The device secret, created with owner-only permissions when missing.

    Callers hold :func:`state_lock`. Only an invalid key file is replaced; if
    another process creates the key first, its key is used.
    """

    existing = read_secret(guard_home)
    if existing is not None:
        return existing
    guard_home.mkdir(parents=True, exist_ok=True)
    target = guard_home / SECRET_FILE
    if target.exists():
        target.unlink()
    value = secrets.token_hex(_SECRET_BYTES)
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        winner = read_secret(guard_home)
        if winner is None:
            raise
        return winner
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(value)
    return value


def delete_secret(guard_home: Path) -> None:
    (guard_home / SECRET_FILE).unlink(missing_ok=True)


def turn_on(guard_home: Path) -> None:
    with state_lock(guard_home):
        ensure_secret(guard_home)
        write_state(guard_home, TelemetryState(enabled=True, last_week=read_state(guard_home).last_week))


def turn_off(guard_home: Path) -> None:
    with state_lock(guard_home):
        write_state(guard_home, TelemetryState(enabled=False, last_week=None))
        delete_secret(guard_home)


def claim_week(guard_home: Path, week: str, *, only_if_due: bool) -> TelemetryState | None:
    """Record ``week`` as sent before sending, so two senders never both send it.

    Returns the state before the claim, or None when counts are off (or, with
    ``only_if_due``, when this week was already claimed).
    """

    with state_lock(guard_home):
        state = read_state(guard_home)
        if not state.enabled or (only_if_due and state.last_week == week):
            return None
        write_state(guard_home, TelemetryState(enabled=True, last_week=week))
        return state


def release_week(guard_home: Path, week: str, previous: TelemetryState) -> None:
    """Undo a claim after a failed send, unless consent or the week changed since."""

    with state_lock(guard_home):
        state = read_state(guard_home)
        if state.enabled and state.last_week == week:
            write_state(guard_home, TelemetryState(enabled=True, last_week=previous.last_week))
