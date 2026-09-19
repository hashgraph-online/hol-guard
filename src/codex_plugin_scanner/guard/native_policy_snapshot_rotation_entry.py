"""Bound the public installation operation before lazy implementation setup."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .native_policy_control_transport import run_native_control_worker
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .sqlite_tuning import sqlite_connect_timeout_seconds


@dataclass(frozen=True, slots=True)
class _RotationOutcome:
    value: dict[str, str] | None = None
    error: Exception | None = None


def rotate_installation_with_native_retirement(
    *,
    guard_home: Path,
    database_path: Path,
    read_existing_key: Callable[[], tuple[bytes | None, str | None]],
    mutation: Callable[[str], dict[str, str]],
) -> dict[str, str]:
    """Compose the existing caller SQLite budget into one new aggregate bound."""
    began = time.monotonic()
    budget = sqlite_connect_timeout_seconds()
    if not math.isfinite(budget) or budget <= 0:
        raise NativePolicySnapshotError("native_policy_snapshot_control_deadline_exceeded")
    deadline = began + budget

    def run(cancelled: threading.Event) -> _RotationOutcome:
        try:
            from .native_policy_snapshot_rotation import _rotate_owned, _RotationInputs

            inputs = _RotationInputs(guard_home, database_path, read_existing_key)
            return _RotationOutcome(value=_rotate_owned(inputs, mutation, cancelled=cancelled, deadline=deadline))
        except Exception as error:
            return _RotationOutcome(error=error)

    outcome = run_native_control_worker(run, deadline_monotonic=deadline)
    if outcome is None:
        reason = "deadline_exceeded" if time.monotonic() >= deadline else "failed"
        raise NativePolicySnapshotError("native_policy_snapshot_control_" + reason)
    if outcome.error is not None:
        raise outcome.error
    if outcome.value is None:
        raise NativePolicySnapshotError("native_policy_snapshot_control_failed")
    return outcome.value
