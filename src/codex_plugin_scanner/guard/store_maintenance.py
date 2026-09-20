"""Explicit wake lookup hints for the single-owner maintenance path.

The immutable lookup grants no policy authority. The owner retains serialization
through connection finalization, including potentially late permission repair
and existing integrity callbacks. A caller timeout does not release that owner.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from .sqlite_deadline import SQLiteDeadlineExceededError, SQLiteDeadlineUnsupportedError, sqlite_maintenance_deadline


@dataclass(frozen=True, slots=True)
class StoreMaintenanceLookup:
    database_path: Path
    canonical_wake_key: str


_LOOKUP: ContextVar[StoreMaintenanceLookup | None] = ContextVar("guard_store_maintenance_lookup", default=None)


def capture_store_maintenance_lookup(
    database_path: Path, *, cancelled: threading.Event, deadline_monotonic: float
) -> StoreMaintenanceLookup:
    """Resolve inside the existing bounded owner, before taking Store locks."""
    _continue(cancelled, deadline_monotonic)
    canonical = database_path.resolve(strict=True)
    _continue(cancelled, deadline_monotonic)
    return StoreMaintenanceLookup(database_path, str(canonical))


def _continue(cancelled: threading.Event, deadline_monotonic: float) -> None:
    if cancelled.is_set() or time.monotonic() >= deadline_monotonic:
        raise SQLiteDeadlineExceededError("SQLite maintenance deadline exceeded")


@contextmanager
def store_maintenance_scope(
    database_path: Path, lookup: StoreMaintenanceLookup, *, deadline_monotonic: float
) -> Iterator[None]:
    if type(lookup) is not StoreMaintenanceLookup or lookup.database_path != database_path:
        raise SQLiteDeadlineUnsupportedError("SQLite maintenance lookup does not match the Store")
    current = _LOOKUP.get()
    if current is not None and current != lookup:
        raise SQLiteDeadlineUnsupportedError("Nested SQLite maintenance changed the Store lookup")
    with sqlite_maintenance_deadline(deadline_monotonic):
        token = _LOOKUP.set(lookup)
        try:
            yield
        finally:
            _LOOKUP.reset(token)


def maintenance_lookup(database_path: Path) -> StoreMaintenanceLookup | None:
    lookup = _LOOKUP.get()
    if lookup is not None and lookup.database_path != database_path:
        raise SQLiteDeadlineUnsupportedError("SQLite maintenance lookup does not match the Store")
    return lookup


def notify_maintenance_outbox_wake(database_path: Path, generation: int | None, *, deadline_monotonic: float) -> None:
    from .review_event_wake import review_event_wake_signal_before_deadline

    lookup = maintenance_lookup(database_path)
    if lookup is None:
        raise SQLiteDeadlineUnsupportedError("SQLite maintenance wake lookup is unavailable")
    if generation is not None:
        review_event_wake_signal_before_deadline(
            lookup.canonical_wake_key, deadline_monotonic=deadline_monotonic
        ).notify_if_outbox_changed_before_deadline(generation, deadline_monotonic=deadline_monotonic)
    if time.monotonic() >= deadline_monotonic:
        raise SQLiteDeadlineExceededError("SQLite maintenance deadline exceeded")
