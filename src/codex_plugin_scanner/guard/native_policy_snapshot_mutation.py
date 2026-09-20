"""Bounded setup and publisher invalidation for off-hook maintenance."""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .native_policy_control_transport import run_native_control_worker
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .sqlite_deadline import sqlite_maintenance_deadline

if TYPE_CHECKING:
    from .store import GuardStore


@dataclass(frozen=True, slots=True)
class NativePublisherLookup:
    """The original home and its successfully resolved registry key."""

    guard_home: Path
    canonical_key: str


def _mutation_wait_seconds(deadline_monotonic: float) -> float:
    if type(deadline_monotonic) not in (int, float):
        raise NativePolicySnapshotError("native_policy_snapshot_control_invalid")
    try:
        valid = math.isfinite(deadline_monotonic)
    except OverflowError:
        valid = False
    if not valid:
        raise NativePolicySnapshotError("native_policy_snapshot_control_invalid")
    remaining = max(0.0, deadline_monotonic - time.monotonic())
    if remaining > threading.TIMEOUT_MAX:
        raise NativePolicySnapshotError("native_policy_snapshot_control_invalid")
    return remaining


def _require_mutation_time(deadline_monotonic: float) -> None:
    if _mutation_wait_seconds(deadline_monotonic) <= 0:
        raise NativePolicySnapshotError("native_policy_snapshot_control_deadline_exceeded")


def capture_native_publisher_lookup(guard_home: Path, *, deadline_monotonic: float) -> NativePublisherLookup:
    """Resolve before cleanup, under bounded ownership; no fallback key on error."""
    _require_mutation_time(deadline_monotonic)

    def resolve(cancelled: threading.Event) -> NativePublisherLookup | None:
        # Any first import/setup of the registry stays within bounded ownership.
        from . import native_policy_snapshot as api

        _ = api._PUBLISHER_LOCK
        canonical = guard_home.expanduser().resolve(strict=True)
        if cancelled.is_set():
            return None
        _require_mutation_time(deadline_monotonic)
        return NativePublisherLookup(guard_home, str(canonical))

    result = run_native_control_worker(resolve, deadline_monotonic=deadline_monotonic)
    _require_mutation_time(deadline_monotonic)
    if result is None:
        raise NativePolicySnapshotError("native_policy_snapshot_control_subject_changed")
    return result


def existing_native_policy_key(store: GuardStore, *, deadline_monotonic: float) -> bytes:
    """Read an existing key only; late cache/backend effects supply no authority.

    Only the absolute SQL deadline is installed in the worker. Publication and
    storage lock ownership, and unrelated ContextVars, are never transferred.
    Existing backend lookup may mirror a primary key to its fallback storage;
    no master key is generated and a late result is never returned to control.
    """
    _require_mutation_time(deadline_monotonic)

    def read(cancelled: threading.Event) -> bytes | None:
        with sqlite_maintenance_deadline(deadline_monotonic):
            material, _key_id = store._policy_integrity_secret_material(create=False)
            if cancelled.is_set():
                return None
            _require_mutation_time(deadline_monotonic)
            return material if type(material) is bytes and len(material) == 32 else None

    result = run_native_control_worker(read, deadline_monotonic=deadline_monotonic)
    _require_mutation_time(deadline_monotonic)
    if result is None:
        raise NativePolicySnapshotError("native_policy_snapshot_integrity_key_unavailable")
    return result


def notify_native_policy_mutation_before_deadline(
    lookup: NativePublisherLookup,
    *,
    guard_home: Path,
    deadline_monotonic: float,
    require_source_authority: bool = False,
) -> None:
    """Attempt bounded invalidation, including zero-wait cleanup after expiry.

    Native withdrawal is the admission fence. A timeout here can follow SQL
    commit and never establishes rollback or restoration of old authority.
    The correctly bound lookup avoids a fresh path resolution during cleanup.
    """
    from . import native_policy_snapshot as api

    if type(lookup) is not NativePublisherLookup or lookup.guard_home != guard_home:
        raise NativePolicySnapshotError("native_policy_snapshot_control_subject_changed")
    if not api._PUBLISHER_LOCK.acquire(timeout=_mutation_wait_seconds(deadline_monotonic)):
        raise NativePolicySnapshotError("native_policy_snapshot_control_deadline_exceeded")
    try:
        publishers = tuple(api._PUBLISHERS.get(lookup.canonical_key, ()))
    finally:
        api._PUBLISHER_LOCK.release()
    for publisher in publishers:
        publisher.request_publish_before_deadline(
            deadline_monotonic=deadline_monotonic,
            require_source_authority=require_source_authority,
        )
    _require_mutation_time(deadline_monotonic)
