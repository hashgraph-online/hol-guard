"""Manage publication retry and renewal state for the current barrier."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import TYPE_CHECKING

from .native_policy_snapshot_constants import (
    _PUBLISH_RETRY_MAX_SECONDS,
    _RENEWAL_JITTER_MAX_SECONDS,
    _RENEWAL_LEAD_SECONDS,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_v3_renewal import retain_source_free_v3_lease

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher


def record_publication_error(
    publisher: NativePolicySnapshotPublisher,
    *,
    error: Exception,
    publish_epoch: int,
    renew_after_generation: int | None,
    v3_capture_active: bool,
    v3_transport_active: bool,
) -> None:
    """Keep a superseded or closed attempt from changing current retry state."""
    with publisher._condition:
        if publisher._closed or publisher._epoch != publish_epoch:
            return
    code = str(error) if isinstance(error, NativePolicySnapshotError) else type(error).__name__
    retained = (
        v3_transport_active
        and v3_capture_active
        and retain_source_free_v3_lease(
            publisher, publish_epoch=publish_epoch, renew_after_generation=renew_after_generation
        )
    )
    with publisher._condition:
        # Lease validation observes external state; another request or close can
        # win while it runs. Commit every failure effect in the same epoch check.
        if publisher._closed or publisher._epoch != publish_epoch:
            return
        if not retained and (
            publisher._scoped_publication_enabled
            or v3_capture_active
            or (isinstance(error, NativePolicySnapshotError) and code.startswith("native_cloud_policy_"))
        ):
            publisher._acked = False
        publisher._record_error(code)


def record_error(publisher: NativePolicySnapshotPublisher, error: str) -> None:
    safe = error.strip().lower()
    if not safe or len(safe) > 128 or not all(character.isalnum() or character in "_-=,:?" for character in safe):
        safe = "native_policy_snapshot_publish_failed"
    with publisher._condition:
        publisher._last_error = safe
        expires = publisher._snapshot.get("expires_at_ms") if publisher._snapshot else None
        if not (publisher._acked and isinstance(expires, int) and expires > int(publisher._wall_clock() * 1_000)):
            publisher._acked = False
        publisher._failure_count += 1
        delay = min(
            _PUBLISH_RETRY_MAX_SECONDS,
            publisher._poll_interval_seconds * (2 ** min(publisher._failure_count - 1, 5)),
        )
        retry_seed = hashlib.sha256(f"{publisher._failure_count}:{safe}".encode("ascii")).digest()
        retry_fraction = int.from_bytes(retry_seed[:2], "big") / float(1 << 16)
        publisher._retry_not_before_monotonic = (
            publisher._monotonic_clock()
            + delay
            + min(
                0.1,
                publisher._poll_interval_seconds * 0.25,
            )
            * retry_fraction
        )
        publisher._condition.notify_all()


def mark_expired_locked(publisher: NativePolicySnapshotPublisher) -> None:
    snapshot = publisher._snapshot
    if not publisher._acked or snapshot is None:
        return
    expires_at_ms = snapshot.get("expires_at_ms")
    if not isinstance(expires_at_ms, int) or expires_at_ms > int(publisher._wall_clock() * 1_000):
        return
    generation = snapshot.get("generation")
    publisher._acked = False
    publisher._last_error = "native_policy_snapshot_expired"
    publisher._renewal_due_monotonic = None
    publisher._renewal_after_generation = generation if isinstance(generation, int) and generation > 0 else None
    publisher._retry_not_before_monotonic = publisher._monotonic_clock()
    publisher._condition.notify_all()
    publisher._publish_event.set()


def renewal_jitter_seconds(snapshot: Mapping[str, object], remaining_seconds: float) -> float:
    digest = snapshot.get("policy_digest")
    generation = snapshot.get("generation")
    if not isinstance(digest, str) or not isinstance(generation, int) or remaining_seconds <= 0:
        return 0.0
    seed = hashlib.sha256(f"{generation}:{digest}".encode("ascii")).digest()
    fraction = int.from_bytes(seed[:4], "big") / float(1 << 32)
    return min(_RENEWAL_JITTER_MAX_SECONDS, remaining_seconds * 0.05) * fraction


def schedule_renewal_locked(publisher: NativePolicySnapshotPublisher, snapshot: Mapping[str, object]) -> None:
    expires_at_ms = snapshot.get("expires_at_ms")
    if not isinstance(expires_at_ms, int):
        publisher._renewal_due_monotonic = publisher._monotonic_clock()
        return
    remaining_seconds = expires_at_ms / 1_000 - publisher._wall_clock()
    if remaining_seconds <= 0:
        publisher._renewal_due_monotonic = publisher._monotonic_clock()
        return
    lead_seconds = min(_RENEWAL_LEAD_SECONDS, max(1.0, remaining_seconds * 0.1))
    jitter_seconds = publisher._renewal_jitter_seconds(snapshot, remaining_seconds)
    due_in = max(0.0, remaining_seconds - lead_seconds - jitter_seconds)
    publisher._renewal_due_monotonic = publisher._monotonic_clock() + due_in
