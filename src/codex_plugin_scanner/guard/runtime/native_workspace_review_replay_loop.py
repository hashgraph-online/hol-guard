"""Scanning loop for bounded native-workspace replay preparation."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress
from typing import cast

from ..store import GuardStore
from . import native_workspace_review_replay as replay
from .native_workspace_review_context import (
    NativeWorkspaceReviewContextProbeState,
    native_workspace_review_context_cache_key,
)


def _probe_replay_context(
    store: GuardStore,
    *,
    request_id: str,
    request_snapshot: Mapping[str, object] | None,
    probe_state: NativeWorkspaceReviewContextProbeState,
) -> dict[str, object] | None:
    cache_key = (
        native_workspace_review_context_cache_key(request_id, request_snapshot)
        if request_snapshot is not None
        else None
    )
    if cache_key is not None and cache_key in probe_state.cache:
        return probe_state.cache[cache_key]
    if probe_state.remaining <= 0:
        return None
    probe_state.remaining -= 1
    context = (
        replay.build_native_workspace_review_context(store, store.guard_home, request_id)
        if request_snapshot is None
        else replay.build_native_workspace_review_context(store, store.guard_home, request_id, request_snapshot)
    )
    if cache_key is not None:
        probe_state.cache[cache_key] = context
    return context


def prepare_native_workspace_review_replay(
    store: GuardStore,
    *,
    binding: dict[str, str],
    force_probe: bool = False,
) -> int:
    """Give a bounded rotating batch of eligible requests a native replay chance."""

    replay_store = cast(replay._NativeWorkspaceReplayStore, cast(object, store))
    probe_state = NativeWorkspaceReviewContextProbeState(remaining=replay._MAX_CONTEXT_PROBES)
    setattr(replay_store, replay._PROBE_STATE_ATTRIBUTE, probe_state)
    if not replay._binding_matches(replay_store, binding):
        return 0
    cursor, upper = replay._scan_bounds(replay_store, binding)
    try:
        if upper is None:
            tail = replay_store.list_pending_review_request_ids(binding=binding, limit=1, descending=True)
            if not tail:
                return 0
            upper = tail[0]
        request_ids = replay_store.list_pending_review_request_ids(
            binding=binding,
            limit=replay._MAX_CONTEXT_PROBES,
            after_request_id=cursor,
            through_request_id=upper,
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return 0
    changed_at = replay._timestamp(replay._now())
    if not request_ids:
        replay._save_scan_cursor(replay_store, binding, None, changed_at, None)
        return 0

    replayed = 0
    now = replay._timestamp(replay._now())
    for request_id in request_ids:
        probe = replay_store.native_workspace_review_replay_marker(
            request_id, binding=binding, now=now, force_probe=force_probe
        )
        if probe.get("due") is not True:
            continue
        marker_key = probe.get("key")
        raw_previous = probe.get("marker")
        previous = cast(dict[str, object], raw_previous) if isinstance(raw_previous, dict) else None
        if not isinstance(marker_key, str):
            continue
        request_snapshot: dict[str, object] | None = None
        try:
            get_request = getattr(replay_store, "get_approval_request", None)
            get_snapshots = getattr(replay_store, "list_review_event_snapshots", None)
            if callable(get_snapshots):
                raw_snapshots = get_snapshots(request_id)
                snapshots = raw_snapshots if isinstance(raw_snapshots, list) else []
                request_snapshot = snapshots[0] if snapshots and isinstance(snapshots[0], dict) else None
                if request_snapshot is None and isinstance(previous, dict):
                    retained_snapshot = previous.get("request_snapshot")
                    request_snapshot = retained_snapshot if isinstance(retained_snapshot, dict) else None
                if request_snapshot is not None:
                    context = _probe_replay_context(
                        store,
                        request_id=request_id,
                        request_snapshot=request_snapshot,
                        probe_state=probe_state,
                    )
                else:
                    context = None
            else:
                snapshot = get_request(request_id) if callable(get_request) else None
                request_snapshot = snapshot if isinstance(snapshot, dict) else None
                context = _probe_replay_context(
                    store,
                    request_id=request_id,
                    request_snapshot=request_snapshot,
                    probe_state=probe_state,
                )
        except (OSError, RuntimeError, TypeError, ValueError):
            context = None
        try:
            outcome = replay_store.transition_native_workspace_review_replay_marker(
                request_id,
                "probed",
                binding=binding,
                now=now,
                changed_at=changed_at,
                authority=replay._authority_fields(context),
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            continue
        seed = outcome.get("seed")
        if outcome.get("action") != "requeue" or not isinstance(seed, dict):
            continue
        marker_seed = cast(dict[str, object], seed)
        request_snapshots = {request_id: request_snapshot} if isinstance(request_snapshot, dict) else None
        try:
            if request_snapshots is None:
                count = replay_store.requeue_pending_review_events_with_marker(
                    changed_at=changed_at,
                    marker_key=marker_key,
                    marker_payload=marker_seed,
                    require_binding=True,
                    request_ids={request_id},
                )
            else:
                marker_seed["request_snapshot"] = request_snapshot
                count = replay_store.requeue_pending_review_events_with_marker(
                    changed_at=changed_at,
                    marker_key=marker_key,
                    marker_payload=marker_seed,
                    require_binding=True,
                    request_ids={request_id},
                    request_snapshots=request_snapshots,
                )
        except (OSError, RuntimeError, TypeError, ValueError):
            count = 0
        with suppress(OSError, RuntimeError, TypeError, ValueError):
            replay_store.transition_native_workspace_review_replay_marker(
                request_id,
                "requeued",
                binding=binding,
                now=now,
                changed_at=changed_at,
                seed=marker_seed,
                count=count,
            )
        replayed += count
    # Finish a finite snapshot before accepting a higher watermark. Do not
    # advance durable progress until the batch has completed.
    next_cursor = (
        request_ids[-1] if len(request_ids) == replay._MAX_CONTEXT_PROBES and request_ids[-1] < upper else None
    )
    replay._save_scan_cursor(replay_store, binding, next_cursor, changed_at, upper if next_cursor else None)
    return replayed
