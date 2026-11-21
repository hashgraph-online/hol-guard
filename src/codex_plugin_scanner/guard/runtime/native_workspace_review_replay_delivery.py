"""Commit-state and marker recovery for native-workspace replay delivery."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import cast

from ..store import GuardStore
from . import native_workspace_review_replay as replay


def _event_is_replay(event: Mapping[str, object]) -> bool:
    payload = event.get("eventPayloadJson")
    if isinstance(payload, str):
        try:
            decoded = json.loads(payload)
        except (json.JSONDecodeError, TypeError, ValueError):
            decoded = None
        if isinstance(decoded, dict) and decoded.get("eventType") == "review.request.snapshot_requeued":
            return decoded.get("nativeReplay") is not False
    return event.get("eventType") == "review.request.snapshot_requeued"


def _replay_event_payload_valid(event: Mapping[str, object]) -> bool:
    return _replay_event_snapshot(event) is not None


def _replay_event_snapshot(event: Mapping[str, object]) -> dict[str, object] | None:
    payload = event.get("eventPayloadJson")
    if not isinstance(payload, str):
        return None
    try:
        decoded = json.loads(payload)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    snapshot = decoded.get("requestSnapshot") if isinstance(decoded, dict) else None
    request_id = event.get("localRequestId")
    if (
        not isinstance(decoded, dict)
        or decoded.get("eventType") != "review.request.snapshot_requeued"
        or not isinstance(request_id, str)
        or not request_id
        or not isinstance(snapshot, Mapping)
        or not snapshot
        or snapshot.get("request_id") != request_id
    ):
        return None
    return {str(key): value for key, value in snapshot.items()}


def _native_replay_event_candidate(store: GuardStore, event: Mapping[str, object]) -> bool:
    del store
    # The durable event type is the authority for replay classification. A
    # missing or compacted local marker must never downgrade a replay event to
    # an ordinary snapshot repair that can be acknowledged as a no-op.
    return _event_is_replay(event)


def _native_replay_delivery_state(
    store: GuardStore,
    *,
    event: Mapping[str, object],
    binding: Mapping[str, str],
    allow_markerless: bool = False,
) -> tuple[str, dict[str, object], Mapping[str, object], str, str | None] | None:
    if _native_replay_event_candidate(store, event) and not _replay_event_payload_valid(event):
        return None
    if not replay._native_claim_bindings_match(event):
        return None
    request_id = event.get("localRequestId")
    event_id = event.get("eventId")
    request_payload = event.get("requestPayload")
    claim = event.get("reviewClaim")
    if (
        not isinstance(request_id, str)
        or not request_id
        or not isinstance(event_id, str)
        or not event_id
        or not isinstance(request_payload, Mapping)
        or not isinstance(claim, Mapping)
    ):
        return None
    context = request_payload.get("nativeWorkspaceReview")
    claim_hash = claim.get("claimHash")
    if not isinstance(context, Mapping):
        return None
    replay_store = cast(replay._NativeWorkspaceReplayStore, cast(object, store))
    marker_key, previous = replay._request_marker(replay_store, request_id)
    if (
        isinstance(previous, dict)
        and replay._same_binding(previous, binding)
        and replay._authority_is_replayed(previous, context)
    ):
        return marker_key, previous, context, event_id, claim_hash if isinstance(claim_hash, str) else None
    state = replay_store.get_sync_payload(replay._commit_state_key(marker_key, event_id))
    if _commit_state_matches(
        state if isinstance(state, Mapping) else None,
        binding=binding,
        request_id=request_id,
        event_id=event_id,
        claim_hash=claim_hash if isinstance(claim_hash, str) else None,
        context=context,
    ):
        return marker_key, {}, context, event_id, claim_hash if isinstance(claim_hash, str) else None
    if allow_markerless and previous is None and _event_is_replay(event):
        return marker_key, {}, context, event_id, claim_hash if isinstance(claim_hash, str) else None
    return None


def _commit_state_matches(
    state: Mapping[str, object] | None,
    *,
    binding: Mapping[str, str],
    request_id: str,
    event_id: str,
    claim_hash: str | None,
    context: Mapping[str, object],
) -> bool:
    if not isinstance(state, Mapping) or state.get("binding") != dict(binding):
        return False
    if state.get("request_id") != request_id or state.get("event_id") != event_id:
        return False
    if claim_hash is not None and state.get("claim_hash") != claim_hash:
        return False
    return state.get("authority_generation") == context.get("authority_generation") and state.get(
        "authority_record_digest"
    ) == context.get("authority_record_digest")


def _set_native_replay_commit_state(
    store: GuardStore,
    *,
    event: Mapping[str, object],
    binding: Mapping[str, str],
    server_committed: bool,
) -> tuple[bool | None, bool]:
    try:
        delivery = _native_replay_delivery_state(
            store,
            event=event,
            binding=binding,
            allow_markerless=server_committed,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None, False
    if delivery is None:
        return None, True
    marker_key, previous, context, event_id, claim_hash = delivery
    replay_store = cast(replay._NativeWorkspaceReplayStore, cast(object, store))
    state_key = replay._commit_state_key(marker_key, event_id)
    try:
        existing = replay_store.get_sync_payload(state_key)
        existing_mapping = existing if isinstance(existing, Mapping) else None
        existing_committed = existing_mapping.get("server_committed") is True if existing_mapping is not None else False
        committed = server_committed or (
            _commit_state_matches(
                existing_mapping,
                binding=binding,
                request_id=str(event["localRequestId"]),
                event_id=event_id,
                claim_hash=claim_hash,
                context=context,
            )
            and existing_committed
        )
        request_snapshot = previous.get("request_snapshot")
        if not isinstance(request_snapshot, dict) and existing_mapping is not None:
            request_snapshot = existing_mapping.get("request_snapshot")
        if not isinstance(request_snapshot, dict):
            request_snapshot = _replay_event_snapshot(event)
        replay_store.set_sync_payload(
            state_key,
            {
                "schema": "guard-cloud-review-native-workspace-review-commit.v1",
                "binding": dict(binding),
                "request_id": str(event["localRequestId"]),
                "event_id": event_id,
                "claim_hash": claim_hash,
                "authority_generation": context.get("authority_generation"),
                "authority_record_digest": context.get("authority_record_digest"),
                "request_snapshot": request_snapshot,
                "server_committed": committed,
            },
            replay._timestamp(replay._now()),
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None, False
    return committed, True


def _prepare_native_replay_commit_states(
    store: GuardStore,
    events: list[dict[str, object]],
    binding: Mapping[str, str],
) -> bool:
    for event in events:
        _committed, persisted = _set_native_replay_commit_state(
            store,
            event=event,
            binding=binding,
            server_committed=False,
        )
        if not persisted:
            return False
    return True


def mark_native_workspace_review_context_accepted(
    store: GuardStore,
    *,
    event: Mapping[str, object],
    binding: Mapping[str, str],
) -> bool | None:
    """Record server acceptance of a replay event's authority-bound claim."""

    if not replay._native_claim_bindings_match(event):
        return None
    request_id = event.get("localRequestId")
    if not isinstance(request_id, str) or not request_id:
        return None
    request_payload = event.get("requestPayload")
    if not isinstance(request_payload, Mapping):
        return None
    context = request_payload.get("nativeWorkspaceReview")
    if not isinstance(context, Mapping):
        return None
    replay_store = cast(replay._NativeWorkspaceReplayStore, cast(object, store))
    try:
        marker_key, previous = replay._request_marker(replay_store, request_id)
        delivery = (
            _native_replay_delivery_state(store, event=event, binding=binding)
            if isinstance(event.get("eventId"), str) and event.get("eventId")
            else None
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    if delivery is None and not isinstance(event.get("eventId"), str):
        delivery_previous = previous if isinstance(previous, dict) else None
        event_id = ""
        claim = event.get("reviewClaim")
        raw_claim_hash = claim.get("claimHash") if isinstance(claim, Mapping) else None
        claim_hash = raw_claim_hash if isinstance(raw_claim_hash, str) else None
    elif delivery is None:
        return None
    else:
        marker_key, delivery_previous, _delivery_context, event_id, claim_hash = delivery
    state = replay_store.get_sync_payload(replay._commit_state_key(marker_key, event_id)) if event_id else None
    if not isinstance(previous, dict) or not replay._same_binding(previous, binding):
        previous = delivery_previous
    if not replay._same_binding(previous, binding):
        if not _commit_state_matches(
            state if isinstance(state, Mapping) else None,
            binding=binding,
            request_id=request_id,
            event_id=event_id,
            claim_hash=claim_hash,
            context=context,
        ):
            return None
        previous = {
            "schema": "guard-cloud-review-native-workspace-review-request.v1",
            "request_id": request_id,
            "binding": dict(binding),
            "authority_generation": context.get("authority_generation"),
            "authority_record_digest": context.get("authority_record_digest"),
            "requeued": 1,
            "replay_attempts": 1,
        }
        if isinstance(state, Mapping) and isinstance(state.get("request_snapshot"), dict):
            previous["request_snapshot"] = state["request_snapshot"]
    authority = replay._authority_marker(context, request_id=request_id, binding=binding)
    if authority is None or not replay._authority_is_replayed(previous, authority):
        return None
    if replay._authority_is_accepted(previous, authority):
        return True
    now = replay._now()
    accepted: dict[str, object] = {
        **cast(dict[str, object], previous),
        **authority,
        "accepted": True,
        "accepted_at": replay._timestamp(now),
        "attempts": 0,
        "next_probe_at": replay._timestamp(now + replay.timedelta(seconds=replay._PROBE_INTERVAL_SECONDS)),
    }
    try:
        replay_store.set_sync_payload(marker_key, accepted, replay._timestamp(now))
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    return True


def _finalize_native_replay_delivery(
    store: GuardStore,
    *,
    event: Mapping[str, object],
    binding: Mapping[str, str],
    native_context_committed: bool,
) -> bool | None:
    if _native_replay_event_candidate(store, event) and not _replay_event_payload_valid(event):
        return False
    try:
        committed, persisted = _set_native_replay_commit_state(
            store,
            event=event,
            binding=binding,
            server_committed=native_context_committed,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    if not persisted:
        return False
    if committed is None:
        return False if _native_replay_event_candidate(store, event) else None
    if not committed:
        return False
    return mark_native_workspace_review_context_accepted(store, event=event, binding=binding) is True


def _mark_accepted_replay_contexts(
    store: GuardStore,
    events: list[dict[str, object]],
    per_event_results: list[dict[str, object]],
    binding: Mapping[str, str],
) -> bool:
    ready = True
    for index, item in enumerate(per_event_results):
        if index >= len(events) or item.get("accepted") is not True:
            continue
        malformed_replay = _native_replay_event_candidate(store, events[index]) and not _replay_event_payload_valid(
            events[index]
        )
        if (
            _finalize_native_replay_delivery(
                store,
                event=events[index],
                binding=binding,
                native_context_committed=item.get("nativeContextCommitted") is True,
            )
            is False
        ):
            ready = False
            if malformed_replay:
                quarantine = getattr(store, "quarantine_review_event", None)
                sequence = events[index].get("localStreamSequence")
                if callable(quarantine) and type(sequence) is int:
                    try:
                        quarantine_binding = {
                            key: binding[key]
                            for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
                        }
                        quarantine(
                            sequence,
                            reason="native_replay_payload_invalid",
                            error="snapshot_requeued event payload is malformed",
                            **quarantine_binding,
                        )
                    except (OSError, RuntimeError, TypeError, ValueError):
                        pass
    return ready
