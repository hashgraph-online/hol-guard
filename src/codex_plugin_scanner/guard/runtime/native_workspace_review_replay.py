"""Bounded replay of pending Cloud Review requests after native enrollment."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol, cast

from ..store import GuardStore
from .native_workspace_review_context import build_native_workspace_review_context  # noqa: F401

_REPLAY_MARKER = "guard_cloud_review_native_workspace_review_replay"
_SCAN_STATE_MARKER = f"{_REPLAY_MARKER}:scan"
_MAX_CONTEXT_PROBES = 2
_DIGEST_LENGTH = 64
_RETRY_BASE_SECONDS = 60
_RETRY_MAX_SECONDS = 15 * 60
_PROBE_INTERVAL_SECONDS = 5 * 60
_REPLAY_DELAYS_SECONDS = (5 * 60, 15 * 60, 60 * 60, 6 * 60 * 60)
_PROBE_STATE_ATTRIBUTE = "_guard_native_workspace_review_probe_state"
_COMMIT_STATE_SUFFIX = ":commit"
_NATIVE_CLAIM_BINDINGS = (
    ("nativeActionBinding", "action_binding"),
    ("nativeIntentBinding", "intent_binding"),
    ("nativePolicyBinding", "policy_binding"),
)


class _NativeWorkspaceReplayStore(Protocol):
    guard_home: Path
    guard_source: str

    def get_review_event_oauth_binding(self) -> dict[str, str] | None: ...

    def get_sync_payload(self, key: str) -> object | None: ...

    def set_sync_payload(self, key: str, payload: object, now: str) -> None: ...

    def list_pending_review_request_ids(
        self,
        *,
        binding: Mapping[str, str],
        limit: int,
        after_request_id: str | None = None,
        through_request_id: str | None = None,
        descending: bool = False,
    ) -> list[str]: ...

    def list_review_event_snapshots(self, request_id: str) -> list[dict[str, object]]: ...

    def requeue_pending_review_events_with_marker(
        self,
        *,
        changed_at: str,
        marker_key: str,
        marker_payload: Mapping[str, object],
        require_binding: bool = False,
        request_ids: set[str] | None = None,
        request_snapshots: Mapping[str, Mapping[str, object]] | None = None,
    ) -> int: ...


def _valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _DIGEST_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.isoformat()


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _marker_key(store: _NativeWorkspaceReplayStore, request_id: str) -> str:
    request_digest = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
    return f"{_REPLAY_MARKER}:{store.guard_source}:request:{request_digest}"


def _scan_key(store: _NativeWorkspaceReplayStore) -> str:
    return f"{_SCAN_STATE_MARKER}:{store.guard_source}"


def _binding_matches(store: _NativeWorkspaceReplayStore, binding: Mapping[str, str]) -> bool:
    current = store.get_review_event_oauth_binding()
    return isinstance(current, dict) and dict(current) == dict(binding)


def _scan_bounds(store: _NativeWorkspaceReplayStore, binding: Mapping[str, str]) -> tuple[str | None, str | None]:
    state = store.get_sync_payload(_scan_key(store))
    if not isinstance(state, dict) or state.get("binding") != dict(binding):
        return None, None
    cursor = state.get("cursor")
    upper = state.get("through_request_id")
    if not isinstance(upper, str) or not upper:
        return None, None
    return (cursor if isinstance(cursor, str) and cursor else None), upper


def _save_scan_cursor(
    store: _NativeWorkspaceReplayStore,
    binding: Mapping[str, str],
    cursor: str | None,
    changed_at: str,
    through_request_id: str | None,
) -> None:
    store.set_sync_payload(
        _scan_key(store),
        {
            "schema": "guard-cloud-review-native-workspace-review-scan.v1",
            "binding": dict(binding),
            "cursor": cursor,
            "through_request_id": through_request_id,
        },
        changed_at,
    )


def _request_marker(
    store: _NativeWorkspaceReplayStore,
    request_id: str,
) -> tuple[str, dict[str, object] | None]:
    key = _marker_key(store, request_id)
    value = store.get_sync_payload(key)
    return key, cast(dict[str, object], value) if isinstance(value, dict) else None


def _same_binding(marker: Mapping[str, object] | None, binding: Mapping[str, str]) -> bool:
    return isinstance(marker, dict) and marker.get("binding") == dict(binding)


def _retry_delay(attempts: int) -> int:
    return min(_RETRY_MAX_SECONDS, _RETRY_BASE_SECONDS * (2 ** min(attempts, 4)))


def _replay_delay(attempts: int) -> int:
    index = max(0, min(len(_REPLAY_DELAYS_SECONDS) - 1, attempts - 1))
    return _REPLAY_DELAYS_SECONDS[index]


def _probe_due(
    marker: Mapping[str, object] | None,
    *,
    binding: Mapping[str, str],
    now: datetime,
    force_probe: bool,
) -> bool:
    if force_probe or marker is None or not _same_binding(marker, binding):
        return True
    retry_at = _parse_timestamp(marker.get("next_probe_at"))
    return retry_at is None or retry_at <= now


def _failure_marker(
    marker: Mapping[str, object] | None,
    *,
    request_id: str,
    binding: Mapping[str, str],
    now: datetime,
) -> dict[str, object]:
    previous_attempts = marker.get("attempts", 0) if marker is not None else 0
    attempts = previous_attempts + 1 if type(previous_attempts) is int and previous_attempts >= 0 else 1
    result: dict[str, object] = {
        "schema": "guard-cloud-review-native-workspace-review-request.v1",
        "request_id": request_id,
        "binding": dict(binding),
        "attempts": attempts,
        "next_probe_at": _timestamp(now + timedelta(seconds=_retry_delay(attempts))),
    }
    if marker is not None:
        for field in (
            "authority_generation",
            "authority_record_digest",
            "requeued",
            "replay_attempts",
            "accepted",
            "accepted_at",
            "request_snapshot",
        ):
            if field in {"accepted", "accepted_at"} and not _same_binding(marker, binding):
                continue
            if field in marker:
                result[field] = marker[field]
    return result


def _authority_marker(
    context: Mapping[str, object],
    *,
    request_id: str,
    binding: Mapping[str, str],
) -> dict[str, object] | None:
    generation = context.get("authority_generation")
    authority_digest = context.get("authority_record_digest")
    if type(generation) is not int or generation <= 0 or not _valid_digest(authority_digest):
        return None
    return {
        "schema": "guard-cloud-review-native-workspace-review-request.v1",
        "request_id": request_id,
        "binding": dict(binding),
        "authority_generation": generation,
        "authority_record_digest": authority_digest,
    }


def _authority_is_replayed(marker: Mapping[str, object] | None, authority: Mapping[str, object]) -> bool:
    requeued = marker.get("requeued", 0) if isinstance(marker, dict) else 0
    replay_attempts = marker.get("replay_attempts", 0) if isinstance(marker, dict) else 0
    return (
        isinstance(marker, dict)
        and marker.get("authority_generation") == authority.get("authority_generation")
        and marker.get("authority_record_digest") == authority.get("authority_record_digest")
        and ((type(requeued) is int and requeued > 0) or (type(replay_attempts) is int and replay_attempts > 0))
    )


def _authority_is_accepted(marker: Mapping[str, object] | None, authority: Mapping[str, object]) -> bool:
    return (
        isinstance(marker, dict)
        and marker.get("accepted") is True
        and marker.get("authority_generation") == authority.get("authority_generation")
        and marker.get("authority_record_digest") == authority.get("authority_record_digest")
    )


def _native_claim_bindings_match(event: Mapping[str, object]) -> bool:
    claim = event.get("reviewClaim")
    request_payload = event.get("requestPayload")
    if not isinstance(claim, Mapping) or not isinstance(request_payload, Mapping):
        return False
    context = request_payload.get("nativeWorkspaceReview")
    if not isinstance(context, Mapping):
        return False
    return all(
        _valid_digest(claim.get(claim_field))
        and claim.get(claim_field) == context.get(context_field)
        and _valid_digest(context.get(context_field))
        for claim_field, context_field in _NATIVE_CLAIM_BINDINGS
    )


def _commit_state_key(marker_key: str, event_id: str) -> str:
    return f"{marker_key}{_COMMIT_STATE_SUFFIX}:{event_id}"


def _prepare_native_replay_commit_states(
    store: GuardStore,
    events: list[dict[str, object]],
    binding: Mapping[str, str],
) -> bool:
    from .native_workspace_review_replay_delivery import _prepare_native_replay_commit_states as prepare_states

    return prepare_states(store, events, binding)


def _mark_accepted_replay_contexts(
    store: GuardStore,
    events: list[dict[str, object]],
    per_event_results: list[dict[str, object]],
    binding: Mapping[str, str],
) -> bool:
    from .native_workspace_review_replay_delivery import _mark_accepted_replay_contexts as mark_contexts

    return mark_contexts(store, events, per_event_results, binding)


def mark_native_workspace_review_context_accepted(
    store: GuardStore,
    *,
    event: Mapping[str, object],
    binding: Mapping[str, str],
) -> bool | None:
    from .native_workspace_review_replay_delivery import (
        mark_native_workspace_review_context_accepted as mark_context,
    )

    return mark_context(store, event=event, binding=binding)


def prepare_native_workspace_review_replay(
    store: GuardStore,
    *,
    binding: dict[str, str],
    force_probe: bool = False,
) -> int:
    from .native_workspace_review_replay_loop import prepare_native_workspace_review_replay as prepare_loop

    return prepare_loop(store, binding=binding, force_probe=force_probe)


__all__ = [
    "mark_native_workspace_review_context_accepted",
    "prepare_native_workspace_review_replay",
]
