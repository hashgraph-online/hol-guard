"""Typed projections between Guard Cloud sync and the native runner-authority owner.

The resident decides which cloud endpoint a sync talks to, which stored events
become pain signals, what the local value metrics say, whether canonical policy
enforcement applies to this device, which stored policy bundle a new bundle must
not be older than, and what a bundle would have decided for recent receipts.
Every function here ships a minimal projection and returns the owner's answer
unchanged; a transport or shape failure raises ``NativeRunnerAuthorityError``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from typing import Any

from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

POLICY_CANONICAL_ENFORCEMENT_ENV = "HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT"
_SIGNAL_PAYLOAD_KEYS = (
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "changed_fields",
    "executor",
    "expires_at",
    "harness",
    "install_kind",
    "policy_action",
    "publisher",
    "reason",
    "risk_signals",
)


def _malformed() -> NativeRunnerAuthorityError:
    return NativeRunnerAuthorityError("native_runner_authority_result_invalid")


def _field(payload: Mapping[str, Any], key: str, kind: type | tuple[type, ...]) -> Any:
    value = payload.get(key)
    if not isinstance(value, kind) or (isinstance(value, bool) and kind is not bool):
        raise _malformed()
    return value


def sync_url(route: str, url: str, **parameters: object) -> str:
    """The endpoint ``route`` derives from the configured sync URL."""

    payload = native_runner_authority("sync_url", {"route": route, "url": url, **parameters})
    return str(_field(payload, "url", str))


def normalized_receipts_sync_url(url: str) -> str:
    return sync_url("receipts", url)


def normalized_runtime_sessions_sync_url(url: str) -> str:
    return sync_url("runtime_sessions", url)


def guard_events_sync_url(url: str) -> str:
    return sync_url("guard_events", url)


def pain_signal_sync_url(url: str) -> str:
    return sync_url("pain_signal", url)


def normalized_supply_chain_bundle_url(url: str, workspace_id: str) -> str:
    return sync_url("supply_chain_bundle", url, workspace_id=workspace_id)


def normalized_supply_chain_bundle_index_url(url: str) -> str:
    return sync_url("supply_chain_index", url)


def supply_chain_partition_bundle_url(url: str, *, ecosystem: str, partition: int) -> str:
    return sync_url("supply_chain_partition", url, ecosystem=ecosystem, partition=partition)


def _slim_event(event: object) -> object:
    if not isinstance(event, Mapping):
        return None
    payload = event.get("payload")
    slim_payload: object = payload
    if isinstance(payload, Mapping):
        slim_payload = {key: payload[key] for key in _SIGNAL_PAYLOAD_KEYS if key in payload}
    return {"event_name": event.get("event_name"), "occurred_at": event.get("occurred_at"), "payload": slim_payload}


def pain_signal_batch(
    events: Sequence[object], warn_counts: Mapping[tuple[str, str], int]
) -> tuple[list[dict[str, object]], dict[tuple[str, str], int]]:
    """Pain-signal items for one batch plus the repeat-warning counters to carry on."""

    payload = native_runner_authority(
        "pain_signal_batch",
        {
            "events": [_slim_event(event) for event in events],
            "warn_counts": [[harness, artifact, count] for (harness, artifact), count in warn_counts.items()],
        },
    )
    items = _field(payload, "items", list)
    counts = _field(payload, "warn_counts", list)
    if not all(isinstance(item, dict) for item in items):
        raise _malformed()
    carried: dict[tuple[str, str], int] = {}
    for row in counts:
        if not (isinstance(row, list) and len(row) == 3 and isinstance(row[2], int)):
            raise _malformed()
        carried[(str(row[0]), str(row[1]))] = row[2]
    return items, carried


def value_metrics(events: Sequence[object], now: str) -> tuple[dict[str, dict[str, object]], dict[str, object]]:
    """Local value metrics and the weekly digest derived from stored events."""

    slim = [_slim_event(event) for event in events]
    payload = native_runner_authority("value_metrics", {"events": slim, "now": now})
    return _field(payload, "metrics", dict), _field(payload, "weekly_digest", dict)


def canonical_policy_enforcement_enabled(*, device_id: str, workspace_id: str | None) -> bool:
    """Whether canonical policy enforcement applies to this device."""

    payload = native_runner_authority(
        "canonical_rollout",
        {
            "raw": os.environ.get(POLICY_CANONICAL_ENFORCEMENT_ENV),
            "device_id": device_id,
            "workspace_id": workspace_id,
        },
    )
    return bool(_field(payload, "enabled", bool))


def completed_guard_event_ids(payload: Mapping[str, object]) -> list[str]:
    """Event ids the cloud acknowledged as finished."""

    statuses = payload.get("statuses")
    slim = {"statuses": statuses if isinstance(statuses, list) else []}
    answer = native_runner_authority("completed_event_ids", {"payload": slim})
    ids = _field(answer, "ids", list)
    if not all(isinstance(item, str) for item in ids):
        raise _malformed()
    return ids


_BUNDLE_KEYS = ("issuedAt", "bundleVersion", "payloadHash", "workspaceId")


def policy_bundle_downgrade_reference(
    candidates: Sequence[object], workspace_id: str | None
) -> dict[str, object] | None:
    """The stored bundle a new bundle must not be older than, if any.

    Only the ordering fields cross the transport; the owner names the winner by
    its position and the full stored bundle is returned unchanged.
    """

    slim = [
        {**{key: item[key] for key in _BUNDLE_KEYS if key in item}, "index": index}
        if isinstance(item, Mapping)
        else None
        for index, item in enumerate(candidates)
    ]
    payload = native_runner_authority("downgrade_reference", {"candidates": slim, "workspace_id": workspace_id})
    if "reference" not in payload:
        raise _malformed()
    reference = payload["reference"]
    if reference is None:
        return None
    index = reference.get("index") if isinstance(reference, dict) else None
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(candidates):
        raise _malformed()
    chosen = candidates[index]
    if not isinstance(chosen, dict):
        raise _malformed()
    return chosen


def policy_simulation(
    receipts: Sequence[object],
    decisions: Sequence[Mapping[str, object]],
    *,
    bundle_version: object,
    bundle_hash: object,
    now: str,
) -> dict[str, object]:
    """What a bundle's decisions would have done to the sampled receipts."""

    return dict(
        native_runner_authority(
            "policy_simulation",
            {
                "receipts": list(receipts),
                "decisions": [dict(decision) for decision in decisions],
                "bundle_version": bundle_version,
                "bundle_hash": bundle_hash,
                "now": now,
            },
        )
    )
