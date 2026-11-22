"""Coordinator state for background workspace assessments.

Each admitted worktree has a dirty generation. A trigger bumps it and leaves
at most one queued run; a worker claims a run under a fenced lease, and only
the holder of the current lease generation can record its outcome. A run
whose snapshot changed while it ran is superseded and one successor is
queued, so results are never attached to content they did not assess.

The native store runs the queue: each call here is one store transaction.
Python keeps the outcome's carry-over of earlier findings, which needs the
advisory feed, and bounds the JSON it stores.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from .store_workspace_assessment_schema import MAX_COVERAGE_JSON_BYTES, MAX_FINDINGS_JSON_BYTES
from .workspace_assessment_carry import carry_unchecked_findings, keep_package_identities
from .workspace_assessment_reads import (
    latest_assessed_run,
    latest_assessed_runs,
    latest_runs,
    list_worktrees,
    recent_runs,
)

DEBOUNCE_MS: Final = 5_000
# Edits that never pause for the debounce still get assessed this often.
MAX_DEBOUNCE_WAIT_MS: Final = 60_000
MIN_INTERVAL_MS: Final = 60_000
MAX_DEVICE_WORKERS: Final = 2
LEASE_MS: Final = 5 * 60_000

TRIGGERS: Final = frozenset({"workspace_open", "file_change", "feed_change", "manual", "fix_verification"})
# User-requested runs skip the debounce and interval: someone is waiting.
USER_TRIGGERS: Final = ("manual", "fix_verification")
_FINISHED_STATES: Final = frozenset({"completed", "partial", "failed", "superseded"})
_OBSERVED_TRIGGERS: Final = ("file_change", "feed_change")
_CLAIM_INTS: Final = frozenset({"dirty_generation", "lease_generation"})
_CLAIM_FIELDS: Final = _CLAIM_INTS | {
    "run_id",
    "codebase_key",
    "worktree_key",
    "private_root",
    "trigger_kind",
    "kind",
    "detector_set_digest",
}


@dataclass(frozen=True)
class WorktreeKeys:
    codebase_key: str
    worktree_key: str


@dataclass(frozen=True)
class ClaimedRun:
    run_id: str
    keys: WorktreeKeys
    private_root: str
    trigger_kind: str
    kind: str
    dirty_generation: int
    lease_generation: int
    detector_set_digest: str


@dataclass(frozen=True)
class RunOutcome:
    state: str
    snapshot_digest: str | None = None
    input_manifest_digest: str | None = None
    feed_context_digest: str | None = None
    coverage: Mapping[str, object] | None = None
    findings: Sequence[Mapping[str, object]] = ()
    error_code: str | None = None
    # (ecosystem, name, version) of every package the audit read; None if it stopped early.
    listed_packages: frozenset[tuple[str, str, str]] | None = None


def set_paused(store: Any, keys: WorktreeKeys, *, paused: bool) -> bool:
    method = "set_workspace_assessment_paused"
    return _flag(store._native_store_call(method, {**_key_args(keys), "paused": paused}), method)


def enqueue(
    store: Any,
    keys: WorktreeKeys,
    *,
    trigger_kind: str,
    detector_set_digest: str,
    now_ms: int,
    kind: str = "deterministic",
) -> str | None:
    """Mark the worktree dirty and return the one queued run that covers it."""

    if trigger_kind not in TRIGGERS:
        raise ValueError("unknown workspace assessment trigger")
    method = "enqueue_workspace_assessment"
    answer = store._native_store_call(
        method,
        {
            **_key_args(keys),
            "trigger_kind": trigger_kind,
            "detector_set_digest": detector_set_digest,
            "kind": kind,
            "now_ms": now_ms,
            "run_id": uuid.uuid4().hex,
        },
    )
    return _optional_text(answer, method)


def claim_next(
    store: Any,
    *,
    owner: str,
    now_ms: int,
    detector_set_digest: str | None = None,
    user_only: bool = False,
) -> ClaimedRun | None:
    """Lease the next due run.

    ``detector_set_digest`` is the set the caller will execute. A run queued by
    an older daemon is relabelled with it at claim time, so the stored digest
    always names the detectors that actually produced the result.
    ``user_only`` leaves automatic runs queued, for a host under pressure.
    """

    method = "claim_workspace_assessment"
    args: dict[str, object] = {"owner": owner, "now_ms": now_ms, "user_only": user_only}
    if detector_set_digest is not None:
        args["detector_set_digest"] = detector_set_digest
    answer = store._native_store_call(method, args)
    if answer is None:
        return None
    if not isinstance(answer, dict) or set(answer) != _CLAIM_FIELDS:
        raise RuntimeError(f"native {method} returned no answer")
    texts = {name: _text(answer[name], method) for name in _CLAIM_FIELDS - _CLAIM_INTS}
    return ClaimedRun(
        run_id=texts["run_id"],
        keys=WorktreeKeys(codebase_key=texts["codebase_key"], worktree_key=texts["worktree_key"]),
        private_root=texts["private_root"],
        trigger_kind=texts["trigger_kind"],
        kind=texts["kind"],
        dirty_generation=_int(answer["dirty_generation"], method),
        lease_generation=_int(answer["lease_generation"], method),
        detector_set_digest=texts["detector_set_digest"],
    )


def finish(store: Any, run: ClaimedRun, outcome: RunOutcome, *, now_ms: int) -> bool:
    """Record ``outcome`` only if ``run`` still holds the current lease."""

    if outcome.state not in _FINISHED_STATES:
        raise ValueError("invalid workspace assessment outcome state")
    # Only one run of a worktree runs at a time, so its last run stays put.
    previous = latest_assessed_run(store, run.keys)
    outcome, settled = keep_package_identities(outcome, previous, store=store)
    if outcome.state == "partial":
        outcome = carry_unchecked_findings(outcome, previous, settled)
    coverage_json = _bounded_json(dict(outcome.coverage or {}), MAX_COVERAGE_JSON_BYTES)
    findings_json = _bounded_json([dict(item) for item in outcome.findings], MAX_FINDINGS_JSON_BYTES)
    method = "finish_workspace_assessment"
    answer = store._native_store_call(
        method,
        {
            **_key_args(run.keys),
            "run_id": run.run_id,
            "lease_generation": run.lease_generation,
            "dirty_generation": run.dirty_generation,
            "trigger_kind": run.trigger_kind,
            "kind": run.kind,
            "detector_set_digest": run.detector_set_digest,
            "state": outcome.state,
            "snapshot_digest": outcome.snapshot_digest,
            "input_manifest_digest": outcome.input_manifest_digest,
            "feed_context_digest": outcome.feed_context_digest,
            "coverage_json": coverage_json,
            "findings_json": findings_json,
            "error_code": outcome.error_code,
            "now_ms": now_ms,
        },
    )
    return _flag(answer, method)


def renew_lease(store: Any, run: ClaimedRun, *, now_ms: int) -> bool:
    """Extend ``run``'s lease between stages; False once it is canceled, expired or fenced."""

    method = "renew_workspace_assessment_lease"
    args = {"run_id": run.run_id, "lease_generation": run.lease_generation, "now_ms": now_ms}
    return _flag(store._native_store_call(method, args), method)


def cancel(store: Any, run_id: str, *, now_ms: int) -> bool:
    """Cancel a queued or running run; a running worker's lease is fenced off."""

    method = "cancel_workspace_assessment"
    return _flag(store._native_store_call(method, {"run_id": run_id, "now_ms": now_ms}), method)


def record_observation(
    store: Any,
    keys: WorktreeKeys,
    *,
    stat_digest: str | None = None,
    feed_digest: str | None = None,
) -> tuple[str, ...]:
    """Store observed digests and return which triggers they imply."""

    method = "record_workspace_assessment_observation"
    answer = store._native_store_call(
        method, {**_key_args(keys), "stat_digest": stat_digest, "feed_digest": feed_digest}
    )
    if not isinstance(answer, list) or not all(item in _OBSERVED_TRIGGERS for item in answer):
        raise RuntimeError(f"native {method} returned no answer")
    if len(set(answer)) != len(answer):
        raise RuntimeError(f"native {method} returned no answer")
    return tuple(str(item) for item in answer)


def observe(
    store: Any,
    keys: WorktreeKeys,
    *,
    detector_set_digest: str,
    now_ms: int,
    stat_digest: str | None = None,
    feed_digest: str | None = None,
) -> int:
    """Store observed digests and queue the runs they imply in one transaction.

    Returns how many runs the observation queued. A failed enqueue leaves the
    earlier digests in place, so the next poll sees the change again.
    """

    method = "observe_workspace_assessment"
    answer = store._native_store_call(
        method,
        {
            **_key_args(keys),
            "stat_digest": stat_digest,
            "feed_digest": feed_digest,
            "detector_set_digest": detector_set_digest,
            "now_ms": now_ms,
        },
    )
    if isinstance(answer, bool) or not isinstance(answer, int) or not 0 <= answer <= len(_OBSERVED_TRIGGERS):
        raise RuntimeError(f"native {method} returned no answer")
    return answer


def _bounded_json(value: object, limit: int) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > limit:
        raise ValueError("workspace assessment result exceeds its storage bound")
    return encoded


def _key_args(keys: WorktreeKeys) -> dict[str, object]:
    return {"codebase_key": keys.codebase_key, "worktree_key": keys.worktree_key}


def _flag(value: object, method: str) -> bool:
    if not isinstance(value, bool):
        raise RuntimeError(f"native {method} returned no answer")
    return value


def _text(value: object, method: str) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"native {method} returned no answer")
    return value


def _optional_text(value: object, method: str) -> str | None:
    return None if value is None else _text(value, method)


def _int(value: object, method: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeError(f"native {method} returned no answer")
    return value


__all__ = [
    "DEBOUNCE_MS",
    "LEASE_MS",
    "MAX_DEVICE_WORKERS",
    "MIN_INTERVAL_MS",
    "ClaimedRun",
    "RunOutcome",
    "WorktreeKeys",
    "cancel",
    "claim_next",
    "enqueue",
    "finish",
    "latest_assessed_run",
    "latest_assessed_runs",
    "latest_runs",
    "list_worktrees",
    "observe",
    "recent_runs",
    "record_observation",
    "renew_lease",
    "set_paused",
]
