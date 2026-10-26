"""Coordinator state for background workspace assessments.

Each admitted worktree has a dirty generation. A trigger bumps it and leaves
at most one queued run; a worker claims a run under a fenced lease, and only
the holder of the current lease generation can record its outcome. A run
whose snapshot changed while it ran is superseded and one successor is
queued, so results are never attached to content they did not assess.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from .store_workspace_assessment_schema import MAX_COVERAGE_JSON_BYTES, MAX_FINDINGS_JSON_BYTES
from .workspace_assessment_reads import (
    get_run,
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


def admit_worktree(store: Any, keys: WorktreeKeys, *, root: str, now_ms: int, resume: bool = True) -> bool:
    """Admit a worktree; ``resume`` also unpauses one admitted before.

    Without ``resume`` an already admitted worktree is left exactly as it is and
    the call returns False, so an automatic admission never undoes a pause.
    """

    conflict = "update set private_root = excluded.private_root, paused = 0" if resume else "nothing"
    with store._connect() as connection:
        cursor = connection.execute(
            f"""
            insert into workspace_assessment_state (codebase_key, worktree_key, private_root, admitted_at_ms)
            values (?, ?, ?, ?)
            on conflict(codebase_key, worktree_key) do {conflict}
            """,
            (keys.codebase_key, keys.worktree_key, root, now_ms),
        )
        return cursor.rowcount == 1


def set_paused(store: Any, keys: WorktreeKeys, *, paused: bool) -> bool:
    with store._connect() as connection:
        cursor = connection.execute(
            "update workspace_assessment_state set paused = ? where codebase_key = ? and worktree_key = ?",
            (1 if paused else 0, keys.codebase_key, keys.worktree_key),
        )
        return cursor.rowcount == 1


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
    with store._connect() as connection:
        connection.execute("begin immediate")
        return _enqueue_locked(
            connection,
            keys,
            trigger_kind=trigger_kind,
            detector_set_digest=detector_set_digest,
            now_ms=now_ms,
            kind=kind,
        )


def _enqueue_locked(
    connection: sqlite3.Connection,
    keys: WorktreeKeys,
    *,
    trigger_kind: str,
    detector_set_digest: str,
    now_ms: int,
    kind: str,
) -> str | None:
    bumped = connection.execute(
        """
        update workspace_assessment_state set dirty_generation = dirty_generation + 1
        where codebase_key = ? and worktree_key = ? and paused = 0
        """,
        (keys.codebase_key, keys.worktree_key),
    )
    if bumped.rowcount != 1:
        return None
    generation = int(
        connection.execute(
            "select dirty_generation from workspace_assessment_state where codebase_key = ? and worktree_key = ?",
            (keys.codebase_key, keys.worktree_key),
        ).fetchone()[0]
    )
    queued = connection.execute(
        """
        select run_id, trigger_kind from workspace_assessment_runs
        where codebase_key = ? and worktree_key = ? and state = 'queued'
        """,
        (keys.codebase_key, keys.worktree_key),
    ).fetchone()
    if queued is not None:
        # Coalesce: the queued run now covers the newer generation and the
        # debounce restarts from this trigger. A user request upgrades an
        # automatic one so it is not held by the debounce. The run records the
        # detector set of the daemon that now covers it, which is the set that
        # will execute it.
        upgraded = trigger_kind if trigger_kind in USER_TRIGGERS else str(queued[1])
        connection.execute(
            """
            update workspace_assessment_runs set
              dirty_generation = ?, trigger_kind = ?, triggered_at_ms = max(triggered_at_ms, ?),
              detector_set_digest = ?
            where run_id = ?
            """,
            (generation, upgraded, now_ms, detector_set_digest, queued[0]),
        )
        return str(queued[0])
    run_id = uuid.uuid4().hex
    connection.execute(
        """
        insert into workspace_assessment_runs (
          run_id, codebase_key, worktree_key, detector_set_digest, kind, trigger_kind,
          state, dirty_generation, created_at_ms, triggered_at_ms
        ) values (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)
        """,
        (
            run_id,
            keys.codebase_key,
            keys.worktree_key,
            detector_set_digest,
            kind,
            trigger_kind,
            generation,
            now_ms,
            now_ms,
        ),
    )
    return run_id


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

    with store._connect() as connection:
        connection.execute("begin immediate")
        _expire_leases_locked(connection, now_ms=now_ms)
        running = connection.execute("select count(*) from workspace_assessment_runs where state = 'running'")
        if int(running.fetchone()[0]) >= MAX_DEVICE_WORKERS:
            return None
        row = connection.execute(
            f"""
            select r.run_id, r.codebase_key, r.worktree_key, s.private_root, r.trigger_kind, r.kind,
                   r.dirty_generation, r.lease_generation, r.detector_set_digest
            from workspace_assessment_runs r
            join workspace_assessment_state s
              on s.codebase_key = r.codebase_key and s.worktree_key = r.worktree_key
            where r.state = 'queued' and s.paused = 0
              and not exists (
                select 1 from workspace_assessment_runs active
                where active.codebase_key = r.codebase_key and active.worktree_key = r.worktree_key
                  and active.state = 'running'
              )
              and (
                r.trigger_kind in ({", ".join("?" for _ in USER_TRIGGERS)})
                or (? = 0
                    and (r.triggered_at_ms <= ? or r.created_at_ms <= ?)
                    and (s.last_scan_at_ms is null or s.last_scan_at_ms <= ?))
              )
            order by r.created_at_ms, r.run_id
            limit 1
            """,
            (
                *USER_TRIGGERS,
                1 if user_only else 0,
                now_ms - DEBOUNCE_MS,
                now_ms - MAX_DEBOUNCE_WAIT_MS,
                now_ms - MIN_INTERVAL_MS,
            ),
        ).fetchone()
        if row is None:
            return None
        lease_generation = int(row[7]) + 1
        claimed_digest = detector_set_digest if detector_set_digest is not None else str(row[8])
        connection.execute(
            """
            update workspace_assessment_runs set
              state = 'running', lease_generation = ?, lease_owner = ?, lease_until_ms = ?, started_at_ms = ?,
              detector_set_digest = ?
            where run_id = ? and state = 'queued'
            """,
            (lease_generation, owner, now_ms + LEASE_MS, now_ms, claimed_digest, row[0]),
        )
        return ClaimedRun(
            run_id=str(row[0]),
            keys=WorktreeKeys(codebase_key=str(row[1]), worktree_key=str(row[2])),
            private_root=str(row[3]),
            trigger_kind=str(row[4]),
            kind=str(row[5]),
            dirty_generation=int(row[6]),
            lease_generation=lease_generation,
            detector_set_digest=claimed_digest,
        )


def _expire_leases_locked(connection: sqlite3.Connection, *, now_ms: int) -> None:
    expired = connection.execute(
        """
        select run_id, codebase_key, worktree_key, trigger_kind, detector_set_digest, kind, created_at_ms
        from workspace_assessment_runs where state = 'running' and lease_until_ms < ?
        """,
        (now_ms,),
    ).fetchall()
    for run_id, codebase_key, worktree_key, trigger_kind, detector_set_digest, kind, created_at in expired:
        # The runner renews its lease between stages, so an expired lease means
        # the worker died or one stage hung. Retry once; a retry that also
        # expires would repeat forever, so the worktree stays stale until its
        # next change or request instead.
        retry = _is_lease_retry_locked(connection, str(codebase_key), str(worktree_key), int(created_at))
        error_code = "assessment_timed_out" if retry else "lease_expired"
        connection.execute(
            """
            update workspace_assessment_runs set
              state = 'failed', error_code = ?, finished_at_ms = ?,
              lease_generation = lease_generation + 1
            where run_id = ?
            """,
            (error_code, now_ms, run_id),
        )
        if error_code != "lease_expired":
            continue
        _enqueue_locked(
            connection,
            WorktreeKeys(str(codebase_key), str(worktree_key)),
            trigger_kind=str(trigger_kind),
            detector_set_digest=str(detector_set_digest),
            now_ms=now_ms,
            kind=str(kind),
        )


def finish(store: Any, run: ClaimedRun, outcome: RunOutcome, *, now_ms: int) -> bool:
    """Record ``outcome`` only if ``run`` still holds the current lease."""

    if outcome.state not in _FINISHED_STATES:
        raise ValueError("invalid workspace assessment outcome state")
    coverage_json = _bounded_json(dict(outcome.coverage or {}), MAX_COVERAGE_JSON_BYTES)
    findings_json = _bounded_json([dict(item) for item in outcome.findings], MAX_FINDINGS_JSON_BYTES)
    with store._connect() as connection:
        connection.execute("begin immediate")
        cursor = connection.execute(
            """
            update workspace_assessment_runs set
              state = ?, snapshot_digest = ?, input_manifest_digest = ?, feed_context_digest = ?,
              coverage_json = ?, findings_json = ?, error_code = ?, finished_at_ms = ?,
              lease_owner = null, lease_until_ms = null
            where run_id = ? and state = 'running' and lease_generation = ? and lease_until_ms >= ?
            """,
            (
                outcome.state,
                outcome.snapshot_digest,
                outcome.input_manifest_digest,
                outcome.feed_context_digest,
                coverage_json,
                findings_json,
                outcome.error_code,
                now_ms,
                run.run_id,
                run.lease_generation,
                now_ms,
            ),
        )
        if cursor.rowcount != 1:
            connection.rollback()
            return False
        if outcome.state in {"completed", "partial"}:
            connection.execute(
                """
                update workspace_assessment_state set
                  last_completed_generation = max(last_completed_generation, min(?, dirty_generation)),
                  last_scan_at_ms = ?,
                  observed_feed_digest = coalesce(?, observed_feed_digest)
                where codebase_key = ? and worktree_key = ?
                """,
                (run.dirty_generation, now_ms, outcome.feed_context_digest, *_key_tuple(run.keys)),
            )
        else:
            connection.execute(
                "update workspace_assessment_state set last_scan_at_ms = ? where codebase_key = ? and worktree_key = ?",
                (now_ms, *_key_tuple(run.keys)),
            )
        if outcome.state == "superseded":
            # The successor keeps a user request's trigger so it is not held
            # back by the debounce the user already bypassed.
            _enqueue_locked(
                connection,
                run.keys,
                trigger_kind=run.trigger_kind if run.trigger_kind in USER_TRIGGERS else "file_change",
                detector_set_digest=run.detector_set_digest,
                now_ms=now_ms,
                kind=run.kind,
            )
        return True


def _is_lease_retry_locked(
    connection: sqlite3.Connection, codebase_key: str, worktree_key: str, created_at_ms: int
) -> bool:
    # A retry is inserted in the same transaction that expires the run before
    # it, so it was created at that run's finish time. A run queued later (for
    # example after a paused worktree resumes) gets its own retry.
    row = connection.execute(
        """
        select 1 from workspace_assessment_runs
        where codebase_key = ? and worktree_key = ? and error_code = 'lease_expired' and finished_at_ms = ?
        limit 1
        """,
        (codebase_key, worktree_key, created_at_ms),
    ).fetchone()
    return row is not None


def renew_lease(store: Any, run: ClaimedRun, *, now_ms: int) -> bool:
    """Extend ``run``'s lease between stages; False once it is canceled, expired or fenced."""

    with store._connect() as connection:
        cursor = connection.execute(
            """
            update workspace_assessment_runs set lease_until_ms = ?
            where run_id = ? and state = 'running' and lease_generation = ? and lease_until_ms >= ?
            """,
            (now_ms + LEASE_MS, run.run_id, run.lease_generation, now_ms),
        )
        return cursor.rowcount == 1


def cancel(store: Any, run_id: str, *, now_ms: int) -> bool:
    """Cancel a queued or running run; a running worker's lease is fenced off."""

    with store._connect() as connection:
        cursor = connection.execute(
            """
            update workspace_assessment_runs set
              state = 'canceled', finished_at_ms = ?, lease_owner = null, lease_until_ms = null,
              lease_generation = lease_generation + 1
            where run_id = ? and state in ('queued', 'running')
            """,
            (now_ms, run_id),
        )
        return cursor.rowcount == 1


def record_observation(
    store: Any,
    keys: WorktreeKeys,
    *,
    stat_digest: str | None = None,
    feed_digest: str | None = None,
) -> tuple[str, ...]:
    """Store observed digests and return which triggers they imply."""

    with store._connect() as connection:
        connection.execute("begin immediate")
        row = connection.execute(
            """
            select observed_stat_digest, observed_feed_digest from workspace_assessment_state
            where codebase_key = ? and worktree_key = ? and paused = 0
            """,
            _key_tuple(keys),
        ).fetchone()
        if row is None:
            return ()
        triggers: list[str] = []
        if stat_digest is not None and row[0] is not None and row[0] != stat_digest:
            triggers.append("file_change")
        if feed_digest is not None and row[1] is not None and row[1] != feed_digest:
            triggers.append("feed_change")
        connection.execute(
            """
            update workspace_assessment_state set
              observed_stat_digest = coalesce(?, observed_stat_digest),
              observed_feed_digest = coalesce(?, observed_feed_digest)
            where codebase_key = ? and worktree_key = ?
            """,
            (stat_digest, feed_digest, *_key_tuple(keys)),
        )
        return tuple(triggers)


def _bounded_json(value: object, limit: int) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > limit:
        raise ValueError("workspace assessment result exceeds its storage bound")
    return encoded


def _key_tuple(keys: WorktreeKeys | None) -> tuple[str, str]:
    assert keys is not None
    return keys.codebase_key, keys.worktree_key


__all__ = [
    "DEBOUNCE_MS",
    "LEASE_MS",
    "MAX_DEVICE_WORKERS",
    "MIN_INTERVAL_MS",
    "ClaimedRun",
    "RunOutcome",
    "WorktreeKeys",
    "admit_worktree",
    "cancel",
    "claim_next",
    "enqueue",
    "finish",
    "get_run",
    "latest_assessed_run",
    "latest_assessed_runs",
    "latest_runs",
    "list_worktrees",
    "recent_runs",
    "record_observation",
    "renew_lease",
    "set_paused",
]
