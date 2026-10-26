"""Read models over the workspace assessment coordinator tables."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .workspace_assessment_store import WorktreeKeys


def list_worktrees(store: Any, *, include_paused: bool = True) -> list[dict[str, object]]:
    with store._connect() as connection:
        rows = connection.execute(
            """
            select codebase_key, worktree_key, private_root, dirty_generation, last_completed_generation,
                   last_scan_at_ms, paused, admitted_at_ms
            from workspace_assessment_state
            where ? or paused = 0
            order by admitted_at_ms, worktree_key
            """,
            (1 if include_paused else 0,),
        ).fetchall()
    return [
        {
            "codebase_key": row[0],
            "worktree_key": row[1],
            "root": row[2],
            "dirty_generation": int(row[3]),
            "last_completed_generation": int(row[4]),
            "stale": int(row[4]) < int(row[3]),
            "last_scan_at_ms": row[5],
            "paused": bool(row[6]),
            "admitted_at_ms": int(row[7]),
        }
        for row in rows
    ]


def recent_runs(store: Any, keys: WorktreeKeys | None = None, *, limit: int = 20) -> list[dict[str, object]]:
    clause, params = ("where codebase_key = ? and worktree_key = ?", _key_tuple(keys)) if keys else ("", ())
    with store._connect() as connection:
        rows = connection.execute(
            f"""
            select run_id, codebase_key, worktree_key, snapshot_digest, kind, trigger_kind, state,
                   dirty_generation, coverage_json, findings_json, error_code,
                   created_at_ms, started_at_ms, finished_at_ms
            from workspace_assessment_runs {clause}
            order by created_at_ms desc, run_id desc
            limit ?
            """,
            (*params, max(1, min(limit, 200))),
        ).fetchall()
    # Run history carries a count; findings are read from the latest assessed
    # run, so a long history never multiplies the stored finding lists.
    runs = [_run_payload(row) for row in rows]
    for run in runs:
        findings = run.pop("findings")
        run["finding_count"] = len(findings) if isinstance(findings, list) else 0
    return runs


def latest_runs(store: Any) -> list[dict[str, object]]:
    """The newest run of every worktree in any state, independent of history limits."""

    with store._connect() as connection:
        rows = connection.execute(
            """
            select run_id, codebase_key, worktree_key, snapshot_digest, kind, trigger_kind, state,
                   dirty_generation, coverage_json, findings_json, error_code,
                   created_at_ms, started_at_ms, finished_at_ms
            from workspace_assessment_runs r
            where r.run_id = (
              select newest.run_id from workspace_assessment_runs newest
              where newest.codebase_key = r.codebase_key and newest.worktree_key = r.worktree_key
              order by newest.created_at_ms desc, newest.run_id desc
              limit 1
            )
            order by created_at_ms desc, run_id desc
            """
        ).fetchall()
    runs = [_run_payload(row) for row in rows]
    for run in runs:
        findings = run.pop("findings")
        run["finding_count"] = len(findings) if isinstance(findings, list) else 0
    return runs


def get_run(store: Any, run_id: str) -> dict[str, object] | None:
    with store._connect() as connection:
        row = connection.execute(
            """
            select run_id, codebase_key, worktree_key, snapshot_digest, kind, trigger_kind, state,
                   dirty_generation, coverage_json, findings_json, error_code,
                   created_at_ms, started_at_ms, finished_at_ms
            from workspace_assessment_runs where run_id = ?
            """,
            (run_id,),
        ).fetchone()
    return _run_payload(row) if row is not None else None


def latest_assessed_runs(store: Any, keys: Sequence[WorktreeKeys] | None = None) -> list[dict[str, object]]:
    """The newest completed or partial run of every admitted worktree, or of just ``keys``.

    Findings JSON is decoded only for the selected worktrees.
    """

    if keys is not None and not keys:
        return []
    scope = ""
    params: tuple[str, ...] = ()
    if keys is not None:
        scope = "and (" + " or ".join("(r.codebase_key = ? and r.worktree_key = ?)" for _ in keys) + ")"
        params = tuple(value for item in keys for value in _key_tuple(item))
    with store._connect() as connection:
        rows = connection.execute(
            f"""
            select r.run_id, r.codebase_key, r.worktree_key, r.snapshot_digest, r.kind, r.trigger_kind, r.state,
                   r.dirty_generation, r.coverage_json, r.findings_json, r.error_code,
                   r.created_at_ms, r.started_at_ms, r.finished_at_ms
            from workspace_assessment_runs r
            where r.state in ('completed', 'partial')
              and r.run_id = (
                select latest.run_id from workspace_assessment_runs latest
                where latest.codebase_key = r.codebase_key and latest.worktree_key = r.worktree_key
                  and latest.state in ('completed', 'partial')
                order by latest.finished_at_ms desc, latest.run_id desc
                limit 1
              )
              {scope}
            """,
            params,
        ).fetchall()
    return [_run_payload(row) for row in rows]


def latest_assessed_run(store: Any, keys: WorktreeKeys) -> dict[str, object] | None:
    """The newest completed or partial run of one worktree."""

    with store._connect() as connection:
        row = connection.execute(
            """
            select run_id, codebase_key, worktree_key, snapshot_digest, kind, trigger_kind, state,
                   dirty_generation, coverage_json, findings_json, error_code,
                   created_at_ms, started_at_ms, finished_at_ms
            from workspace_assessment_runs
            where codebase_key = ? and worktree_key = ? and state in ('completed', 'partial')
            order by finished_at_ms desc, run_id desc
            limit 1
            """,
            _key_tuple(keys),
        ).fetchone()
    return _run_payload(row) if row is not None else None


def _run_payload(row: Sequence[object]) -> dict[str, object]:
    return {
        "run_id": row[0],
        "codebase_key": row[1],
        "worktree_key": row[2],
        "snapshot_digest": row[3],
        "kind": row[4],
        "trigger_kind": row[5],
        "state": row[6],
        "dirty_generation": row[7],
        "coverage": json.loads(str(row[8])),
        "findings": json.loads(str(row[9])),
        "error_code": row[10],
        "created_at_ms": row[11],
        "started_at_ms": row[12],
        "finished_at_ms": row[13],
    }


def _key_tuple(keys: WorktreeKeys | None) -> tuple[str, str]:
    assert keys is not None
    return (keys.codebase_key, keys.worktree_key)


__all__ = ["get_run", "latest_assessed_run", "latest_assessed_runs", "latest_runs", "list_worktrees", "recent_runs"]
