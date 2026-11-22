"""Read models over the workspace assessment coordinator tables.

The worktree list, run history and the newest assessed runs are read by the
native store; the stored coverage and findings JSON come back as text and are
parsed here.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from .workspace_assessment_store import WorktreeKeys


# Each field a native row must carry, with the type its value must have.
_TEXT, _INT, _FLAG, _OPTIONAL_INT, _OPTIONAL_TEXT = "text", "int", "flag", "optional_int", "optional_text"
_WORKTREE_FIELDS: Final[dict[str, str]] = {
    "codebase_key": _TEXT,
    "worktree_key": _TEXT,
    "root": _TEXT,
    "dirty_generation": _INT,
    "last_completed_generation": _INT,
    "last_scan_at_ms": _OPTIONAL_INT,
    "paused": _FLAG,
    "admitted_at_ms": _INT,
    "ended": _FLAG,
}
_RUN_FIELDS: Final[dict[str, str]] = {
    "run_id": _TEXT,
    "codebase_key": _TEXT,
    "worktree_key": _TEXT,
    "snapshot_digest": _OPTIONAL_TEXT,
    "kind": _TEXT,
    "trigger_kind": _TEXT,
    "state": _TEXT,
    "dirty_generation": _INT,
    "coverage_json": _TEXT,
    "error_code": _OPTIONAL_TEXT,
    "created_at_ms": _INT,
    "started_at_ms": _OPTIONAL_INT,
    "finished_at_ms": _OPTIONAL_INT,
}
# A runaway store cannot keep a listing loop going forever.
_MAX_PAGES: Final = 4096


def list_worktrees(store: Any, *, include_paused: bool = True) -> list[dict[str, object]]:
    method = "list_workspace_assessment_worktrees"
    rows = _pages(store, method, {"include_paused": include_paused}, "after", _WORKTREE_FIELDS)
    worktrees: list[dict[str, object]] = []
    for row in rows:
        dirty = _int(row["dirty_generation"], method)
        completed = _int(row["last_completed_generation"], method)
        worktrees.append(
            {
                "codebase_key": row["codebase_key"],
                "worktree_key": row["worktree_key"],
                "root": row["root"],
                "dirty_generation": dirty,
                "last_completed_generation": completed,
                "stale": completed < dirty,
                "last_scan_at_ms": row["last_scan_at_ms"],
                "paused": bool(row["paused"]),
                "admitted_at_ms": _int(row["admitted_at_ms"], method),
                # The install that admitted it is gone: paused, and kept for its records.
                "ended": bool(row["ended"]),
            }
        )
    return worktrees


def recent_runs(store: Any, keys: WorktreeKeys | None = None, *, limit: int = 20) -> list[dict[str, object]]:
    # Run history carries a count; findings are read from the latest assessed
    # run, so a long history never multiplies the stored finding lists.
    args: dict[str, object] = {"mode": "recent", "limit": max(1, min(limit, 200))}
    if keys is not None:
        args["codebase_key"], args["worktree_key"] = _key_tuple(keys)
    return _run_history(store, args)


def latest_runs(store: Any) -> list[dict[str, object]]:
    """The newest run of every worktree in any state, independent of history limits."""

    return _run_history(store, {"mode": "latest"})


def latest_assessed_runs(store: Any, keys: Sequence[WorktreeKeys] | None = None) -> list[dict[str, object]]:
    """The newest completed or partial run of every admitted worktree, or of just ``keys``.

    Findings JSON is decoded only for the selected worktrees.
    """

    if keys is not None and not keys:
        return []
    method = "list_latest_assessed_workspace_runs"
    args: dict[str, object] = {}
    if keys is not None:
        args["keys"] = [list(_key_tuple(item)) for item in keys]
    runs: list[dict[str, object]] = []
    for row in _pages(store, method, args, "after", {**_RUN_FIELDS, "findings_json": _TEXT}):
        run = _run_fields(row, method)
        run["findings"] = json.loads(_text(row["findings_json"], method))
        runs.append(run)
    return runs


def latest_assessed_run(store: Any, keys: WorktreeKeys) -> dict[str, object] | None:
    """The newest completed or partial run of one worktree.

    Runs finished in the same millisecond keep the order they were queued in.
    """

    method = "latest_workspace_assessment_run"
    codebase_key, worktree_key = _key_tuple(keys)
    answer = store._native_store_call(method, {"codebase_key": codebase_key, "worktree_key": worktree_key})
    if answer is None:
        return None
    row = _row(answer, {**_RUN_FIELDS, "findings_json": _TEXT}, method)
    run = _run_fields(row, method)
    run["findings"] = json.loads(_text(row["findings_json"], method))
    return run


def _run_history(store: Any, args: dict[str, object]) -> list[dict[str, object]]:
    method = "list_workspace_assessment_runs"
    limit = args.get("limit")
    runs: list[dict[str, object]] = []
    for row in _pages(store, method, args, "before", {**_RUN_FIELDS, "finding_count": _INT}):
        run = _run_fields(row, method)
        run["finding_count"] = _int(row["finding_count"], method)
        runs.append(run)
        if isinstance(limit, int) and len(runs) >= limit:
            break
    return runs


def _pages(
    store: Any, method: str, args: dict[str, object], cursor_name: str, fields: dict[str, str]
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    cursor: object = None
    for _ in range(_MAX_PAGES):
        page_args = dict(args)
        if cursor is not None:
            page_args[cursor_name] = cursor
        answer = store._native_store_call(method, page_args)
        if not isinstance(answer, dict) or set(answer) != {"items", "next"}:
            raise RuntimeError(f"native {method} returned no answer")
        items = answer["items"]
        previous, cursor = cursor, answer["next"]
        if not isinstance(items, list) or not (cursor is None or isinstance(cursor, list)):
            raise RuntimeError(f"native {method} returned no answer")
        # A page must move on: an empty page or a repeated cursor would hand
        # back the same rows again.
        if cursor is not None and (not items or cursor == previous):
            raise RuntimeError(f"native {method} returned no answer")
        rows.extend(_row(item, fields, method) for item in items)
        if cursor is None:
            return rows
        limit = args.get("limit")
        if isinstance(limit, int) and len(rows) >= limit:
            return rows
    raise RuntimeError(f"native {method} kept paging")


def _row(value: object, fields: dict[str, str], method: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise RuntimeError(f"native {method} returned no answer")
    if not all(_has_type(value[name], kind) for name, kind in fields.items()):
        raise RuntimeError(f"native {method} returned no answer")
    return {str(key): item for key, item in value.items()}


def _has_type(value: object, kind: str) -> bool:
    if value is None:
        return kind in (_OPTIONAL_INT, _OPTIONAL_TEXT)
    if kind in (_TEXT, _OPTIONAL_TEXT):
        return isinstance(value, str)
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return value in (0, 1) if kind == _FLAG else True


def _int(value: object, method: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(f"native {method} returned no answer")
    return value


def _text(value: object, method: str) -> str:
    if not isinstance(value, str):
        raise RuntimeError(f"native {method} returned no answer")
    return value


def _run_fields(row: dict[str, object], method: str) -> dict[str, object]:
    return {
        "run_id": row["run_id"],
        "codebase_key": row["codebase_key"],
        "worktree_key": row["worktree_key"],
        "snapshot_digest": row["snapshot_digest"],
        "kind": row["kind"],
        "trigger_kind": row["trigger_kind"],
        "state": row["state"],
        "dirty_generation": row["dirty_generation"],
        "coverage": json.loads(_text(row["coverage_json"], method)),
        "error_code": row["error_code"],
        "created_at_ms": row["created_at_ms"],
        "started_at_ms": row["started_at_ms"],
        "finished_at_ms": row["finished_at_ms"],
    }


def _key_tuple(keys: WorktreeKeys | None) -> tuple[str, str]:
    assert keys is not None
    return (keys.codebase_key, keys.worktree_key)


__all__ = ["latest_assessed_run", "latest_assessed_runs", "latest_runs", "list_worktrees", "recent_runs"]
