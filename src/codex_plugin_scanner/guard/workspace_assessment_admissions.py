"""Admitting worktrees for background assessment, and ending install admissions.

An admission, its first observation and its first run are written in one
transaction, so a failure part way leaves nothing behind for the next poll to
mistake for a finished admission. A worktree admitted automatically, because a
harness install registered it, is marked; it stops being watched once no active
install registers its root, unless someone admitted it themselves.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

from .workspace_assessment_store import WorktreeKeys, _enqueue_locked

# Rows that name a worktree; the store does not enforce foreign keys, so ending
# an admission deletes them explicitly.
_WORKTREE_TABLES = (
    "workspace_fix_proposals",
    "workspace_assessment_runs",
    "workspace_assessment_install_admissions",
    "workspace_assessment_state",
)


def admit_and_queue(
    store: Any,
    keys: WorktreeKeys,
    *,
    root: str,
    now_ms: int,
    automatic: bool,
    stat_digest: str,
    feed_digest: str | None,
    detector_set_digest: str,
) -> str | None:
    """Admit a worktree, record its first observation and queue its first run.

    A manual admission also resumes a paused worktree and takes over one that
    was admitted automatically. An automatic admission leaves a worktree that is
    already admitted alone and returns ``None``; when its root used to name
    another worktree admitted the same way, that admission ends.
    """

    conflict = "nothing" if automatic else "update set private_root = excluded.private_root, paused = 0"
    with store._connect() as connection:
        connection.execute("begin immediate")
        inserted = connection.execute(
            f"""
            insert into workspace_assessment_state (codebase_key, worktree_key, private_root, admitted_at_ms)
            values (?, ?, ?, ?)
            on conflict(codebase_key, worktree_key) do {conflict}
            """,
            (keys.codebase_key, keys.worktree_key, root, now_ms),
        )
        if inserted.rowcount != 1:
            return None
        if automatic:
            replaced = connection.execute(
                """
                select s.codebase_key, s.worktree_key from workspace_assessment_state s
                join workspace_assessment_install_admissions a using (codebase_key, worktree_key)
                where s.private_root = ? and not (s.codebase_key = ? and s.worktree_key = ?)
                """,
                (root, keys.codebase_key, keys.worktree_key),
            ).fetchall()
            _delete_worktrees(connection, [(str(row[0]), str(row[1])) for row in replaced])
            connection.execute(
                "insert or ignore into workspace_assessment_install_admissions values (?, ?)",
                (keys.codebase_key, keys.worktree_key),
            )
        else:
            connection.execute(
                "delete from workspace_assessment_install_admissions where codebase_key = ? and worktree_key = ?",
                (keys.codebase_key, keys.worktree_key),
            )
        connection.execute(
            """
            update workspace_assessment_state set observed_stat_digest = ?, observed_feed_digest = ?
            where codebase_key = ? and worktree_key = ?
            """,
            (stat_digest, feed_digest, keys.codebase_key, keys.worktree_key),
        )
        return _enqueue_locked(
            connection,
            keys,
            trigger_kind="workspace_open",
            detector_set_digest=detector_set_digest,
            now_ms=now_ms,
            kind="deterministic",
        )


def watched_roots(store: Any, *, unavailable_digest: str) -> set[str]:
    """Roots of admitted worktrees, leaving out those last observed unavailable.

    An unavailable root may now name another worktree, so it is not proof that
    the worktree at that path is already admitted.
    """

    with store._connect() as connection:
        rows = connection.execute(
            """
            select private_root from workspace_assessment_state
            where observed_stat_digest is null or observed_stat_digest != ?
            """,
            (unavailable_digest,),
        ).fetchall()
    return {str(row[0]) for row in rows}


def end_unregistered_install_admissions(store: Any, registered_roots: Collection[str]) -> int:
    """End automatic admissions whose root no active install registers."""

    with store._connect() as connection:
        connection.execute("begin immediate")
        rows = connection.execute(
            """
            select s.codebase_key, s.worktree_key, s.private_root from workspace_assessment_state s
            join workspace_assessment_install_admissions a using (codebase_key, worktree_key)
            """
        ).fetchall()
        ended = [(str(row[0]), str(row[1])) for row in rows if str(row[2]) not in registered_roots]
        _delete_worktrees(connection, ended)
    return len(ended)


def _delete_worktrees(connection: Any, keys: list[tuple[str, str]]) -> None:
    for table in _WORKTREE_TABLES:
        connection.executemany(f"delete from {table} where codebase_key = ? and worktree_key = ?", keys)


__all__ = ["admit_and_queue", "end_unregistered_install_admissions", "watched_roots"]
