"""Admitting worktrees for background assessment, and ending install admissions.

An admission, its first observation and its first run are written in one
transaction, so a failure part way leaves nothing behind for the next poll to
mistake for a finished admission. A worktree admitted automatically, because a
harness install registered it, is marked; it stops being watched once no active
install registers its root, unless someone admitted it themselves.

Ending an admission stops the worker from checking the worktree and nothing
else: its run history and fix proposals are the record of what Guard found and
of any manifest edit it made, so they are kept. The worktree's state row stays,
paused and marked ended, and a later admission of the same worktree resumes it.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

from .workspace_assessment_store import WorktreeKeys, _enqueue_locked

# True for a state row whose automatic admission has ended.
_IS_ENDED = """exists (
    select 1 from workspace_assessment_ended_admissions e
    where e.codebase_key = workspace_assessment_state.codebase_key
      and e.worktree_key = workspace_assessment_state.worktree_key
)"""


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

    # A manual admission takes over any existing row. An automatic one leaves it
    # alone unless its admission had ended, which a new registration revives.
    takeover = "update set private_root = excluded.private_root, paused = 0"
    conflict = f"{takeover} where {_IS_ENDED}" if automatic else takeover
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
        connection.execute(
            "delete from workspace_assessment_ended_admissions where codebase_key = ? and worktree_key = ?",
            (keys.codebase_key, keys.worktree_key),
        )
        if automatic:
            replaced = connection.execute(
                """
                select s.codebase_key, s.worktree_key from workspace_assessment_state s
                join workspace_assessment_install_admissions a using (codebase_key, worktree_key)
                where s.private_root = ? and not (s.codebase_key = ? and s.worktree_key = ?)
                """,
                (root, keys.codebase_key, keys.worktree_key),
            ).fetchall()
            _end_admissions(connection, [(str(row[0]), str(row[1])) for row in replaced], now_ms=now_ms)
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
            f"""
            select private_root from workspace_assessment_state
            where (observed_stat_digest is null or observed_stat_digest != ?)
              and not {_IS_ENDED}
            """,
            (unavailable_digest,),
        ).fetchall()
    return {str(row[0]) for row in rows}


def is_manual_admission(store: Any, keys: WorktreeKeys, *, root: str) -> bool:
    """Return whether someone admitted this worktree at ``root`` themselves and it is still checked."""

    with store._connect() as connection:
        row = connection.execute(
            """
            select 1 from workspace_assessment_state s
            where s.codebase_key = ? and s.worktree_key = ? and s.private_root = ? and s.paused = 0
              and not exists (
                select 1 from workspace_assessment_install_admissions a
                where a.codebase_key = s.codebase_key and a.worktree_key = s.worktree_key
              )
            """,
            (keys.codebase_key, keys.worktree_key, root),
        ).fetchone()
    return row is not None


def end_unregistered_install_admissions(store: Any, registered_roots: Collection[str], *, now_ms: int) -> int:
    """End automatic admissions whose root no active install registers.

    Only the admission ends; the worktree's runs, findings and fix proposals stay.
    """

    with store._connect() as connection:
        connection.execute("begin immediate")
        rows = connection.execute(
            """
            select s.codebase_key, s.worktree_key, s.private_root from workspace_assessment_state s
            join workspace_assessment_install_admissions a using (codebase_key, worktree_key)
            """
        ).fetchall()
        ended = [(str(row[0]), str(row[1])) for row in rows if str(row[2]) not in registered_roots]
        _end_admissions(connection, ended, now_ms=now_ms)
    return len(ended)


def _end_admissions(connection: Any, keys: list[tuple[str, str]], *, now_ms: int) -> None:
    """Stop watching these worktrees, keeping every record that names them."""

    connection.executemany(
        "delete from workspace_assessment_install_admissions where codebase_key = ? and worktree_key = ?", keys
    )
    connection.executemany(
        "update workspace_assessment_state set paused = 1 where codebase_key = ? and worktree_key = ?", keys
    )
    connection.executemany(
        "insert or ignore into workspace_assessment_ended_admissions (codebase_key, worktree_key, ended_at_ms)"
        " values (?, ?, ?)",
        [(codebase_key, worktree_key, now_ms) for codebase_key, worktree_key in keys],
    )


__all__ = ["admit_and_queue", "end_unregistered_install_admissions", "is_manual_admission", "watched_roots"]
