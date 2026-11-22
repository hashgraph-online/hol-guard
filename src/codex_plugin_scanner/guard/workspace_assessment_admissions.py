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

The native store runs each of these as one store transaction.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection
from typing import Any, Final

from .workspace_assessment_store import WorktreeKeys

# A runaway store cannot keep a listing loop going forever.
_MAX_PAGES: Final = 4096


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

    method = "admit_workspace_assessment"
    answer = store._native_store_call(
        method,
        {
            "codebase_key": keys.codebase_key,
            "worktree_key": keys.worktree_key,
            "root": root,
            "now_ms": now_ms,
            "automatic": automatic,
            "stat_digest": stat_digest,
            "feed_digest": feed_digest,
            "detector_set_digest": detector_set_digest,
            "run_id": uuid.uuid4().hex,
        },
    )
    if answer is not None and (not isinstance(answer, str) or not answer):
        raise RuntimeError(f"native {method} returned no answer")
    return answer


def watched_roots(store: Any, *, unavailable_digest: str) -> set[str]:
    """Roots of admitted worktrees, leaving out those last observed unavailable.

    An unavailable root may now name another worktree, so it is not proof that
    the worktree at that path is already admitted.
    """

    method = "workspace_assessment_watched_roots"
    roots: set[str] = set()
    cursor: object = None
    for _ in range(_MAX_PAGES):
        args: dict[str, object] = {"unavailable_digest": unavailable_digest}
        if cursor is not None:
            args["after"] = cursor
        answer = store._native_store_call(method, args)
        if not isinstance(answer, dict) or set(answer) != {"items", "next"}:
            raise RuntimeError(f"native {method} returned no answer")
        items = answer["items"]
        previous, cursor = cursor, answer["next"]
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise RuntimeError(f"native {method} returned no answer")
        if cursor is not None and (not isinstance(cursor, list) or not items or cursor == previous):
            raise RuntimeError(f"native {method} returned no answer")
        roots.update(items)
        if cursor is None:
            return roots
    raise RuntimeError(f"native {method} kept paging")


def is_manual_admission(store: Any, keys: WorktreeKeys, *, root: str) -> bool:
    """Return whether someone admitted this worktree at ``root`` themselves and it is still checked."""

    method = "is_manual_workspace_assessment_admission"
    answer = store._native_store_call(
        method, {"codebase_key": keys.codebase_key, "worktree_key": keys.worktree_key, "root": root}
    )
    if not isinstance(answer, bool):
        raise RuntimeError(f"native {method} returned no answer")
    return answer


def end_unregistered_install_admissions(store: Any, registered_roots: Collection[str], *, now_ms: int) -> int:
    """End automatic admissions whose root no active install registers.

    Only the admission ends; the worktree's runs, findings and fix proposals stay.
    """

    method = "end_unregistered_workspace_assessment_admissions"
    answer = store._native_store_call(method, {"registered_roots": sorted(registered_roots), "now_ms": now_ms})
    if isinstance(answer, bool) or not isinstance(answer, int) or answer < 0:
        raise RuntimeError(f"native {method} returned no answer")
    return answer


__all__ = ["admit_and_queue", "end_unregistered_install_admissions", "is_manual_admission", "watched_roots"]
