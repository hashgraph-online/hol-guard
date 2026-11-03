"""Regroup pending connector setup reviews written before they carried a group.

A review held only because Guard did not recognise the local CLI it launches is
queued under ``connector:<identity_hash>:<action digest>`` so the Inbox shows one
setup card per connector. Reviews queued before that grouping existed sit under
their per-action group. The v14 migration moves the pending ones that tie to one
observed CLI with no decision yet, and nothing else: no row is created, resolved
or deleted, and no notification is sent. Grouping reduces cards, not evidence.

The native ``connector_regroup`` kind decides which reviews tie to a CLI and
where they move; this module reads the rows it needs and applies the moves. A
runtime that cannot answer leaves every review where it was.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from typing import Final, cast

_LOGGER = logging.getLogger(__name__)

# The stored text of the reviews that mean only "Guard does not recognise this
# command": the generic review (with split advice for a chain, without it for a
# single step), and the one for a program the workspace sandbox cannot run.
# Mirrors `connector_setup::NON_RECOGNITION_REASON_CODES`; the approval row keeps
# this text, not the code.
NON_RECOGNITION_RISK_SUMMARIES: Final = (
    "HOL Guard requires review because this command could not be confirmed read-only. "
    "Splitting it into simpler commands can let the read-only parts run without review.",
    "HOL Guard requires review because this command could not be confirmed read-only.",
    "HOL Guard's workspace sandbox cannot run this program, so it was not started there.",
)
# The native kind never moves a longer command, so those rows are not sent.
_MAX_COMMAND_CHARS: Final = 4096
_REVIEW_BATCH: Final = 200


def regroup_pending_connector_reviews(connection: sqlite3.Connection) -> int:
    """Regroup the pending reviews that tie to one undecided CLI; returns how many moved.

    Best effort: the migration that calls this must not fail because of it, so a
    store error leaves every row as it was.
    """

    connection.execute("savepoint connector_regroup")
    try:
        moved = _regroup(connection)
    except sqlite3.Error as error:
        connection.execute("rollback to savepoint connector_regroup")
        connection.execute("release savepoint connector_regroup")
        _LOGGER.warning("Connector review regroup skipped (%s)", type(error).__name__)
        return 0
    connection.execute("release savepoint connector_regroup")
    return moved


def _regroup(connection: sqlite3.Connection) -> int:
    if not _has_columns(
        connection, "approval_requests", {"request_id", "status", "risk_summary", "raw_command_text", "queue_group_id"}
    ) or not _has_columns(connection, "local_cli_observation", {"cli_id", "identity_hash", "name", "kind", "surface"}):
        return 0
    marks = ", ".join("?" for _ in NON_RECOGNITION_RISK_SUMMARIES)
    reviews = connection.execute(
        f"""
        select request_id, raw_command_text, queue_group_id, workspace from approval_requests
        where status = 'pending' and raw_command_text is not null
          and length(raw_command_text) <= ? and workspace is not null and workspace != ''
          and risk_summary in ({marks})
        order by created_at, request_id
        """,
        (_MAX_COMMAND_CHARS, *NON_RECOGNITION_RISK_SUMMARIES),
    ).fetchall()
    if not reviews:
        return 0
    observations = connection.execute(
        """
        select cli_id, identity_hash, name, source_path from local_cli_observation
        where kind = 'executable' and surface = 'cli'
          and interpreter_name is null and example_label = name
        """
    ).fetchall()
    decided = (
        connection.execute(
            "select cli_id, identity_hash from local_cli_grant where state in ('allowed', 'blocked')"
        ).fetchall()
        if _has_columns(connection, "local_cli_grant", {"cli_id", "identity_hash", "state"})
        else []
    )
    if not _verifier_key_ready():
        # Without the key the native call would provision it through a second
        # store, which waits on the schema lock this migration holds.
        _LOGGER.warning("Connector review regroup skipped (native verifier key not provisioned)")
        return 0
    planned: list[tuple[object, str]] = []
    # Batches keep each request well under the native transport limit. A batch
    # carries only the observations whose name occurs in one of its commands
    # (the program a command names is always in its text) and the decisions
    # for those CLIs.
    for start in range(0, len(reviews), _REVIEW_BATCH):
        batch = reviews[start : start + _REVIEW_BATCH]
        commands = [str(row[1]) for row in batch]
        named = [row for row in observations if row[2] and any(str(row[2]) in command for command in commands)]
        identities = {(row[0], row[1]) for row in named}
        moves = _native_moves(
            {
                "reviews": [list(row) for row in batch],
                "observations": [list(row) for row in named],
                "decided": [list(row) for row in decided if (row[0], row[1]) in identities],
            }
        )
        if moves is None:
            # All or nothing: a batch that cannot be answered leaves every
            # review where it was, including those earlier batches would move.
            return 0
        planned.extend(moves)
    for request_id, target in planned:
        connection.execute("update approval_requests set queue_group_id = ? where request_id = ?", (target, request_id))
    return len(planned)


def _verifier_key_ready() -> bool:
    from .native_context import _resolve_digest_home  # pyright: ignore[reportPrivateUsage]
    from .native_policy_snapshot_constants import NATIVE_POLICY_VERIFIER_KEY_NAME, NATIVE_RUNTIME_STATE_DIRECTORY

    key = _resolve_digest_home(None) / NATIVE_RUNTIME_STATE_DIRECTORY / NATIVE_POLICY_VERIFIER_KEY_NAME
    return os.path.lexists(key)


def _native_moves(request: dict[str, object]) -> list[tuple[object, str]] | None:
    """The ``[request_id, queue_group_id]`` moves the native runtime answers, or ``None`` when it cannot."""

    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority("connector_regroup", request)
    except NativeRunnerAuthorityError as error:
        _LOGGER.warning("Connector review regroup skipped (%s)", error)
        return None
    moves = answer.get("moves")
    if not isinstance(moves, list):
        return None
    checked: list[tuple[object, str]] = []
    for move in cast("list[object]", moves):
        if not isinstance(move, list) or len(cast("list[object]", move)) != 2:
            return None
        request_id, target = cast("list[object]", move)
        if not isinstance(target, str) or not target.startswith("connector:"):
            return None
        checked.append((request_id, target))
    return checked


def _has_columns(connection: sqlite3.Connection, table: str, required: set[str]) -> bool:
    names = {str(row[1]) for row in connection.execute(f"pragma table_info({table})").fetchall()}
    return required <= names


__all__ = [
    "NON_RECOGNITION_RISK_SUMMARIES",
    "regroup_pending_connector_reviews",
]
