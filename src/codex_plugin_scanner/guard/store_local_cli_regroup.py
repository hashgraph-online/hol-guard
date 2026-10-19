"""Regroup pending connector setup reviews written before they carried a group.

A review held only because Guard did not recognise the local CLI it launches is
queued under ``connector:<identity_hash>:<action digest>`` so the Inbox shows one
setup card per connector. Reviews queued before that grouping existed sit under
their per-action group. The v14 migration moves the pending ones that can be tied
to one observed CLI with no decision yet, and nothing else: no row is created,
resolved or deleted, and no notification is sent. Grouping reduces cards, not
evidence.

The tie is deliberately narrow. The stored command must be a plain
``program [argument ...]`` of safe ASCII tokens (no quoting, expansion,
redirection or compound operators), the program's name must match exactly one
plain executable observation, and that CLI must not already be allowed or
blocked. A program written with a path must be that observation's own recorded
executable path, so two binaries that share a name are never merged; a bare
name carries no path to contradict. Anything else keeps the group it has.
``connector_queue_group_id`` mirrors ``connector_setup::queue_group_id`` in the
resident; the shared vectors in ``connector_group_vectors.json`` pin both. A
stored review keeps its workspace, not the directory the hook ran in, so a row
without a workspace keeps its group and one launched from a subdirectory lands
in a sibling group under the same connector prefix.
"""

from __future__ import annotations

import hashlib
import logging
import re
import sqlite3
from typing import Final

_LOGGER = logging.getLogger(__name__)

# The stored text of the two reviews that mean only "Guard does not recognise
# this command": the generic review, and the one for a program the workspace
# sandbox cannot run. Mirrors `connector_setup::NON_RECOGNITION_REASON_CODES`;
# the approval row keeps this text, not the code.
NON_RECOGNITION_RISK_SUMMARIES: Final = (
    "HOL Guard requires review because this command could not be confirmed read-only. "
    "Splitting it into simpler commands can let the read-only parts run without review.",
    "HOL Guard's workspace sandbox cannot run this program, so it was not started there.",
)
ACTION_DIGEST_HEX: Final = 16
_MAX_COMMAND_CHARS: Final = 4096
_SIMPLE_TOKEN: Final = re.compile(r"[A-Za-z0-9._/@:+=%,-]+")
# Runners launch another program, so the first word is not the connector.
_RUNNERS: Final = frozenset({"npx", "bunx", "pnpm", "pnpx", "yarn", "npm"})
_ANSI: Final = re.compile(r"\x1b\[[0-9;]*[mABCDEFGHJKSTfhinsu]")
_REQUEST_ID: Final = re.compile(r"\b(?:req|request|approval|id)[-_][a-zA-Z0-9_-]{4,64}\b", re.IGNORECASE)
_UUID: Final = re.compile(r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b")
_TIMESTAMP: Final = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?\b")
_PORT: Final = re.compile(r"(?:--port|-p)\s+\d{2,5}\b", re.IGNORECASE)
_SPACE: Final = re.compile(r"\s+")


def normalize_command_identity(command: str) -> str:
    """`normalize_command_identity` of the resident, for ASCII text."""

    text = _ANSI.sub("", command)
    text = _REQUEST_ID.sub("<request-id>", text)
    text = _UUID.sub("<uuid>", text)
    text = _TIMESTAMP.sub("<timestamp>", text)
    text = _PORT.sub("<port-flag>", text)
    return _SPACE.sub(" ", text).strip()


def connector_queue_group_id(identity_hash: str, cwd: str, command: str) -> str | None:
    """``connector:<identity_hash>:<action digest>``, or ``None`` outside the ASCII subset.

    The digest binds the launch directory and the command, as the resident's does.
    """

    if not command.isascii():
        return None
    material = cwd.encode("utf-8") + b"\0" + normalize_command_identity(command).encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()
    return f"connector:{identity_hash}:{digest[:ACTION_DIGEST_HEX]}"


def connector_program_name(command: str) -> str | None:
    """The program a plain command launches, or ``None`` for any other shape."""

    if not command or len(command) > _MAX_COMMAND_CHARS or not command.isascii():
        return None
    tokens = command.split()
    if not all(_SIMPLE_TOKEN.fullmatch(token) for token in tokens):
        return None
    program = tokens[0]
    if "=" in program or program.endswith("/"):
        return None
    name = program.rsplit("/", 1)[-1]
    if not name or name in _RUNNERS or name.startswith("."):
        return None
    return name


def connector_program_path(command: str) -> str | None:
    """The program token when it is written with a path, else ``None`` for a bare name."""

    program = command.split()[0] if command.split() else ""
    return program if "/" in program else None


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
    rows = connection.execute(
        f"""
        select request_id, raw_command_text, queue_group_id, workspace from approval_requests
        where status = 'pending' and raw_command_text is not null
          and risk_summary in ({marks})
        order by created_at, request_id
        """,
        NON_RECOGNITION_RISK_SUMMARIES,
    ).fetchall()
    moved = 0
    identities: dict[tuple[str, str | None], str | None] = {}
    for request_id, command, group, workspace in ((row[0], row[1], row[2], row[3]) for row in rows):
        if not isinstance(command, str) or not isinstance(workspace, str) or not workspace:
            continue
        name = connector_program_name(command)
        if name is None:
            continue
        program_path = connector_program_path(command)
        if (name, program_path) not in identities:
            identities[(name, program_path)] = _undecided_identity(connection, name, program_path)
        identity_hash = identities[(name, program_path)]
        target = None if identity_hash is None else connector_queue_group_id(identity_hash, workspace, command)
        if target is None or target == group:
            continue
        connection.execute("update approval_requests set queue_group_id = ? where request_id = ?", (target, request_id))
        moved += 1
    return moved


def _undecided_identity(connection: sqlite3.Connection, name: str, program_path: str | None) -> str | None:
    """The identity hash of the one plain executable called ``name``, while it has no decision.

    A program written with a path ties only to the observation recorded at that
    exact path; an observation without a path cannot vouch for one.
    """

    found = connection.execute(
        """
        select cli_id, identity_hash, source_path from local_cli_observation
        where name = ? and kind = 'executable' and surface = 'cli'
          and interpreter_name is null and example_label = name
        limit 2
        """,
        (name,),
    ).fetchall()
    if len(found) != 1:
        return None
    cli_id, identity_hash, source_path = found[0][0], found[0][1], found[0][2]
    if not isinstance(cli_id, str) or not isinstance(identity_hash, str):
        return None
    if program_path is not None and source_path != program_path:
        return None
    if _has_columns(connection, "local_cli_grant", {"cli_id", "identity_hash", "state"}):
        decided = connection.execute(
            "select 1 from local_cli_grant where cli_id = ? and identity_hash = ? and state in ('allowed', 'blocked')",
            (cli_id, identity_hash),
        ).fetchone()
        if decided is not None:
            return None
    return identity_hash


def _has_columns(connection: sqlite3.Connection, table: str, required: set[str]) -> bool:
    names = {str(row[1]) for row in connection.execute(f"pragma table_info({table})").fetchall()}
    return required <= names


__all__ = [
    "ACTION_DIGEST_HEX",
    "NON_RECOGNITION_RISK_SUMMARIES",
    "connector_program_name",
    "connector_program_path",
    "connector_queue_group_id",
    "normalize_command_identity",
    "regroup_pending_connector_reviews",
]
