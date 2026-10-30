"""A saved or Guard Cloud block on one exact shell command stops it at the hook.

Exact-command rules are stored under ``memory:exact-shell-command:<sha256>``,
which a native review's exact-action token never names, so the review flow
has to ask for them itself before it reuses any allow.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import sqlite3
from collections.abc import Iterator
from typing import Any

from codex_plugin_scanner.guard.daemon.hook_native_saved_approval import native_exact_command_block_response

_COMMAND = "npm publish"
_EXACT_ID = "memory:exact-shell-command:" + hashlib.sha256(_COMMAND.encode()).hexdigest()
_REVIEW = {
    "decision": "deny",
    "minimum_action": "review",
    "policy_action": "review",
    "reason_code": "native_command_extension_review",
    "reason": "Review this command.",
    "action": {"action_type": "command"},
}


class _Store:
    """The two store reads the hook makes, over a real ``policy_decisions`` table."""

    def __init__(self, rows: list[tuple[str, str, str, str]], *, lookup_error: Exception | None = None) -> None:
        self._connection = sqlite3.connect(":memory:")
        self._connection.execute(
            "create table policy_decisions (harness text, scope text, artifact_id text, action text, source text)"
        )
        self._connection.executemany(
            "insert into policy_decisions values (?, 'artifact', ?, ?, ?)",
            rows,
        )
        self._lookup_error = lookup_error
        self.lookups: list[str] = []

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        yield self._connection

    def resolve_policy_decision_lookup(self, harness: str, artifact_id: str, **_kwargs: object) -> dict[str, Any]:
        self.lookups.append(artifact_id)
        if self._lookup_error is not None:
            raise self._lookup_error
        row = self._connection.execute(
            "select harness, artifact_id, action, source from policy_decisions"
            " where harness in (?, '*') and artifact_id = ? order by harness = '*' limit 1",
            (harness, artifact_id),
        ).fetchone()
        if row is None:
            return {"decision": None}
        return {"decision": {"scope": "artifact", "artifact_id": row[1], "action": row[2], "source": row[3]}}


def _respond(store: _Store, command: str | None = _COMMAND, review: dict[str, Any] | None = None) -> object:
    return native_exact_command_block_response(
        store,
        harness="claude-code",
        command=command,
        native_result=copy.deepcopy(review or _REVIEW),
        workspace=None,
    )


def test_a_cloud_policy_block_denies_the_exact_command() -> None:
    response = _respond(_Store([("*", _EXACT_ID, "block", "policy-bundle-canonical")]))

    assert isinstance(response, dict)
    assert response["approval_reuse_status"] == "blocked"
    rendered = str(response)
    assert "Guard Cloud policy blocks this exact command" in rendered
    assert "Do not retry it" in rendered


def test_a_remembered_local_block_names_the_user_choice() -> None:
    response = _respond(_Store([("claude-code", _EXACT_ID, "block", "local")]))

    assert isinstance(response, dict)
    assert "You chose to always block this exact command" in str(response)


def test_other_commands_harnesses_and_actions_keep_their_review() -> None:
    blocked = _Store([("*", _EXACT_ID, "block", "policy-bundle-canonical")])
    assert _respond(blocked, command="npm publish --dry-run") is None
    assert _respond(blocked, command=None) is None
    assert _respond(blocked, review={**_REVIEW, "action": {"action_type": "mcp_tool"}}) is None
    assert _respond(_Store([("codex", _EXACT_ID, "block", "policy-bundle-canonical")])) is None
    allowed = _Store([("*", _EXACT_ID, "allow", "policy-bundle-canonical")])
    assert _respond(allowed) is None
    # No block row means no lookup at all on the hot path.
    assert allowed.lookups == []


def test_a_block_the_store_cannot_read_still_denies() -> None:
    store = _Store(
        [("*", _EXACT_ID, "block", "policy-bundle-canonical")],
        lookup_error=RuntimeError("integrity"),
    )

    response = _respond(store)

    assert isinstance(response, dict)
    assert response["approval_reuse_status"] == "blocked"
    assert "could not read the saved block" in str(response)
