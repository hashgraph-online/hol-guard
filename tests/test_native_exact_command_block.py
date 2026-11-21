"""The resident handles saved exact-command blocks on the daemon hook path."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_hook_render import native_exact_command_block_response
from codex_plugin_scanner.guard.store import GuardStore

_COMMAND = "pytest -q"
_EXACT_ID = "memory:exact-shell-command:" + hashlib.sha256(_COMMAND.encode()).hexdigest()
_REVIEW = {
    "decision": "deny",
    "minimum_action": "review",
    "policy_action": "review",
    "reason_code": "native_command_extension_review",
    "reason": "Review this command.",
    "action": {"action_type": "command"},
}


@pytest.fixture
def store(tmp_path: Path, native_context_digest: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


def _save(store: GuardStore, *, harness: str = "*", action: str = "block", source: str = "approval-gate") -> None:
    store.upsert_policy(
        PolicyDecision(harness=harness, scope="artifact", artifact_id=_EXACT_ID, action=action, source=source),
        "2026-10-08T00:00:00+00:00",
        remote_write_authorized=source == "policy-bundle-canonical",
    )


def _respond(
    store: GuardStore,
    *,
    command: str | None = _COMMAND,
    verdict: dict[str, object] = _REVIEW,
    edge_hint: bool | None = True,
) -> dict[str, object] | None:
    return native_exact_command_block_response(
        store, harness="claude-code", command=command, native_result=verdict, workspace=None, edge_hint=edge_hint
    )


@pytest.mark.parametrize(
    ("source", "code", "text"),
    [
        ("policy-bundle-canonical", "policy_exact_command_block", "Guard Cloud policy blocks"),
        ("approval-gate", "saved_exact_command_block", "You chose to always block"),
    ],
)
def test_a_saved_block_denies_the_exact_command(store, source, code, text):
    _save(store, source=source)
    response = _respond(store, edge_hint=None)
    assert response is not None
    assert response["reason_code"] == code
    assert response["approval_reuse_status"] == "blocked"
    assert text in str(response)
    assert "Do not retry it" in str(response)


def test_other_commands_and_tool_actions_keep_their_review(store):
    _save(store)
    assert _respond(store, command="pytest -q tests") is None
    assert _respond(store, command=None) is None
    assert _respond(store, verdict={**_REVIEW, "action": {"action_type": "mcp_tool"}}) is None


@pytest.mark.parametrize(("harness", "action"), [("codex", "block"), ("*", "allow")])
def test_other_harnesses_and_saved_allows_do_not_block(store, harness, action):
    _save(store, harness=harness, action=action)
    assert _respond(store) is None


def test_an_edge_that_found_no_block_skips_integrity_evidence(store, monkeypatch):
    _save(store)

    def unexpected():
        pytest.fail("The edge already ruled out a saved block")

    monkeypatch.setattr(store, "policy_lookup_evidence", unexpected)
    assert _respond(store, edge_hint=False) is None


def test_a_block_the_store_cannot_read_still_denies(store, monkeypatch):
    _save(store)

    def unavailable():
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "policy_lookup_evidence", unavailable)
    response = _respond(store)
    assert response is not None
    assert response["reason_code"] == "saved_exact_command_unreadable"
    assert response["approval_reuse_status"] == "blocked"
