"""A saved or Guard Cloud block on an exact command stops it even when Guard allows it.

Guard's own review allows most commands outright, so the exact-command block
has to be applied on the allowed path too, not only to commands Guard reviews.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_pretool_edge_fixtures import _edge, _sync_receipt
from tests.native_review_evidence_support import with_review_evidence

_BLOCKED = "npm publish"


def _allowing_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[HookWorker, GuardStore]:
    edge = _edge("codex", "PreToolUse", "command")
    result = edge["result"]
    assert isinstance(result, dict)
    result.update(
        decision="allow",
        policy_action="allow",
        minimum_action="allow",
        reason_code="native_pre_tool_allowed",
        reason="Guard allows this command.",
    )
    edge["harness_response"] = {}
    _sync_receipt(edge)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **kwargs: with_review_evidence(edge, **kwargs),
    )
    store = GuardStore(tmp_path / "guard-home")
    return HookWorker(store=store), store


def _review(worker: HookWorker, tmp_path: Path, command: str) -> dict[str, object]:
    return worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}},
        params={},
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )


def _block(store: GuardStore, *, harness: str, source: str) -> None:
    store.upsert_policy(
        PolicyDecision(
            harness=harness,
            scope="artifact",
            action="block",
            artifact_id="memory:exact-shell-command:" + hashlib.sha256(_BLOCKED.encode()).hexdigest(),
            source=source,
        ),
        "2026-10-30T00:00:00+00:00",
        remote_write_authorized=source == "policy-bundle-canonical",
    )


@pytest.mark.parametrize(
    ("harness", "source", "reason_code"),
    [
        ("*", "policy-bundle-canonical", "policy_exact_command_block"),
        ("codex", "approval-gate", "saved_exact_command_block"),
    ],
)
def test_an_exact_command_block_stops_a_command_guard_allows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str, source: str, reason_code: str
) -> None:
    worker, store = _allowing_worker(tmp_path, monkeypatch)
    assert _review(worker, tmp_path, _BLOCKED).get("reason_code") != reason_code
    _block(store, harness=harness, source=source)

    response = _review(worker, tmp_path, _BLOCKED)
    hook_output = response["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "deny"
    assert response["reason_code"] == reason_code
    assert "approval_request_id" not in response

    # Another command, and the same command from another agent, keep the allow.
    assert _review(worker, tmp_path, "npm test").get("reason_code") != reason_code


def test_another_agents_exact_command_block_leaves_the_allow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    worker, store = _allowing_worker(tmp_path, monkeypatch)
    _block(store, harness="claude-code", source="policy-bundle-canonical")
    response = _review(worker, tmp_path, _BLOCKED)
    assert "hookSpecificOutput" not in response or response["hookSpecificOutput"].get("permissionDecision") != "deny"
