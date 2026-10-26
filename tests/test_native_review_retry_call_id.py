"""Claude Code and Codex retries carry a new ``tool_use_id`` for the same action.

The model emits a new tool-use block for every attempt, so an Allow once approval
has to reach the retry that follows it although its transport id differs. The
mocked receipts here follow the identity the resident computes
(``request_payload_identity``); the real resident is exercised by
``test_native_review_approved_shell_retry.py``.
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.test_native_review_fixtures import _edge, _worker


def _kwargs(tmp_path: Path, harness: str, payload: dict[str, object]) -> dict[str, object]:
    return {
        "payload": payload,
        "params": {},
        "default_harness": harness,
        "home_dir": tmp_path / "home",
        "guard_home": tmp_path / "guard-home",
        "workspace": tmp_path / "workspace",
    }


def _approve_once(store: object, request_id: str) -> None:
    store.resolve_approval_request(  # type: ignore[attr-defined]
        request_id,
        resolution_action="allow",
        resolution_scope="once",
        reason="operator approved exact action",
        resolved_at=datetime.now(timezone.utc).isoformat(),
    )


def _not_allowed(response: dict[str, object]) -> None:
    hook_output = response["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] != "allow"
    assert response["policy_action"] == "review"


@pytest.mark.parametrize("harness", ("claude-code", "codex"))
def test_retry_under_a_new_tool_use_id_consumes_the_approval_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str
) -> None:
    worker, store = _worker(tmp_path, monkeypatch, _edge(harness, action_type="unknown"))
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "toolu_original",
        "session_id": "fixture-session",
        "tool_input": {"command": "ls -la"},
    }
    kwargs = _kwargs(tmp_path, harness, payload)
    first = worker.review_http_payload(**kwargs)
    assert first["policy_action"] == "review"
    _approve_once(store, first["approval_request_id"])
    payload["tool_use_id"] = "toolu_retry"
    retry = worker.review_http_payload(**kwargs)
    assert retry["policy_action"] == "allow"
    assert retry.get("block") is not True
    assert store.list_approval_requests(status="pending") == []
    payload["tool_use_id"] = "toolu_later"
    later = worker.review_http_payload(**kwargs)
    _not_allowed(later)


@pytest.mark.parametrize("harness", ("claude-code", "codex"))
def test_a_changed_command_or_session_does_not_inherit_the_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str
) -> None:
    worker, store = _worker(tmp_path, monkeypatch, _edge(harness, action_type="unknown"))
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "toolu_original",
        "session_id": "fixture-session",
        "tool_input": {"command": "ls -la"},
    }
    kwargs = _kwargs(tmp_path, harness, payload)
    first = worker.review_http_payload(**kwargs)
    _approve_once(store, first["approval_request_id"])
    payload["tool_use_id"] = "toolu_retry"
    payload["tool_input"] = {"command": "ls -l"}
    reworded = worker.review_http_payload(**kwargs)
    _not_allowed(reworded)
    assert reworded["approval_request_id"] != first["approval_request_id"]
    payload["tool_input"] = {"command": "ls -la"}
    payload["session_id"] = "another-session"
    other_session = worker.review_http_payload(**kwargs)
    _not_allowed(other_session)
    assert other_session["approval_request_id"] != first["approval_request_id"]


@pytest.mark.parametrize("harness", ("claude-code", "codex"))
def test_sessionless_retry_does_not_inherit_the_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str
) -> None:
    worker, store = _worker(tmp_path, monkeypatch, _edge(harness, action_type="unknown"))
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "toolu_original",
        "tool_input": {"command": "ls -la"},
    }
    kwargs = _kwargs(tmp_path, harness, payload)
    first = worker.review_http_payload(**kwargs)
    _approve_once(store, first["approval_request_id"])
    payload["tool_use_id"] = "toolu_retry"
    retry = worker.review_http_payload(**kwargs)
    _not_allowed(retry)
    assert retry["approval_request_id"] != first["approval_request_id"]
