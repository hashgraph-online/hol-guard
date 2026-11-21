from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_claude_guard_question
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.native_claude_guard_question import settle_claude_guard_question

_VECTORS = (
    Path(__file__).resolve().parents[1]
    / "rust/crates/guard-runtime/tests/fixtures/claude_guard_question_vectors.json.gz"
)
_CASES = json.loads(gzip.decompress(_VECTORS.read_bytes()))["cases"]
_PLAN = {
    "stored_artifact_hash": "hash-1",
    "policy_action": "allow",
    "events": [{"name": "claude/native_permission_saved", "payload": {}, "before_policy": False}],
    "inventory_approved": True,
}
_SAVE = {
    "outcome": "save",
    "artifact_id": "claude-code:project:bash",
    "reason": "Allowed through HOL Guard AskUserQuestion approval.",
    "source": "claude-ask-user-question",
    "plan": _PLAN,
}


def _could_be_question(case: dict, event: str | None) -> bool:
    tool_name = case["payload"].get("tool_name")
    return event == "PostToolUse" and isinstance(tool_name, str) and tool_name.strip().lower() == "askuserquestion"


@pytest.mark.parametrize("case", _CASES, ids=[case["name"] for case in _CASES])
def test_transport_forwards_the_recorded_hook(
    case: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = guard_commands_module._hook_event_name(case["payload"])
    payloads: list[str] = []
    monkeypatch.setattr(
        native_claude_guard_question,
        "hook_authority_state",
        lambda _store, _op, **fields: payloads.append(fields["payload"]),
    )
    settle_claude_guard_question(
        object(), session_id="session-1", payload=case["payload"], event=event, now="2026-10-26T00:00:00+00:00"
    )
    if not _could_be_question(case, event):
        assert payloads == []
        return
    (raw,) = payloads
    forwarded = json.loads(raw)
    assert forwarded == {
        "event": event,
        **{name: case["payload"].get(name) for name in ("tool_name", "tool_input", "tool_response")},
    }
    response = forwarded["tool_response"]
    if isinstance(response, dict) and isinstance(response.get("answers"), dict):
        assert list(response["answers"]) == list(case["payload"]["tool_response"]["answers"])


def _settle(monkeypatch: pytest.MonkeyPatch, reply: object, payload: dict) -> tuple[object, dict]:
    calls: list[dict] = []

    def fake(_store: object, op: str, **fields: object) -> object:
        calls.append({"op": op, **fields})
        return reply

    monkeypatch.setattr(native_claude_guard_question, "hook_authority_state", fake)
    settled = settle_claude_guard_question(
        object(), session_id="session-1", payload=payload, event="PostToolUse", now="2026-10-26T00:00:00+00:00"
    )
    assert len(calls) == 1
    return settled, calls[0]


@pytest.mark.parametrize(
    "reply",
    [
        None,
        {},
        {"outcome": "none"},
        {"outcome": "allow"},
        {"outcome": "unseen", "extra": 1},
        {"outcome": []},
        {"outcome": {}},
        {**_SAVE, "artifact_id": ""},
        {**_SAVE, "reason": None},
        {key: value for key, value in _SAVE.items() if key != "source"},
        {**_SAVE, "extra": 1},
        {**_SAVE, "plan": {**_PLAN, "policy_action": "approve"}},
        {**_SAVE, "plan": {**_PLAN, "stored_artifact_hash": None}},
        {**_SAVE, "plan": {**_PLAN, "events": []}},
        {**_SAVE, "plan": {**_PLAN, "inventory_approved": "yes"}},
    ],
)
def test_native_failure_is_never_an_approval(monkeypatch: pytest.MonkeyPatch, reply: object) -> None:
    case = next(case for case in _CASES if case["name"] == "answers-keyed-allow-once")

    settled, _call = _settle(monkeypatch, reply, case["payload"])

    assert settled is None


@pytest.mark.parametrize("outcome", ["unseen", "unanswered"])
def test_an_unsaved_answer_is_still_the_question(monkeypatch: pytest.MonkeyPatch, outcome: str) -> None:
    case = next(case for case in _CASES if case["name"] == "answers-keyed-allow-once")

    settled, _call = _settle(monkeypatch, {"outcome": outcome}, case["payload"])

    assert settled == {"outcome": outcome}


def test_a_saved_answer_carries_its_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    case = next(case for case in _CASES if case["name"] == "answers-keyed-allow-once")

    settled, call = _settle(monkeypatch, _SAVE, case["payload"])

    assert settled == _SAVE
    assert call["op"] == "claude_question_settle_hook"
    assert call["session_id"] == "session-1"
    assert json.loads(call["payload"])["tool_response"] == case["payload"]["tool_response"]


def test_a_saved_answer_may_carry_the_pending_identifier(monkeypatch: pytest.MonkeyPatch) -> None:
    case = next(case for case in _CASES if case["name"] == "answers-keyed-allow-once")

    settled, _call = _settle(monkeypatch, {**_SAVE, "pending_id": "pending-1"}, case["payload"])

    assert settled == {**_SAVE, "pending_id": "pending-1"}


def test_other_tools_never_reach_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    case = next(case for case in _CASES if case["name"] == "answers-keyed-allow-once")
    calls: list[str] = []

    def fake(_store: object, op: str, **_fields: object) -> object:
        calls.append(op)
        return {"outcome": "none"}

    monkeypatch.setattr(native_claude_guard_question, "hook_authority_state", fake)
    for payload, event in (
        ({**case["payload"], "tool_name": "Bash"}, "PostToolUse"),
        ({**case["payload"], "tool_name": "NotAskUserQuestion"}, "PostToolUse"),
        (case["payload"], "PreToolUse"),
    ):
        settled = settle_claude_guard_question(
            object(), session_id="session-1", payload=payload, event=event, now="2026-10-26T00:00:00+00:00"
        )
        assert settled is None
    assert calls == []
