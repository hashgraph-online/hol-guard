from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_claude_guard_question
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.native_claude_guard_question import (
    claude_guard_question_request,
    claude_guard_question_verdict,
)

_VECTORS = (
    Path(__file__).resolve().parents[1]
    / "rust/crates/guard-runtime/tests/fixtures/claude_guard_question_vectors.json.gz"
)
_CASES = json.loads(gzip.decompress(_VECTORS.read_bytes()))["cases"]


@pytest.mark.parametrize("case", _CASES, ids=[case["name"] for case in _CASES])
def test_transport_projects_the_recorded_request(case: dict) -> None:
    event = guard_commands_module._hook_event_name(case["payload"])

    assert claude_guard_question_request(case["payload"], case["pending"], event=event) == case["request"]


def test_native_verdicts_match_the_recorded_answers() -> None:
    for case in _CASES:
        event = guard_commands_module._hook_event_name(case["payload"])
        verdict = claude_guard_question_verdict(case["payload"], case["pending"], event=event)

        assert verdict._asdict() == case["expected"], case["name"]


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {"status": "error", "code": "native_context_digest_unsupported"},
        {"status": "ok"},
        {"status": "ok", "claude_guard_question": {"is_question": True, "action": "approve"}},
        {"status": "ok", "claude_guard_question": {"is_question": "yes", "action": "allow"}},
        {"status": "ok", "claude_guard_question": {"is_question": False, "action": "allow"}},
        {"status": "ok", "claude_guard_question": {"is_question": True, "action": "allow", "extra": 1}},
        {"status": "ok", "claude_guard_question": {"is_question": True, "action": ["allow"]}},
        {"status": "ok", "claude_guard_question": {"is_question": True, "action": {"kind": "allow"}}},
    ],
)
def test_native_failure_is_never_an_approval(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    monkeypatch.setattr(native_claude_guard_question, "native_context_digest", lambda *_args, **_kwargs: answer)
    case = next(case for case in _CASES if case["name"] == "answers-keyed-allow-once")

    verdict = claude_guard_question_verdict(case["payload"], case["pending"], event="PostToolUse")

    assert verdict == (False, None)


def test_other_tools_never_reach_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("resident called")

    monkeypatch.setattr(native_claude_guard_question, "native_context_digest", fail)
    case = next(case for case in _CASES if case["name"] == "answers-keyed-allow-once")

    assert claude_guard_question_verdict(
        {**case["payload"], "tool_name": "Bash"}, case["pending"], event="PostToolUse"
    ) == (
        False,
        None,
    )
    assert claude_guard_question_verdict(
        {**case["payload"], "tool_name": "NotAskUserQuestion"}, case["pending"], event="PostToolUse"
    ) == (False, None)
    assert claude_guard_question_verdict(case["payload"], case["pending"], event="PreToolUse") == (False, None)
