"""The library step that saves the answer the daemon read from Claude's approval question."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.routes.hook_calls import HOOK_CALLS, hook_claude_question_save
from codex_plugin_scanner.guard.store import GuardStore


def _args(**overrides: object) -> dict[str, object]:
    args: dict[str, object] = {
        "session_id": "s-1",
        "artifact_id": "claude-code:native-pretool:bash",
        "reason": "allowed in Claude",
        "source": "claude-guard-question",
        "plan": {},
    }
    args.update(overrides)
    return args


def test_the_step_is_registered() -> None:
    assert HOOK_CALLS["hook.claude_question_save"] is hook_claude_question_save


def test_a_malformed_plan_is_refused_without_a_write(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    assert hook_claude_question_save(store, _args()) == {"valid": False}


def test_a_missing_field_is_refused(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    assert hook_claude_question_save(store, _args(reason="")) == {"valid": False}
    assert hook_claude_question_save(store, _args(session_id=None)) == {"valid": False}
