"""The library step that saves the answer the daemon read from Claude's approval question."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.routes.hook_calls import (
    HOOK_CALLS,
    hook_claude_question_save,
    hook_integrity_finalize,
    hook_integrity_finalize_locked,
)
from codex_plugin_scanner.guard.store import GuardStore


def _args(**overrides: object) -> dict[str, object]:
    args: dict[str, object] = {
        "session_id": "s-1",
        "artifact_id": "claude-code:native-pretool:bash",
        "pending_artifact_hash": "sha256:pending",
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


def test_integrity_finalize_reports_a_failed_control_state_write() -> None:
    class Store:
        def _finalize_policy_integrity_control_state(self, payload: object) -> bool:
            return False

    assert hook_integrity_finalize(Store(), {"next_control_state": {"generation": 1}}) == {"finalized": False}


def test_locked_integrity_finalize_uses_the_lock_owning_finalize_path() -> None:
    class Store:
        def _finalize_policy_integrity_control_state(self, payload: object) -> bool:
            return False

    assert hook_integrity_finalize_locked(Store(), {"next_control_state": {"generation": 1}}) == {
        "finalized": False
    }
