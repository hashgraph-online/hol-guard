"""Runtime regression tests: guard hook claude notification saved allow does."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    guard_commands_module,
    json,
)
from tests.guard_runtime_test_scenarios import (
    _load_claude_pending_question_contract,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _run_guard_hook,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_hook_claude_notification_saved_allow_does_not_lower_current_reapproval(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    first_event = {
        "session_id": "session-claude-guard-question-notification-only",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace_dir / ".env")},
        "source_scope": "project",
    }
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    first_rc, first_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=first_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    notification_rc, notification_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={
            "session_id": "session-claude-guard-question-notification-only",
            "hook_event_name": "Notification",
            "notification_type": "permission_prompt",
            "title": "Permission needed",
            "message": "Claude needs your permission to use Read",
            "tool_name": "Read",
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    approval_question, question_options = _load_claude_pending_question_contract(
        home_dir,
        "session-claude-guard-question-notification-only",
    )
    question_rc, question_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={
            "session_id": "session-claude-guard-question-notification-only",
            "hook_event_name": "PostToolUse",
            "tool_name": "AskUserQuestion",
            "tool_input": {
                "questions": [
                    {
                        "header": "HOL Guard",
                        "question": approval_question,
                        "options": question_options,
                    }
                ]
            },
            "tool_response": {
                "questions": [
                    {
                        "header": "HOL Guard",
                        "question": approval_question,
                        "options": question_options,
                    }
                ],
                "answers": {approval_question: "Allow once"},
            },
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    second_rc, second_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={**first_event, "session_id": "session-claude-guard-question-notification-only-retry"},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    first_payload = json.loads(first_output)
    notification_payload = json.loads(notification_output)
    second_payload = json.loads(second_output)
    policies = GuardStore(home_dir).list_policy_decisions("claude-code")

    assert first_rc == 0
    assert first_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert notification_rc == 0
    assert "AskUserQuestion" in notification_payload["hookSpecificOutput"]["additionalContext"]
    assert question_rc == 0
    assert question_output == ""
    assert second_rc == 0
    assert second_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert policies[0]["source"] == "claude-ask-user-question"


def test_guard_hook_claude_repeated_notifications_keep_bound_question_without_lowering_reapproval(
    tmp_path, capsys, monkeypatch
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    first_event = {
        "session_id": "session-claude-guard-question-repeat-notification",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace_dir / ".env")},
        "source_scope": "project",
    }
    notification_event = {
        "session_id": "session-claude-guard-question-repeat-notification",
        "hook_event_name": "Notification",
        "notification_type": "permission_prompt",
        "title": "Permission needed",
        "message": "Claude needs your permission to use Read",
        "tool_name": "Read",
    }
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    first_rc, first_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=first_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    notification_one_rc, notification_one_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=notification_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    approval_question, question_options = _load_claude_pending_question_contract(
        home_dir,
        "session-claude-guard-question-repeat-notification",
    )
    notification_two_rc, notification_two_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=notification_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    question_rc, question_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={
            "session_id": "session-claude-guard-question-repeat-notification",
            "hook_event_name": "PostToolUse",
            "tool_name": "AskUserQuestion",
            "tool_input": {
                "questions": [
                    {
                        "header": "HOL Guard",
                        "question": approval_question,
                        "options": question_options,
                    }
                ]
            },
            "tool_response": {
                "questions": [
                    {
                        "header": "HOL Guard",
                        "question": approval_question,
                        "options": question_options,
                    }
                ],
                "answers": {approval_question: "Allow once"},
            },
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    second_rc, second_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={**first_event, "session_id": "session-claude-guard-question-repeat-notification-retry"},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    first_payload = json.loads(first_output)
    notification_one_payload = json.loads(notification_one_output)
    notification_two_payload = json.loads(notification_two_output)
    second_payload = json.loads(second_output)
    policies = GuardStore(home_dir).list_policy_decisions("claude-code")

    assert first_rc == 0
    assert first_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert notification_one_rc == 0
    assert notification_two_rc == 0
    assert approval_question in notification_one_payload["hookSpecificOutput"]["additionalContext"]
    assert approval_question in notification_two_payload["hookSpecificOutput"]["additionalContext"]
    assert question_rc == 0
    assert question_output == ""
    assert second_rc == 0
    assert second_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert policies[0]["source"] == "claude-ask-user-question"


def test_guard_hook_claude_ask_user_question_keep_blocked_persists_block(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    first_event = {
        "session_id": "session-claude-guard-question-block",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace_dir / ".env")},
        "source_scope": "project",
    }
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    first_rc, first_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=first_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    permission_rc, permission_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={**first_event, "hook_event_name": "PermissionRequest"},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    approval_question, question_options = _load_claude_pending_question_contract(
        home_dir,
        "session-claude-guard-question-block",
    )
    question_rc, question_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={
            "session_id": "session-claude-guard-question-block",
            "hook_event_name": "PostToolUse",
            "tool_name": "AskUserQuestion",
            "tool_input": {
                "questions": [
                    {
                        "header": "HOL Guard",
                        "question": approval_question,
                        "options": question_options,
                    }
                ]
            },
            "tool_response": {
                "questions": [
                    {
                        "header": "HOL Guard",
                        "question": approval_question,
                        "options": question_options,
                    }
                ],
                "answers": {approval_question: "Keep blocked"},
            },
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    second_rc, second_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={**first_event, "session_id": "session-claude-guard-question-block-retry"},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    first_payload = json.loads(first_output)
    permission_payload = json.loads(permission_output)
    second_payload = json.loads(second_output)
    policies = GuardStore(home_dir).list_policy_decisions("claude-code")

    assert first_rc == 0
    assert first_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert permission_rc == 0
    assert permission_payload["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    assert question_rc == 0
    assert question_output == ""
    assert second_rc == 0
    assert second_payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "HOL Guard blocked Claude's attempt to use Read" in second_payload["systemMessage"]
    assert policies[0]["source"] == "claude-ask-user-question"


def test_guard_hook_claude_ask_user_question_without_answer_does_not_persist_block(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    first_event = {
        "session_id": "session-claude-guard-question-no-answer",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace_dir / ".env")},
        "source_scope": "project",
    }
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    first_rc, first_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=first_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    permission_rc, permission_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={**first_event, "hook_event_name": "PermissionRequest"},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    approval_question, question_options = _load_claude_pending_question_contract(
        home_dir,
        "session-claude-guard-question-no-answer",
    )
    question_rc, question_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={
            "session_id": "session-claude-guard-question-no-answer",
            "hook_event_name": "PostToolUse",
            "tool_name": "AskUserQuestion",
            "tool_input": {
                "questions": [
                    {
                        "header": "HOL Guard",
                        "question": approval_question,
                        "options": question_options,
                    }
                ]
            },
            "tool_response": {
                "questions": [
                    {
                        "header": "HOL Guard",
                        "question": approval_question,
                        "options": question_options,
                    }
                ],
            },
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    second_rc, second_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={**first_event, "session_id": "session-claude-guard-question-no-answer-retry"},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    first_payload = json.loads(first_output)
    permission_payload = json.loads(permission_output)
    second_payload = json.loads(second_output)
    policies = GuardStore(home_dir).list_policy_decisions("claude-code")

    assert first_rc == 0
    assert first_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert permission_rc == 0
    assert permission_payload["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    assert question_rc == 0
    assert json.loads(question_output)["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert second_rc == 0
    assert second_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert policies == []
