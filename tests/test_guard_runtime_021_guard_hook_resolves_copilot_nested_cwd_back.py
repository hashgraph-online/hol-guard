"""Runtime regression tests: guard hook resolves copilot nested cwd back."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    APPROVAL_CONTEXT_TOKEN_PREFIX,
    GuardStore,
    guard_commands_module,
    io,
    json,
    main,
    sys,
)
from tests.guard_runtime_test_scenarios import (
    _load_claude_pending_question_contract,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _run_guard_hook,
    _write_json,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_hook_resolves_copilot_nested_cwd_back_to_workspace_root(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    nested_dir = workspace_dir / "src" / "components"
    nested_dir.mkdir(parents=True, exist_ok=True)
    _build_guard_fixture(home_dir, workspace_dir)
    _write_json(
        workspace_dir / ".vscode" / "mcp.json",
        {
            "servers": {
                "danger_lab": {
                    "type": "local",
                    "command": "python3",
                    "args": ["danger-lab.py"],
                }
            }
        },
    )
    monkeypatch.chdir(nested_dir)
    event = {
        "hook_event_name": "PreToolUse",
        "toolName": "mcp_danger_lab_safe_echo",
        "toolArgs": json.dumps({"text": "ok"}),
        "sourceScope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--guard-home",
            str(guard_home),
            "--harness",
            "copilot",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    store = GuardStore(guard_home)
    receipts = store.list_receipts(limit=20)

    assert rc == 0
    assert output == {"permissionDecision": "allow"}
    assert any(
        receipt["artifact_id"] == "copilot:runtime:project:danger_lab:safe_echo"
        and receipt["policy_decision"] == "warn"
        for receipt in receipts
    )


def test_guard_hook_emits_copilot_native_deny_response_for_sandbox_required_requests(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": "docker run --rm alpine sh"}),
        "sourceScope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "copilot",
            "--policy-action",
            "sandbox-required",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["permissionDecision"] == "deny"


def test_guard_hook_emits_claude_native_ask_response(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace_dir / ".env")},
        "source_scope": "project",
    }
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    output = json.loads(output)

    assert rc == 0
    assert "systemMessage" in output
    assert "HOL Guard intercepted Claude's attempt to use Read" in output["systemMessage"]
    assert output["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert output["hookSpecificOutput"]["permissionDecision"] == "ask"
    reason = output["hookSpecificOutput"]["permissionDecisionReason"].lower()
    assert "approval flow came from hol guard" in reason
    assert "allow once" in reason
    assert "keep blocked" in reason
    assert str(workspace_dir) not in output["hookSpecificOutput"]["permissionDecisionReason"]


def test_guard_hook_emits_claude_native_pretooluse_notice_on_stderr(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace_dir / ".env")},
        "source_scope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    captured_notice: list[str] = []
    monkeypatch.setattr(
        guard_commands_module,
        "_emit_native_hook_notification_stderr",
        lambda reason: captured_notice.append(reason),
    )

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "claude-code",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert captured_notice
    assert "HOL Guard intercepted Claude's attempt to use Read." in captured_notice[0]
    assert "protect your local secrets" in captured_notice[0]
    assert "HOL Guard prompt" in captured_notice[0]


def test_guard_hook_claude_native_approval_does_not_lower_current_reapproval(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    first_event = {
        "session_id": "session-claude-approval",
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
    prompt_rc, _ = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={
            **first_event,
            "hook_event_name": "Notification",
            "notification_type": "permission_prompt",
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    post_event = {
        **first_event,
        "hook_event_name": "PostToolUse",
        "tool_response": {"filePath": str(workspace_dir / ".env"), "success": True},
    }
    post_rc, post_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=post_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    second_rc, second_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={**first_event, "session_id": "session-claude-next"},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    first_payload = json.loads(first_output)
    post_payload = json.loads(post_output)
    second_payload = json.loads(second_output)
    store = GuardStore(home_dir)
    receipts = store.list_receipts(limit=20)
    policies = store.list_policy_decisions("claude-code")
    native_receipt = next(receipt for receipt in receipts if receipt["user_override"] == "claude-native-approve")

    assert first_rc == 0
    assert first_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert prompt_rc == 0
    assert post_rc == 0
    assert post_payload["decision"] == "block"
    assert post_payload["continue"] is True
    assert second_rc == 0
    assert second_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert native_receipt["artifact_hash"].startswith(APPROVAL_CONTEXT_TOKEN_PREFIX)
    assert native_receipt["policy_decision"] == "require-reapproval"
    assert all(policy["source"] != "claude-native-approval" for policy in policies)
    assert any(
        evidence.get("source") == "claude_native_approval"
        and evidence.get("authoritative_action") == "require-reapproval"
        and evidence.get("reusable_policy_saved") is False
        for evidence in native_receipt["scanner_evidence"]
    )


def test_guard_hook_claude_ask_user_question_allow_does_not_lower_current_reapproval(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    first_event = {
        "session_id": "session-claude-guard-question-allow",
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
        "session-claude-guard-question-allow",
    )
    question_rc, question_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={
            "session_id": "session-claude-guard-question-allow",
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
        event={**first_event, "session_id": "session-claude-guard-question-allow-retry"},
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
    assert "AskUserQuestion" in permission_payload["hookSpecificOutput"]["decision"]["message"]
    assert question_rc == 0
    assert question_output == ""
    assert second_rc == 0
    assert second_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert policies[0]["source"] == "claude-ask-user-question"


def test_guard_hook_claude_docker_saved_allow_does_not_lower_terminal_block(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    def saved_allow_lookup(_store, _harness, artifact_id, *, artifact_hash=None, **_kwargs):
        return {
            "decision": {
                "action": "allow",
                "scope": "workspace",
                "artifact_id": artifact_id,
                "artifact_hash": artifact_hash,
            },
            "ignored_local_integrity": None,
            "trust_status": {"trusted": True},
            "authority_revision": 1,
        }

    monkeypatch.setattr(
        GuardStore,
        "resolve_policy_decision_lookup_with_memory_pattern",
        saved_allow_lookup,
    )
    event = {
        "session_id": "session-claude-docker-block",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "docker compose run --rm app"},
        "source_scope": "project",
    }

    rc, raw_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    output = json.loads(raw_output)

    assert rc == 0
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "sensitive native tool action" in output["hookSpecificOutput"]["permissionDecisionReason"].lower()
    assert GuardStore(home_dir).list_approval_requests(limit=10) == []
