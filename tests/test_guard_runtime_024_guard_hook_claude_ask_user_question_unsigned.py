"""Runtime regression tests: guard hook claude ask user question unsigned."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardArtifact,
    GuardStore,
    Path,
    _runtime_scoped_exact_match_key,
    guard_commands_module,
    json,
    pytest,
    runtime_tool_action_exact_match_context,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _run_guard_hook,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_hook_claude_ask_user_question_unsigned_legacy_pending_state_cannot_persist_decision(tmp_path):
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    session_id = "session-claude-legacy-pending"
    artifact_id = "claude-code:runtime:file-read:.env"
    now = "2026-04-24T00:00:00+00:00"
    pending_key = guard_commands_module._claude_pending_permission_state_key(session_id, artifact_id)
    store.set_sync_payload(
        pending_key,
        {
            "saved_at": now,
            "reason": "HOL Guard intercepted Claude's attempt to use Read for local .env file.",
            "artifact_id": artifact_id,
            "artifact_hash": "hash-legacy",
            "artifact_name": "Read",
            "tool_name": "Read",
            "permission_prompt_seen": True,
        },
        now,
    )
    store.set_sync_payload(
        guard_commands_module._claude_pending_permission_index_key(session_id),
        [pending_key],
        now,
    )

    persisted = guard_commands_module._persist_claude_guard_question_decision(
        store,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "AskUserQuestion",
            "tool_input": {
                "questions": [
                    {
                        "header": "HOL Guard",
                        "question": "HOL Guard intercepted this sensitive action. What should Claude do?",
                        "options": [
                            {"label": "Allow once"},
                            {"label": "Allow during this session"},
                            {"label": "Keep blocked"},
                        ],
                    }
                ]
            },
            "tool_response": {
                "questions": [
                    {
                        "header": "HOL Guard",
                        "question": "HOL Guard intercepted this sensitive action. What should Claude do?",
                        "options": [
                            {"label": "Allow once"},
                            {"label": "Allow during this session"},
                            {"label": "Keep blocked"},
                        ],
                    }
                ],
                "answers": {"HOL Guard intercepted this sensitive action. What should Claude do?": "Allow once"},
            },
        },
    )
    policies = store.list_policy_decisions("claude-code")

    assert persisted is False
    assert policies == []
    assert store.get_sync_payload(guard_commands_module._claude_pending_permission_index_key(session_id)) is None
    events = store.list_events(event_name="rule.ignored.local_integrity")
    event_payloads = [event_payload for event in events if isinstance(event_payload := event.get("payload"), dict)]
    assert any(event_payload.get("integrity_status") == "missing_integrity" for event_payload in event_payloads)


def test_guard_hook_claude_native_denial_uses_contextual_tool_action_key(tmp_path):
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    session_id = "session-claude-deny"
    artifact_id = "claude-code:runtime:tool-action:bash"
    wrapper_chain = ["bash", "zsh"]
    artifact = GuardArtifact(
        artifact_id=artifact_id,
        name="Bash",
        harness="claude-code",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="workspace/app/claude-settings.json",
        command="docker compose up -d postgres",
        metadata={
            "raw_command_text": "docker compose up -d postgres",
            "wrapper_chain": wrapper_chain,
        },
    )
    prompt_payload = {"session_id": session_id, "tool_name": "Bash"}
    guard_commands_module._record_claude_permission_notice(
        store=store,
        payload=prompt_payload,
        reason="HOL Guard intercepted Claude's shell action.",
        artifact=artifact,
        artifact_hash="hash-denied",
    )
    notice = guard_commands_module._peek_claude_permission_notice(store, prompt_payload)
    assert notice is not None
    guard_commands_module._mark_claude_pending_permission_prompt_seen(
        store=store,
        payload=prompt_payload,
        notice=notice,
    )

    denied = guard_commands_module._persist_claude_pending_permission_denials(
        store,
        {"session_id": session_id},
    )
    context = runtime_tool_action_exact_match_context(
        config_path="workspace/app/claude-settings.json",
        source_scope="project",
        raw_command_text="docker compose up -d postgres",
        wrapper_chain=wrapper_chain,
    )
    contextual_key = _runtime_scoped_exact_match_key(artifact_id, context)

    policies = store.list_policy_decisions("claude-code")
    assert denied == 1
    assert len(policies) == 1
    assert policies[0]["artifact_id"] == artifact_id
    assert policies[0]["artifact_hash"] == contextual_key
    assert policies[0]["action"] == "block"


def test_guard_hook_claude_ask_user_question_unsigned_bound_pending_cannot_persist_decision(tmp_path):
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    session_id = "session-claude-bound-no-seen"
    artifact_id = "claude-code:runtime:file-read:.env"
    now = "2026-04-24T00:00:00+00:00"
    approval_code = "abc123abc123"
    approval_question = guard_commands_module._claude_guard_approval_question_text(approval_code)
    pending_key = guard_commands_module._claude_pending_permission_state_key(session_id, artifact_id)
    store.set_sync_payload(
        pending_key,
        {
            "saved_at": now,
            "reason": "HOL Guard intercepted Claude's attempt to use Read for local .env file.",
            "artifact_id": artifact_id,
            "artifact_hash": "hash-bound",
            "artifact_name": "Read",
            "tool_name": "Read",
            "approval_header": "HOL Guard",
            "approval_question": approval_question,
            "approval_options": ["Allow once", "Allow during this session", "Keep blocked"],
            "approval_code": approval_code,
        },
        now,
    )
    store.set_sync_payload(
        guard_commands_module._claude_pending_permission_index_key(session_id),
        [pending_key],
        now,
    )

    persisted = guard_commands_module._persist_claude_guard_question_decision(
        store,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "AskUserQuestion",
            "tool_input": {
                "questions": [
                    {
                        "header": "HOL Guard",
                        "question": approval_question,
                        "options": [
                            {"label": "Allow once"},
                            {"label": "Allow during this session"},
                            {"label": "Keep blocked"},
                        ],
                    }
                ]
            },
            "tool_response": {
                "questions": [
                    {
                        "header": "HOL Guard",
                        "question": approval_question,
                        "options": [
                            {"label": "Allow once"},
                            {"label": "Allow during this session"},
                            {"label": "Keep blocked"},
                        ],
                    }
                ],
                "answers": {approval_question: "Allow once"},
            },
        },
    )
    policies = store.list_policy_decisions("claude-code")

    assert persisted is False
    assert policies == []


def test_guard_hook_claude_native_cancel_does_not_persist_flat_block(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    first_event = {
        "session_id": "session-claude-native-cancel",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace_dir / ".npmrc")},
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
            **first_event,
            "hook_event_name": "Notification",
            "notification_type": "permission_prompt",
            "message": "Claude needs your permission to use Read",
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    stop_rc, stop_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={"session_id": "session-claude-native-cancel", "hook_event_name": "Stop"},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    second_rc, second_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={**first_event, "session_id": "session-claude-native-cancel-retry"},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    first_payload = json.loads(first_output)
    notification_payload = json.loads(notification_output)
    second_payload = json.loads(second_output)

    assert first_rc == 0
    assert first_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert notification_rc == 0
    assert "HOL Guard approval question" in notification_payload["systemMessage"]
    assert stop_rc == 0
    assert stop_output == ""
    assert GuardStore(home_dir).list_policy_decisions("claude-code") == []
    assert second_rc == 0
    assert second_payload["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_guard_hook_claude_alias_saved_allow_does_not_lower_canonical_reapproval(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    first_event = {
        "session_id": "session-claude-alias-approval",
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
        harness="claude",
        event=first_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    post_rc, post_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude",
        event={
            **first_event,
            "hook_event_name": "PostToolUse",
            "tool_response": {"filePath": str(workspace_dir / ".env"), "success": True},
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    second_rc, second_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={**first_event, "session_id": "session-claude-alias-next"},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    first_payload = json.loads(first_output)
    post_payload = json.loads(post_output)
    second_payload = json.loads(second_output)
    receipts = GuardStore(home_dir).list_receipts(limit=20)

    assert first_rc == 0
    assert first_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert post_rc == 0
    assert post_payload["decision"] == "block"
    assert post_payload["continue"] is True
    assert second_rc == 0
    assert second_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert any(receipt["harness"] == "claude-code" for receipt in receipts)


def test_hook_runtime_artifact_prefers_raw_file_read_path_over_redacted_action_path(tmp_path):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    outside_secret = tmp_path / "outside-a" / ".env"
    payload = {
        "event": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(outside_secret)},
        "source_scope": "project",
    }
    action = guard_commands_module._hook_action_envelope(
        harness="claude-code",
        payload=payload,
        home_dir=home_dir,
        workspace=workspace_dir,
    )

    artifact = guard_commands_module._hook_runtime_artifact(
        harness="claude-code",
        payload=payload,
        action_envelope=action,
        home_dir=home_dir,
        guard_home=home_dir,
        workspace=workspace_dir,
    )

    assert action is not None
    assert action.target_paths == (".../.env",)
    assert artifact is not None
    assert artifact.metadata["normalized_path"] == str(outside_secret)


@pytest.mark.parametrize(
    "strict_config",
    (
        'default_action = "require-reapproval"\napproval_wait_timeout_seconds = 0\n',
        '[harnesses.codex]\ndefault_action = "require-reapproval"\napproval_wait_timeout_seconds = 0\n',
    ),
    ids=("global", "harness"),
)
def test_guard_hook_codex_review_default_allows_verified_non_sensitive_apply_patch(
    strict_config: str,
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", strict_config)
    patch = """*** Begin Patch
*** Update File: docs/notes.md
@@
+Updated project status.
*** End Patch"""
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "tool_input": {"command": patch},
        "source_scope": "project",
        "cwd": str(workspace_dir),
    }
    monkeypatch.setattr(
        guard_commands_module,
        "schedule_guard_daemon_ensure",
        lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )
    store = GuardStore(home_dir)

    assert rc == 0
    assert output["policy_action"] == "warn"
    assert store.list_approval_requests(limit=10) == []
