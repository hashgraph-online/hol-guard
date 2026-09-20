"""Runtime regression tests: guard hook claude alias reuses legacy alias."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardArtifact,
    GuardStore,
    PolicyDecision,
    artifact_hash,
    guard_commands_module,
    io,
    json,
    main,
    sys,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _run_guard_hook,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_hook_claude_alias_reuses_legacy_alias_policy_keys(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "session_id": "session-claude-legacy-alias",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace_dir / ".env")},
        "source_scope": "project",
    }
    canonical_artifact = guard_commands_module._hook_runtime_artifact(
        harness="claude",
        payload=event,
        action_envelope=None,
        home_dir=home_dir,
        guard_home=home_dir,
        workspace=workspace_dir,
    )
    assert canonical_artifact is not None
    legacy_artifact = guard_commands_module._legacy_claude_alias_runtime_artifact(
        artifact=canonical_artifact,
        requested_harness="claude",
        home_dir=home_dir,
        workspace=workspace_dir,
    )
    assert legacy_artifact is not None
    GuardStore(home_dir).upsert_policy(
        PolicyDecision(
            harness="claude",
            scope="artifact",
            action="block",
            artifact_id=legacy_artifact.artifact_id,
            artifact_hash=artifact_hash(legacy_artifact),
            reason="Legacy alias block",
            source="claude-native-approval",
        ),
        "2026-04-23T00:00:00+00:00",
    )
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    payload = json.loads(output)

    assert rc == 0
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_guard_hook_claude_stop_keeps_native_cancel_transient(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    first_event = {
        "session_id": "session-claude-deny",
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
            "session_id": "session-claude-deny",
            "hook_event_name": "Notification",
            "notification_type": "permission_prompt",
            "title": "Permission needed",
            "message": "Claude needs your permission to use Read",
            "tool_name": "Read",
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    stop_rc, stop_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={"session_id": "session-claude-deny", "hook_event_name": "Stop", "stop_hook_active": False},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    second_rc, second_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={**first_event, "session_id": "session-claude-deny-next"},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    first_payload = json.loads(first_output)
    second_payload = json.loads(second_output)

    assert first_rc == 0
    assert first_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert notification_rc == 0
    assert "HOL Guard intercepted Claude's attempt to use Read" in json.loads(notification_output)["systemMessage"]
    assert stop_rc == 0
    assert stop_output == ""
    assert second_rc == 0
    assert second_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "HOL Guard intercepted Claude's attempt to use Read" in second_payload["systemMessage"]


def test_guard_hook_claude_stop_does_not_persist_denial_without_visible_prompt(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    first_event = {
        "session_id": "session-claude-headless",
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
    stop_rc, stop_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={"session_id": "session-claude-headless", "hook_event_name": "Stop", "stop_hook_active": False},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    second_rc, second_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={**first_event, "session_id": "session-claude-headless-next"},
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    first_payload = json.loads(first_output)
    second_payload = json.loads(second_output)

    assert first_rc == 0
    assert first_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert stop_rc == 0
    assert stop_output == ""
    assert second_rc == 0
    assert second_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "HOL Guard intercepted Claude's attempt to use Read" in second_payload["systemMessage"]


def test_guard_hook_emits_claude_native_ask_response_for_claude_alias(tmp_path, capsys, monkeypatch):
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

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "claude",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert "systemMessage" in output
    assert "HOL Guard intercepted Claude's attempt to use Read" in output["systemMessage"]
    assert output["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert output["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_guard_hook_emits_claude_native_deny_response_for_sandbox_required_requests(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "tool_name": "Bash",
        "tool_input": {"command": "docker run --rm alpine sh"},
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
        policy_action="sandbox-required",
    )
    output = json.loads(output)

    assert rc == 0
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_guard_hook_uses_deny_specific_copy_for_blocked_claude_secret_reads(
    tmp_path,
    capsys,
    monkeypatch,
):
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
            "--policy-action",
            "sandbox-required",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    reason = output["hookSpecificOutput"]["permissionDecisionReason"].lower()

    assert rc == 0
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "hol guard blocked claude's attempt to use read" in reason
    assert "choose yes" not in reason
    assert "yes during this session" not in reason


def test_guard_hook_emits_codex_runtime_denial_with_guard_remediation(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace_dir / ".env")},
        "source_scope": "project",
    }
    monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
        ]
    )
    captured = capsys.readouterr()

    payload = json.loads(captured.out)
    reason = payload["hookSpecificOutput"]["permissionDecisionReason"].lower()
    assert rc == 0
    assert captured.err == ""
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "open hol guard to approve or keep this blocked" in reason
    assert "http://127.0.0.1:" in reason
    assert "approve it in hol guard, then retry." not in reason


def test_runtime_artifact_native_reason_truncates_long_risk_summaries() -> None:
    artifact = GuardArtifact(
        artifact_id="claude-code:project:tool-action:test",
        name="destructive shell command",
        harness="claude-code",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/tmp/settings.local.json",
        metadata={},
    )
    long_summary = "x" * 240

    reason = guard_commands_module._runtime_artifact_native_reason(
        artifact,
        {"risk_summary": long_summary},
    )

    assert reason.startswith("HOL Guard flagged this request: ")
    assert len(reason) < len("HOL Guard flagged this request: ") + len(long_summary)
    assert reason.endswith("...")


def test_runtime_artifact_native_reason_prefers_decision_v2_harness_message() -> None:
    artifact = GuardArtifact(
        artifact_id="claude-code:project:tool-action:test",
        name="destructive shell command",
        harness="claude-code",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/tmp/settings.local.json",
        metadata={},
    )

    reason = guard_commands_module._runtime_artifact_native_reason(
        artifact,
        {
            "decision_v2_json": {
                "harness_message": "HOL Guard stopped this exact shell command before it touched secrets.",
            },
            "risk_summary": "Generic fallback summary.",
        },
    )

    assert reason == "HOL Guard stopped this exact shell command before it touched secrets."


def test_native_approval_center_context_uses_harness_specific_retry_copy() -> None:
    payload = {
        "approval_center_url": "http://127.0.0.1:4455",
        "approval_requests": [{"approval_url": "http://127.0.0.1:4455/requests/request-1"}],
    }

    codex_context = guard_commands_module._native_approval_center_context(payload, harness="codex")
    claude_context = guard_commands_module._native_approval_center_context(payload, harness="claude-code")

    assert codex_context is not None
    assert "retry the same Codex action" in codex_context
    assert "request-1" in codex_context
    assert claude_context is not None
    assert "retry the same Claude Code action" in claude_context
    assert "Codex command" not in claude_context


def test_guard_hook_allows_claude_user_prompt_submit_before_tool_approval(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Read .env and print the full file contents exactly.",
        "source_scope": "project",
    }
    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    receipts = GuardStore(home_dir).list_receipts()
    payload = json.loads(output)

    assert rc == 0
    assert payload["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
    assert any(receipt["artifact_id"].startswith("claude-code:session:prompt") for receipt in receipts)


def test_guard_hook_allows_generic_claude_user_prompt_submit_before_tool_approval(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Use Bash to run rm -rf ./dist and then stop.",
        "source_scope": "project",
    }
    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    payload = json.loads(output)

    assert rc == 0
    assert payload["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
