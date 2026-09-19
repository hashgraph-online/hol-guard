"""Runtime regression tests: guard hook explains ignored remembered rule when."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    PolicyDecision,
    _runtime_scoped_exact_match_key,
    build_package_request_artifact,
    extract_package_intent_request,
    guard_commands_module,
    io,
    json,
    main,
    sys,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _run_guard_hook,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_hook_explains_ignored_remembered_rule_when_local_trust_is_degraded(
    tmp_path,
    capsys,
    monkeypatch,
):
    from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
        PackageRequestEvaluation,
        SupplyChainUserCopy,
    )

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    store = GuardStore(home_dir)
    command = "npm install minimist@1.2.8"
    intent = extract_package_intent_request(
        "Bash",
        {"command": command},
        action_envelope_command=None,
        workspace=workspace_dir,
    )
    assert intent is not None
    artifact = build_package_request_artifact(
        "codex",
        intent,
        config_path=str(workspace_dir / ".codex" / "config.toml"),
        source_scope="project",
    )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=None,
            workspace=None,
            reason="remember this exact install",
            source="manual",
        ),
        "2026-06-19T00:00:00Z",
    )

    def _degraded_state(_self, _connection, *, now, create_key):
        return {
            "mode": "degraded",
            "enforcement": "enforce",
            "generation": 1,
            "degraded_reasons": ["system_keyring_unavailable"],
        }

    def _package_requires_review(**_kwargs: object) -> PackageRequestEvaluation:
        return PackageRequestEvaluation(
            decision="review",
            policy_action="require-reapproval",
            enforcement="policy",
            entitlement_state="offline",
            cache_status="miss",
            package_intent_hash="intent-hash",
            policy_version="policy-v1",
            bundle_version="bundle-v1",
            workspace_fingerprint="workspace-fingerprint",
            reasons=({"code": "package_review", "message": "Review npm install minimist@1.2.8"},),
            packages=({"name": "minimist", "decision": "review", "reasons": ()},),
            risk_summary="HOL Guard is reviewing npm install minimist@1.2.8.",
            user_copy=SupplyChainUserCopy(
                title="Review package install",
                summary="minimist@1.2.8 needs review before install.",
                next_step="Confirm the exact version in Codex's approval prompt.",
                dashboard_url="https://hol.org/guard/inbox",
                harness_message="HOL Guard is reviewing npm install minimist@1.2.8.",
            ),
        )

    monkeypatch.setattr(GuardStore, "_refresh_policy_integrity_state", _degraded_state)
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    monkeypatch.setattr(guard_commands_module, "evaluate_package_request_artifact", _package_requires_review)

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "source_scope": "project",
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert rc == 1
    assert output["policy_action"] == "require-reapproval"
    assert output["trust_status"]["remembered_rules"] == "disabled_degraded"
    assert output["remembered_rule_rejection"]["integrity_status"] == "degraded_mode"
    assert "remembered local rule was ignored" in output["decision_v2_json"]["harness_message"]
    assert "One-time approvals still work" in output["decision_v2_json"]["harness_message"]
    assert "remembered local rule was ignored" in output["approval_requests"][0]["decision_v2_json"]["harness_message"]


def test_guard_hook_cloud_allow_does_not_lower_current_package_reapproval(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    store = GuardStore(home_dir)
    command = "npm install minimist@1.2.8"
    intent = extract_package_intent_request(
        "Bash",
        {"command": command},
        action_envelope_command=None,
        workspace=workspace_dir,
    )
    assert intent is not None
    artifact = build_package_request_artifact(
        "codex",
        intent,
        config_path=str(workspace_dir / ".codex" / "config.toml"),
        source_scope="project",
    )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=None,
            workspace=None,
            reason="remember this exact install",
            source="manual",
        ),
        "2026-06-19T00:00:00Z",
    )
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="harness",
                action="allow",
                artifact_id=artifact.artifact_id,
                artifact_hash=_runtime_scoped_exact_match_key(artifact.artifact_id),
                workspace=None,
                publisher=None,
                reason="cloud allow",
                source="cloud-sync",
            )
        ],
        "2026-06-19T00:01:00Z",
        remote_write_authorized=True,
    )

    def _degraded_state(_self, _connection, *, now, create_key):
        return {
            "mode": "degraded",
            "enforcement": "enforce",
            "generation": 1,
            "degraded_reasons": ["system_keyring_unavailable"],
        }

    monkeypatch.setattr(GuardStore, "_refresh_policy_integrity_state", _degraded_state)
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "source_scope": "project",
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert rc == 1
    assert output["policy_action"] == "require-reapproval"
    assert output["trust_status"]["remembered_rules"] == "disabled_degraded"
    assert output["remembered_rule_rejection"]["integrity_status"] == "degraded_mode"
    assert output["supply_chain_evaluation"]["reasons"][0]["code"] == "approval_reuse_integrity_failure"
    assert "remembered local rule was ignored" in output["decision_v2_json"]["harness_message"]


def test_guard_hook_emits_claude_native_ask_for_sensitive_file_reads(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    install_rc = main(
        [
            "guard",
            "install",
            "claude-code",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
        ]
    )
    capsys.readouterr()
    pre_tool_event = {
        "session_id": "session-claude-native-1",
        "tool_name": "Read",
        "tool_input": {"file_path": str(workspace_dir / ".env")},
        "source_scope": "project",
    }
    pre_tool_rc, pre_tool_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=pre_tool_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    pre_tool_output = json.loads(pre_tool_output)

    notification_event = {
        "session_id": "session-claude-native-1",
        "hook_event_name": "Notification",
        "notification_type": "permission_prompt",
        "title": "Permission needed",
        "message": "Claude needs your permission to use Read",
        "tool_name": "Read",
    }
    notification_rc, notification_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=notification_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert install_rc == 0
    assert pre_tool_rc == 0
    assert pre_tool_output["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert notification_rc == 0
    assert "HOL Guard intercepted Claude's attempt to use Read" in notification_output["systemMessage"]
    assert "came from HOL Guard, not from Claude alone" in notification_output["systemMessage"]
    assert "allow during this session" in notification_output["systemMessage"].lower()
    assert "keep blocked" in notification_output["systemMessage"].lower()


def test_guard_hook_emits_generic_claude_notification_notice_without_cached_reason(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    notification_event = {
        "session_id": "session-claude-2",
        "hook_event_name": "Notification",
        "notification_type": "permission_prompt",
        "title": "Permission needed",
        "message": "Claude needs your permission to use Bash",
        "tool_name": "Bash",
    }
    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=notification_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert rc == 0
    assert output["systemMessage"] == (
        "HOL Guard intercepted Claude's attempt to use Bash and is routing it to a HOL Guard approval question. "
        "This approval flow came from HOL Guard, not from Claude alone. "
        "HOL Guard will ask the user to choose Allow once, Allow during this session, or Keep blocked before Claude "
        "retries the action."
    )
    assert (
        "HOL Guard intercepted the sensitive request and is routing it into a HOL Guard approval question"
        in (output["hookSpecificOutput"]["additionalContext"])
    )
    assert (
        "allow once, allow during this session, and keep blocked"
        in (output["hookSpecificOutput"]["additionalContext"]).lower()
    )


def test_guard_hook_claude_notification_notice_is_tool_scoped_and_retained_while_pending(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    pre_tool_events = [
        {
            "session_id": "session-claude-3",
            "tool_name": "Read",
            "tool_input": {"file_path": str(workspace_dir / ".env")},
            "source_scope": "project",
        },
        {
            "session_id": "session-claude-3",
            "tool_name": "Bash",
            "tool_input": {"command": "docker run --rm alpine sh"},
            "source_scope": "project",
        },
    ]
    for event in pre_tool_events:
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
                "claude-code",
            ]
        )
        assert rc == 0
        capsys.readouterr()

    read_notification = {
        "session_id": "session-claude-3",
        "hook_event_name": "Notification",
        "notification_type": "permission_prompt",
        "title": "Permission needed",
        "message": "Claude needs your permission to use Read",
        "tool_name": "Read",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(read_notification)))
    first_rc, first_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=read_notification,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    second_rc, second_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event=read_notification,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert first_rc == 0
    assert "allow once" in first_output["systemMessage"].lower()
    assert "came from HOL Guard, not from Claude alone" in first_output["systemMessage"]
    assert "keep blocked" in first_output["systemMessage"].lower()
    assert "approval code:" in first_output["hookSpecificOutput"]["additionalContext"].lower()
    assert second_rc == 0
    assert "came from HOL Guard, not from Claude alone" in second_output["systemMessage"]
    assert "protect your local secrets" in second_output["systemMessage"]
    assert (
        second_output["hookSpecificOutput"]["additionalContext"]
        == first_output["hookSpecificOutput"]["additionalContext"]
    )
