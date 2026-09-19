"""Runtime regression tests: runtime hook package without workspace invalidates allow."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    APPROVAL_CONTEXT_TOKEN_PREFIX,
    GuardStore,
    PolicyDecision,
    guard_commands_module,
    io,
    json,
    main,
    sys,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _write_json,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_runtime_hook_package_without_workspace_invalidates_allow_after_lockfile_mutation(
    tmp_path,
    capsys,
    monkeypatch,
):
    from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
        PackageRequestEvaluation,
        SupplyChainUserCopy,
    )

    home_dir = tmp_path / "home"
    cwd = tmp_path / "inherited-cwd"
    cwd.mkdir()
    _write_text(cwd / "package.json", '{"dependencies":{"minimist":"1.2.8"}}\n')
    _write_text(cwd / "package-lock.json", '{"lockfileVersion":3,"packages":{}}\n')
    _write_text(
        home_dir / "config.toml",
        'approval_wait_timeout_seconds = 0\n[risk_actions]\npackage_script = "review"\n',
    )
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "npm install minimist@1.2.8"},
        "source_scope": "project",
    }
    evaluation = PackageRequestEvaluation(
        decision="review",
        policy_action="review",
        enforcement="policy",
        entitlement_state="active",
        cache_status="hit",
        package_intent_hash="intent-hash",
        policy_version="policy-v1",
        bundle_version="bundle-v1",
        workspace_fingerprint="no-workspace",
        reasons=({"code": "package_review", "message": "Review package install."},),
        packages=({"name": "minimist", "decision": "review", "reasons": ()},),
        risk_summary="Review package install.",
        user_copy=SupplyChainUserCopy(
            title="Review package install",
            summary="Review package install.",
            next_step="Review the exact request.",
            dashboard_url=None,
            harness_message="Review package install.",
        ),
    )
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(guard_commands_module, "evaluate_package_request_artifact", lambda **_kwargs: evaluation)

    def run_without_workspace() -> tuple[int, dict[str, object]]:
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        rc = main(
            [
                "guard",
                "hook",
                "--home",
                str(home_dir),
                "--harness",
                "codex",
                "--json",
            ]
        )
        return rc, json.loads(capsys.readouterr().out)

    first_rc, first_output = run_without_workspace()
    store = GuardStore(home_dir)
    first_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=str(first_output["artifact_id"]),
            artifact_hash=first_token,
            reason="Reviewed exact inherited-cwd package context",
            source="manual",
        ),
        "2026-07-17T12:00:00+00:00",
    )

    unchanged_rc, unchanged_output = run_without_workspace()
    _write_text(
        cwd / "package-lock.json",
        '{"lockfileVersion":3,"packages":{"node_modules/minimist":{"version":"1.2.8"}}}\n',
    )
    changed_rc, changed_output = run_without_workspace()
    changed_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])

    assert first_rc == 1
    assert first_output["policy_action"] == "review"
    assert first_token.startswith(APPROVAL_CONTEXT_TOKEN_PREFIX)
    assert unchanged_rc == 0
    assert unchanged_output["policy_action"] == "allow"
    assert unchanged_output["supply_chain_evaluation"]["policy_action"] == "allow"
    assert unchanged_output["approval_reuse"]["status"] == "accepted"
    assert changed_rc == 1
    assert changed_output["policy_action"] == "review"
    assert changed_output["supply_chain_evaluation"]["policy_action"] == "review"
    assert changed_output["approval_reuse"]["status"] == "rejected"
    assert changed_output["approval_reuse"]["reason_code"] == "approval_reuse_content_changed"
    assert changed_token != first_token


def test_guard_hook_saved_file_read_allow_does_not_lower_current_reapproval(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    blocked_event = {
        "event": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": ".env.local"},
        "source_scope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(blocked_event)))

    first_rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "claude-code",
            "--json",
        ]
    )
    first_output = json.loads(capsys.readouterr().out)
    approval_request = first_output["approval_requests"][0]
    first_receipt = GuardStore(home_dir).list_receipts(limit=1)[0]

    approval_rc = main(
        [
            "guard",
            "approvals",
            "approve",
            str(approval_request["request_id"]),
            "--scope",
            "artifact",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(blocked_event)))
    second_rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "claude-code",
            "--json",
        ]
    )
    second_output = json.loads(capsys.readouterr().out)

    different_event = {
        "event": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "~/.aws/credentials"},
        "source_scope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(different_event)))
    third_rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "claude-code",
            "--json",
        ]
    )
    third_output = json.loads(capsys.readouterr().out)

    assert first_rc == 1
    assert first_output["policy_action"] == "require-reapproval"
    assert first_output["artifact_type"] == "file_read_request"
    assert "sensitive local file" in first_output["risk_summary"].lower()
    assert approval_request["recommended_scope"] == "workspace"
    assert approval_request["artifact_hash"].startswith(APPROVAL_CONTEXT_TOKEN_PREFIX)
    assert approval_request["artifact_hash"] == first_receipt["artifact_hash"]
    assert approval_rc == 0
    assert second_rc == 1
    assert second_output["policy_action"] == "require-reapproval"
    assert second_output["approval_reuse"]["reason_code"] == "approval_reuse_reapproval_required"
    assert third_rc == 1
    assert third_output["policy_action"] == "require-reapproval"


def test_guard_hook_exact_v1_allow_cannot_hide_matching_legacy_block(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    def saved_decision_lookup(
        _store: GuardStore,
        _harness: str,
        _artifact_id: str,
        *,
        artifact_hash: str,
        **kwargs: object,
    ) -> dict[str, object]:
        assert kwargs["consume_one_shot"] is False
        action = "allow" if artifact_hash.startswith(APPROVAL_CONTEXT_TOKEN_PREFIX) else "block"
        return {
            "decision": {
                "action": action,
                "artifact_hash": artifact_hash,
                "scope": "artifact",
                "source": "local",
            },
            "ignored_local_integrity": None,
            "trust_status": {},
        }

    monkeypatch.setattr(
        GuardStore,
        "resolve_policy_decision_lookup_with_memory_pattern",
        saved_decision_lookup,
    )
    monkeypatch.setattr(
        guard_commands_module,
        "ensure_guard_daemon",
        lambda _guard_home: (_ for _ in ()).throw(AssertionError("a saved block must not be queued")),
    )
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(
            json.dumps(
                {
                    "event": "PreToolUse",
                    "tool_name": "Read",
                    "tool_input": {"file_path": ".env.local"},
                    "source_scope": "project",
                }
            )
        ),
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
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert output["policy_action"] == "block"
    assert output["approval_reuse"]["reason_code"] == "approval_reuse_saved_block"
    assert GuardStore(home_dir).list_receipts(limit=1)[0]["policy_decision"] == "block"


def test_guard_hook_saved_artifact_approval_never_lowers_current_payload_block(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    blocked_event = {
        "hookName": "preToolUse",
        "toolName": "bash",
        "toolArgs": {"command": "echo MALICIOUS > dangerous-marker.json"},
        "policyAction": "block",
        "sourceScope": "project",
        "cwd": str(workspace_dir),
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(blocked_event)))

    first_rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "copilot",
            "--json",
        ]
    )
    first_output = json.loads(capsys.readouterr().out)
    store = GuardStore(home_dir)
    first_receipt = store.list_receipts(limit=1)[0]
    store.upsert_policy(
        PolicyDecision(
            harness="copilot",
            scope="artifact",
            action="allow",
            artifact_id=str(first_output["artifact_id"]),
            artifact_hash=str(first_receipt["artifact_hash"]),
            reason="Reviewed exact artifact before current policy became terminal.",
            source="manual",
        ),
        "2026-07-17T12:00:00+00:00",
    )

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(blocked_event)))
    second_rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "copilot",
            "--json",
        ]
    )
    second_output = json.loads(capsys.readouterr().out)

    different_event = {
        "hookName": "preToolUse",
        "toolName": "bash",
        "toolArgs": {"command": "echo MALICIOUS > danger-two.json"},
        "policyAction": "block",
        "sourceScope": "project",
        "cwd": str(workspace_dir),
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(different_event)))
    third_rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "copilot",
            "--json",
        ]
    )
    third_output = json.loads(capsys.readouterr().out)

    assert first_rc == 1
    assert first_output["policy_action"] == "block"
    assert first_output["approval_requests"] == []
    assert first_output["terminal"] is True
    assert first_output["artifact_type"] == "tool_action_request"
    assert "recovery may require version control or a backup" in first_output["risk_summary"].lower()
    assert second_rc == 1
    assert second_output["policy_action"] == "block"
    assert second_output["approval_reuse"]["status"] == "rejected"
    assert second_output["approval_reuse"]["reason_code"] == "approval_reuse_current_block"
    assert third_rc == 1
    assert third_output["policy_action"] == "block"
    assert third_output["approval_requests"] == []


def test_guard_hook_codex_emits_native_deny_for_sensitive_bash_command(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 0\n")
    monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    event_path = tmp_path / "codex-hook.json"
    _write_json(
        event_path,
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo MALICIOUS > dangerous-marker.json"},
            "policy_action": "require-reapproval",
            "cwd": str(workspace_dir),
        },
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
            "codex",
            "--event-file",
            str(event_path),
        ]
    )
    captured = capsys.readouterr()

    payload = json.loads(captured.out)
    reason = payload["hookSpecificOutput"]["permissionDecisionReason"]
    assert rc == 0
    assert captured.err == ""
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "HOL Guard" in reason
    assert "HOL Guard blocked this action" in reason
    assert "http://127.0.0.1:4455/requests/" not in reason
    assert "approve" not in reason.lower()
