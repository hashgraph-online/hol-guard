"""Runtime regression tests: guard hook blocks require reapproval."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    guard_commands_module,
    io,
    json,
    main,
    pytest,
    sys,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


class TestGuardRuntime:
    def test_guard_hook_blocks_require_reapproval(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        event = {
            "event": "PreToolUse",
            "tool_name": "workspace-tools",
            "artifact_id": "claude-code:project:mcp:workspace-tools",
            "artifact_name": "workspace-tools",
            "policy_action": "require-reapproval",
            "changed_capabilities": ["tool_name"],
            "provenance_summary": "project artifact defined at .mcp.json",
            "source_scope": "project",
        }
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
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["policy_action"] == "require-reapproval"

    def test_guard_hook_uses_decision_v2_harness_message_for_native_block(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        message = "HOL Guard blocked this launch because the action matched a sensitive local secret path."
        event = {
            "event": "PreToolUse",
            "artifact_id": "claude-code:project:mcp:workspace-tools",
            "artifact_name": "workspace-tools",
            "policy_action": "block",
            "decision_v2_json": {
                "harness_message": message,
            },
            "permission_decision_reason": "Generic fallback reason.",
            "changed_capabilities": ["tool_name"],
            "provenance_summary": "project artifact defined at .mcp.json",
            "source_scope": "project",
        }
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
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert output["hookSpecificOutput"]["permissionDecisionReason"] == message

    def test_guard_hook_codex_native_block_appends_approval_url_for_precomputed_payload(
        self,
        tmp_path,
        capsys,
        monkeypatch,
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "hook_event_name": "PreToolUse",
            "artifact_id": "codex:project:dangerous-command",
            "artifact_name": "dangerous-command",
            "policy_action": "block",
            "permission_decision_reason": "This command sends local secret to network host.",
            "approval_center_url": "http://127.0.0.1:4455",
            "approval_requests": [{"approval_url": "http://127.0.0.1:4455/requests/request-1"}],
            "changed_capabilities": ["command"],
            "provenance_summary": "project artifact defined at .codex/config.toml",
            "source_scope": "project",
        }
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
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "Open HOL Guard to approve or keep this blocked" in reason
        assert "http://127.0.0.1:4455/requests/request-1" in reason
        assert "Approve it in HOL Guard, then retry." not in reason

    def test_guard_hook_fallback_artifact_id_uses_scope(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        event = {
            "event": "PreToolUse",
            "tool_name": "workspace-tools",
            "source_scope": "project",
        }
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
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["artifact_id"] == "claude-code:project:mcp:workspace-tools"

    def test_guard_hook_uses_copilot_repo_hook_runtime_path(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "tool_name": "read_file",
            "tool_input": {"path": str(home_dir / ".env")},
            "policy_action": "require-reapproval",
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
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
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["artifact_type"] == "file_read_request"
        assert output["policy_action"] == "require-reapproval"
        assert output["path_summary"] == str(home_dir / ".env")

    def test_guard_hook_normalizes_copilot_camel_case_payload(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "toolName": "view",
            "toolArgs": json.dumps({"path": str(home_dir / ".env")}),
            "sourceScope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
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
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["artifact_type"] == "file_read_request"
        assert output["policy_action"] == "require-reapproval"
        assert output["path_summary"] == str(home_dir / ".env")

    @pytest.mark.parametrize(
        "path",
        [
            ".env",
            ".npmrc",
            ".pypirc",
            "~/.aws/" + "credentials",
            "~/.ssh/id_rsa",
            "~/.ssh/id_ed25519",
            "~/.gnupg/private-keys-v1.d/example.key",
            "~/.docker/" + "config.json",
            "~/.kube/config",
            ".terraform.tfvars",
        ],
    )
    def test_guard_hook_asks_for_planned_secret_file_reads(self, tmp_path, capsys, monkeypatch, path):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "tool_name": "read_file",
            "tool_input": {"path": path},
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
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
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["artifact_type"] == "file_read_request"
        assert output["policy_action"] == "require-reapproval"
