"""Headless queueing and CLI approval resolution."""

from __future__ import annotations

import json
from dataclasses import replace

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.approval_scope_support import StaleApprovalScopeContractError, request_scope_contract
from codex_plugin_scanner.guard.cli import approval_commands as approval_commands_module
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_approvals_support import (
    _build_guard_fixture,
    _clear_agent_context,
)
from tests.guard_approvals_support import (
    _disable_real_desktop_notification_setup as _disable_real_desktop_notification_setup,
)


class TestGuardApprovals:
    def test_guard_run_headless_enqueues_approval_request(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        store = GuardStore(home_dir)
        approvals = store.list_approval_requests()

        assert rc == 1
        assert output["blocked"] is True
        assert output["approval_center_url"].startswith("http://127.0.0.1:")
        assert approvals[0]["harness"] == "codex"
        assert approvals[0]["status"] == "pending"
        assert approvals[0]["decision_v2_json"]["action"] == "ask"
        assert (
            approvals[0]["decision_v2_json"]["harness_message"]
            == "HOL Guard needs a fresh approval because this action changed."
        )

    def test_guard_approvals_cli_lists_and_resolves_requests(self, tmp_path, capsys, monkeypatch):
        _clear_agent_context(monkeypatch)
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-789",
                harness="codex",
                artifact_id="codex:project:workspace_skill",
                artifact_name="workspace_skill",
                artifact_hash="hash-789",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-789",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )

        list_rc = main(["guard", "approvals", "--home", str(home_dir), "--json"])
        list_output = json.loads(capsys.readouterr().out)
        approve_rc = main(
            [
                "guard",
                "approvals",
                "approve",
                "req-789",
                "--home",
                str(home_dir),
                "--scope",
                "artifact",
                "--reason",
                "approved",
                "--json",
            ]
        )
        approve_output = json.loads(capsys.readouterr().out)

        assert list_rc == 0
        assert list_output["items"][0]["request_id"] == "req-789"
        assert approve_rc == 0
        assert approve_output["resolved"] is True
        assert store.list_policy_decisions("codex") == []

        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-remember",
                harness="codex",
                artifact_id="codex:project:workspace_skill",
                artifact_name="workspace_skill",
                artifact_hash="hash-remember",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / "config.toml"),
                review_command="hol-guard approvals approve req-remember",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:01:00+00:00",
        )
        remember_rc = main(
            [
                "guard",
                "approvals",
                "approve",
                "req-remember",
                "--home",
                str(home_dir),
                "--scope",
                "artifact",
                "--remember",
                "--reason",
                "approved",
                "--json",
            ]
        )
        remember_output = json.loads(capsys.readouterr().out)

        assert remember_rc == 0
        assert remember_output["resolved"] is True
        assert remember_output["item"]["applied_scope"] == "artifact"
        assert store.list_policy_decisions("codex") == []

    def test_guard_approvals_cli_remembers_eligible_exact_action(self, tmp_path, capsys, monkeypatch):
        _clear_agent_context(monkeypatch)
        home_dir = tmp_path / "home"
        workspace = str(tmp_path / "workspace")
        store = GuardStore(home_dir)
        exact_request = GuardApprovalRequest(
            request_id="req-exact-remember",
            harness="codex",
            artifact_id="codex:project:tool-action:script",
            artifact_name="Bash unmatched tool action",
            artifact_type="tool_action_request",
            artifact_hash="hash-exact-remember",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("tool_action",),
            source_scope="project",
            config_path=workspace,
            workspace=workspace,
            launch_target="npm run guard:acquisition-loop",
            action_envelope_json={
                "action_type": "shell_command",
                "tool_name": "Bash",
                "command": "npm run guard:acquisition-loop",
                "raw_payload_redacted": {
                    "tool_name": "Bash",
                    "tool_input": {"command": "npm run guard:acquisition-loop"},
                    "permission_mode": "ask",
                },
            },
            review_command="hol-guard approvals approve req-exact-remember",
            approval_url="http://127.0.0.1/pending",
        )
        store.add_approval_request(
            exact_request,
            "2026-08-11T00:02:00+00:00",
        )

        remember_rc = main(
            [
                "guard",
                "approvals",
                "approve",
                "req-exact-remember",
                "--home",
                str(home_dir),
                "--scope",
                "artifact",
                "--remember",
                "--json",
            ]
        )
        remember_output = json.loads(capsys.readouterr().out)

        assert remember_rc == 0
        assert remember_output["resolved"] is True
        assert remember_output["item"]["exact_action_persistence_eligible"] is True
        assert remember_output["item"]["scope_contract_version"].startswith("guard.approval-scopes.v")
        assert len(remember_output["item"]["scope_contract_digest"]) == 64
        decisions = store.list_policy_decisions("codex")
        assert len(decisions) == 1
        assert decisions[0]["action"] == "allow"
        assert decisions[0]["scope"] == "artifact"

        stale_request = replace(
            exact_request,
            request_id="req-stale-remember",
            artifact_hash="hash-stale-remember",
            review_command="hol-guard approvals approve req-stale-remember",
        )
        store.add_approval_request(stale_request, "2026-08-11T00:03:00+00:00")
        stale_contract = request_scope_contract(store.get_approval_request("req-stale-remember") or {})

        def raise_stale_contract(**_kwargs):
            raise StaleApprovalScopeContractError(stale_contract)

        monkeypatch.setattr(approval_commands_module, "apply_approval_resolution", raise_stale_contract)
        stale_rc = main(
            [
                "guard",
                "approvals",
                "approve",
                "req-stale-remember",
                "--home",
                str(home_dir),
                "--scope",
                "artifact",
                "--remember",
                "--json",
            ]
        )
        stale_output = json.loads(capsys.readouterr().out)

        assert stale_rc == 4
        assert stale_output["resolved"] is False
        assert stale_output["error"] == "stale_scope_contract"
        assert stale_output["scope_contract_digest"] == stale_contract.digest

    def test_guard_approvals_cli_derives_workspace_scope_without_workspace_override(
        self,
        tmp_path,
        capsys,
        monkeypatch,
    ):
        _clear_agent_context(monkeypatch)
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-workspace",
                harness="codex",
                artifact_id="codex:project:workspace_skill",
                artifact_name="workspace_skill",
                artifact_hash="hash-workspace",
                policy_action="require-reapproval",
                recommended_scope="workspace",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-workspace",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )

        try:
            main(
                [
                    "guard",
                    "approvals",
                    "approve",
                    "req-workspace",
                    "--home",
                    str(home_dir),
                    "--scope",
                    "workspace",
                    "--json",
                ]
            )
        except SystemExit as error:
            rc = error.code
        else:
            rc = 0

        captured = capsys.readouterr()
        payload = json.loads(captured.out)

        assert rc == 0
        assert captured.err == ""
        assert payload["resolved"] is True
        assert payload["item"]["resolution_scope"] == "artifact"
        assert payload["item"]["scope_warning"] == "legacy_scope_narrowed_to_artifact"
        assert store.get_approval_request("req-workspace")["status"] == "resolved"
