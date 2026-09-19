"""CLI policy listing, clearing and approval history."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.models import GuardApprovalRequest, PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_approvals_support import (
    _disable_real_desktop_notification_setup as _disable_real_desktop_notification_setup,
)


class TestGuardApprovals:
    def test_guard_policies_cli_clears_local_decisions_for_harness(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="block",
                artifact_id="claude-code:runtime:file-read:.npmrc",
                artifact_hash="hash-npmrc",
                reason="blocked during local test",
                source="claude-ask-user-question",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="harness",
                action="allow",
                reason="keep codex decisions",
                source="manual",
            ),
            "2026-04-23T00:00:00+00:00",
        )

        rc = main(["guard", "policies", "clear", "--home", str(home_dir), "--harness", "claude-code", "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["cleared"] == 1
        assert store.list_policy_decisions("claude-code") == []
        assert len(store.list_policy_decisions("codex")) == 1

    def test_guard_approvals_clear_history_resets_saved_decisions(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="block",
                artifact_id="claude-code:runtime:file-read:.env",
                artifact_hash="hash-env",
                reason="blocked during local test",
                source="claude-ask-user-question",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:workspace_skill",
                artifact_hash="hash-workspace",
                reason="keep codex allow",
                source="manual",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-claude-resolved",
                harness="claude-code",
                artifact_id="claude-code:runtime:file-read:.env",
                artifact_name=".env",
                artifact_hash="hash-env",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("first_seen",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".claude" / "settings.local.json"),
                review_command="hol-guard approvals approve req-claude-resolved",
                approval_url="http://127.0.0.1/pending/req-claude-resolved",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.resolve_approval_request(
            "req-claude-resolved",
            resolution_action="block",
            resolution_scope="artifact",
            reason="intentional block",
            resolved_at="2026-04-23T00:01:00+00:00",
        )
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-claude-pending",
                harness="claude-code",
                artifact_id="claude-code:runtime:file-read:.npmrc",
                artifact_name=".npmrc",
                artifact_hash="hash-npmrc",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("first_seen",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".claude" / "settings.local.json"),
                review_command="hol-guard approvals approve req-claude-pending",
                approval_url="http://127.0.0.1/pending/req-claude-pending",
            ),
            "2026-04-23T00:02:00+00:00",
        )

        rc = main(
            [
                "guard",
                "approvals",
                "clear-history",
                "--home",
                str(home_dir),
                "--harness",
                "claude-code",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["history_cleared"] is True
        assert output["cleared_policies"] == 1
        assert output["cleared_resolved_requests"] == 1
        assert store.list_policy_decisions("claude-code") == []
        assert len(store.list_policy_decisions("codex")) == 1
        assert len(store.list_approval_requests(status="resolved", harness="claude-code", limit=None)) == 0
        assert len(store.list_approval_requests(status="pending", harness="claude-code", limit=None)) == 1

    def test_guard_policies_clear_renders_non_json_result(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="block",
                artifact_id="claude-code:runtime:file-read:.npmrc",
                artifact_hash="hash-npmrc",
                reason="blocked during local test",
                source="claude-ask-user-question",
            ),
            "2026-04-23T00:00:00+00:00",
        )

        rc = main(["guard", "policies", "clear", "--home", str(home_dir), "--harness", "claude-code"])
        output = capsys.readouterr().out

        assert rc == 0
        assert "Guard rules clear" in output
        assert "cleared 1 decision" in output
        assert store.list_policy_decisions("claude-code") == []

    def test_guard_policies_clear_renders_non_json_validation_error(self, tmp_path, capsys):
        rc = main(["guard", "policies", "clear", "--home", str(tmp_path / "home")])
        output = capsys.readouterr().out

        assert rc == 2
        assert "Guard rules clear" in output
        assert "Choose --decision-id <id>, --harness <name>, or --all" in output

    def test_guard_policies_list_uses_remembered_rule_copy(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:package-request:pnpm",
                artifact_hash="hash-pnpm",
                reason="approved",
                source="manual",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.replace_remote_policies(
            [
                PolicyDecision(
                    harness="codex",
                    scope="publisher",
                    action="block",
                    publisher="npm",
                    reason="cloud bundle block",
                    source="cloud-sync",
                )
            ],
            "2026-04-23T00:01:00+00:00",
            remote_write_authorized=True,
        )

        rc = main(["guard", "policies", "--home", str(home_dir)])
        output = capsys.readouterr().out

        assert rc == 0
        assert "Guard remembered rules and Cloud policies" in output
        assert "policy_decisions" not in output

    def test_guard_policies_clear_rejects_all_with_harness(self, tmp_path, capsys):
        rc = main(
            [
                "guard",
                "policies",
                "clear",
                "--home",
                str(tmp_path / "home"),
                "--all",
                "--harness",
                "claude-code",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["cleared"] == 0
        assert "Choose either --all or --harness <name>" in output["error"]

    def test_guard_approvals_clear_history_requires_scope_selector(self, tmp_path, capsys):
        rc = main(["guard", "approvals", "clear-history", "--home", str(tmp_path / "home"), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["history_cleared"] is False
        assert output["cleared_policies"] == 0
        assert output["cleared_resolved_requests"] == 0
        assert "Choose --harness <name> or --all" in output["error"]

    def test_guard_approvals_clear_history_with_source_only_clears_matching_policies(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="block",
                artifact_id="claude-code:runtime:file-read:.env",
                artifact_hash="hash-env",
                reason="blocked during local test",
                source="claude-ask-user-question",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="allow",
                artifact_id="claude-code:runtime:file-read:.npmrc",
                artifact_hash="hash-npmrc",
                reason="keep manual allow",
                source="manual",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-claude-resolved-source",
                harness="claude-code",
                artifact_id="claude-code:runtime:file-read:.env",
                artifact_name=".env",
                artifact_hash="hash-env",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("first_seen",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".claude" / "settings.local.json"),
                review_command="hol-guard approvals approve req-claude-resolved-source",
                approval_url="http://127.0.0.1/pending/req-claude-resolved-source",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.resolve_approval_request(
            "req-claude-resolved-source",
            resolution_action="block",
            resolution_scope="artifact",
            reason="intentional block",
            resolved_at="2026-04-23T00:01:00+00:00",
        )

        rc = main(
            [
                "guard",
                "approvals",
                "clear-history",
                "--home",
                str(home_dir),
                "--harness",
                "claude-code",
                "--source",
                "claude-ask-user-question",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["history_cleared"] is True
        assert output["source"] == "claude-ask-user-question"
        assert output["cleared_policies"] == 1
        assert output["cleared_resolved_requests"] == 0
        remaining = store.list_policy_decisions("claude-code")
        assert len(remaining) == 1
        assert remaining[0]["source"] == "manual"
        assert len(store.list_approval_requests(status="resolved", harness="claude-code", limit=None)) == 1
