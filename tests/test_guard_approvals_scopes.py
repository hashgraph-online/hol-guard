"""Approval scope coverage, duplicate queues and workspace isolation."""

from __future__ import annotations

from codex_plugin_scanner.guard.approval_scope_support import package_request_portable_workspace_scope
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.models import GuardApprovalRequest, GuardArtifact
from codex_plugin_scanner.guard.package_execution_context import build_package_execution_context
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_approvals_support import (
    _disable_real_desktop_notification_setup as _disable_real_desktop_notification_setup,
)
from tests.guard_approvals_support import (
    _write_text,
)


class TestGuardApprovals:
    def test_guard_store_keeps_request_id_when_duplicate_pending_request_is_requeued(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        original = GuardApprovalRequest(
            request_id="req-original",
            harness="codex",
            artifact_id="codex:project:workspace_skill",
            artifact_name="workspace_skill",
            artifact_hash="hash-1",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("args",),
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            review_command="hol-guard approvals approve req-original",
            approval_url="http://127.0.0.1:4455/approvals/req-original",
        )
        updated = GuardApprovalRequest(
            request_id="req-new",
            harness="codex",
            artifact_id=original.artifact_id,
            artifact_name="workspace_skill",
            artifact_hash="hash-2",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("command",),
            source_scope="project",
            config_path=original.config_path,
            review_command="hol-guard approvals approve req-new",
            approval_url="http://127.0.0.1:4455/approvals/req-new",
        )

        first_id = store.add_approval_request(original, "2026-04-11T00:00:00+00:00")
        second_id = store.add_approval_request(updated, "2026-04-11T00:01:00+00:00")
        pending = store.list_approval_requests()

        assert first_id == "req-original"
        assert second_id == "req-original"
        assert len(pending) == 1
        assert pending[0]["request_id"] == "req-original"
        assert pending[0]["artifact_hash"] == "hash-2"
        assert pending[0]["changed_fields"] == ["command"]

    def test_guard_broad_scope_resolution_clears_matching_pending_requests(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        for request_id, artifact_id in (
            ("req-a", "codex:project:mcp:first"),
            ("req-b", "codex:project:mcp:second"),
        ):
            store.add_approval_request(
                GuardApprovalRequest(
                    request_id=request_id,
                    harness="codex",
                    artifact_id=artifact_id,
                    artifact_name=artifact_id.rsplit(":", maxsplit=1)[-1],
                    artifact_type="mcp_server",
                    artifact_hash=f"hash-{request_id}",
                    policy_action="require-reapproval",
                    recommended_scope="harness",
                    changed_fields=("args",),
                    source_scope="project",
                    config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                    review_command=f"hol-guard approvals approve {request_id}",
                    approval_url=f"http://127.0.0.1:4455/approvals/{request_id}",
                ),
                "2026-04-11T00:00:00+00:00",
            )

        resolved = apply_approval_resolution(
            store=store,
            request_id="req-a",
            action="block",
            scope="harness",
            workspace=None,
            reason="blocked in harness",
            now="2026-04-11T00:02:00+00:00",
        )

        assert resolved["status"] == "resolved"
        assert store.get_approval_request("req-b")["status"] == "resolved"

    def test_guard_global_scope_resolution_clears_pending_requests_across_harnesses(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        for request_id, harness in (("req-codex", "codex"), ("req-copilot", "copilot")):
            store.add_approval_request(
                GuardApprovalRequest(
                    request_id=request_id,
                    harness=harness,
                    artifact_id=f"{harness}:project:mcp:item",
                    artifact_name=f"{harness}-item",
                    artifact_type="mcp_server",
                    artifact_hash=f"hash-{request_id}",
                    policy_action="require-reapproval",
                    recommended_scope="global",
                    changed_fields=("args",),
                    source_scope="project",
                    config_path=str(tmp_path / harness / ".config" / "guard.toml"),
                    review_command=f"hol-guard approvals approve {request_id}",
                    approval_url=f"http://127.0.0.1:4455/approvals/{request_id}",
                ),
                "2026-04-11T00:00:00+00:00",
            )

        resolved = apply_approval_resolution(
            store=store,
            request_id="req-codex",
            action="block",
            scope="global",
            workspace=None,
            reason="blocked globally",
            now="2026-04-11T00:02:00+00:00",
        )

        pending = store.list_approval_requests(status="pending", limit=None)
        decisions = store.list_policy_decisions()

        assert resolved["status"] == "resolved"
        assert pending == []
        assert decisions[0]["harness"] == "*"

    def test_guard_broad_scope_resolution_clears_more_than_default_pending_page(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        for index in range(520):
            store.add_approval_request(
                GuardApprovalRequest(
                    request_id=f"req-{index}",
                    harness="codex",
                    artifact_id=f"codex:project:mcp:item-{index}",
                    artifact_name=f"item-{index}",
                    artifact_type="mcp_server",
                    artifact_hash=f"hash-{index}",
                    policy_action="require-reapproval",
                    recommended_scope="harness",
                    changed_fields=("args",),
                    source_scope="project",
                    config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                    review_command=f"hol-guard approvals approve req-{index}",
                    approval_url=f"http://127.0.0.1:4455/approvals/req-{index}",
                ),
                "2026-04-11T00:00:00+00:00",
            )

        resolved = apply_approval_resolution(
            store=store,
            request_id="req-0",
            action="block",
            scope="harness",
            workspace=None,
            reason="blocked in harness",
            now="2026-04-11T00:02:00+00:00",
        )

        pending = store.list_approval_requests(status="pending", harness="codex", limit=None)

        assert resolved["status"] == "resolved"
        assert pending == []

    def test_guard_pending_request_payload_lists_supported_scopes(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        workspace = tmp_path / "workspace"
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-supported-scopes",
                harness="codex",
                artifact_id="codex:project:tool-action:req-supported-scopes",
                artifact_name="Shell command",
                artifact_type="tool_action_request",
                artifact_hash="hash-supported-scopes",
                policy_action="require-reapproval",
                recommended_scope="publisher",
                changed_fields=("shell_command",),
                source_scope="project",
                config_path=str(workspace / ".codex" / "config.toml"),
                workspace=str(workspace),
                publisher="hashgraph-online",
                review_command="hol-guard approvals approve req-supported-scopes",
                approval_url="http://127.0.0.1:5474/requests/req-supported-scopes",
            ),
            "2026-04-11T00:00:00+00:00",
        )

        request = store.get_approval_request("req-supported-scopes")

        assert request is not None
        assert request["allowed_scopes"] == ["artifact", "workspace"]
        assert request["allowed_scopes_by_action"] == {
            "allow": ["artifact", "workspace"],
            "block": ["artifact", "workspace", "publisher", "harness", "global"],
        }

    def test_guard_workspace_resolution_does_not_match_sibling_workspace(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        primary_workspace = tmp_path / "workspace"
        sibling_workspace = tmp_path / "workspace-copy"
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-primary",
                harness="codex",
                artifact_id="codex:project:primary",
                artifact_name="primary",
                artifact_hash="hash-primary",
                policy_action="require-reapproval",
                recommended_scope="workspace",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(primary_workspace / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-primary",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-sibling",
                harness="codex",
                artifact_id="codex:project:sibling",
                artifact_name="sibling",
                artifact_hash="hash-sibling",
                policy_action="require-reapproval",
                recommended_scope="workspace",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(sibling_workspace / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-sibling",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )

        resolved = apply_approval_resolution(
            store=store,
            request_id="req-primary",
            action="allow",
            scope="workspace",
            workspace=str(primary_workspace),
            reason="trusted in workspace",
            now="2026-04-11T00:02:00+00:00",
        )

        assert resolved["status"] == "resolved"
        assert store.get_approval_request("req-primary")["status"] == "resolved"
        assert store.get_approval_request("req-sibling")["status"] == "pending"

    def test_guard_workspace_package_resolution_stays_bound_to_same_request(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir()
        (workspace_dir / ".git").mkdir()
        _write_text(workspace_dir / ".git" / "config", '[remote "origin"]\nurl = https://example.test/app.git\n')
        _write_text(workspace_dir / "package.json", '{"name":"approval-test"}\n')
        executable = tmp_path / "bin" / "npm"
        _write_text(executable, "#!/bin/sh\n")
        executable.chmod(0o755)
        (tmp_path / "home").mkdir()
        package_artifact = GuardArtifact(
            artifact_id="guard-cli:project:package-request:a",
            name="npm install left-pad",
            harness="guard-cli",
            artifact_type="package_request",
            source_scope="project",
            config_path=str(workspace_dir / "hol-guard.toml"),
            metadata={
                "package_manager": "npm",
                "package_executable": "npm",
                "manifest_paths": ["package.json"],
                "lockfile_paths": [],
            },
        )
        package_context = build_package_execution_context(
            workspace_dir=workspace_dir,
            artifact=package_artifact,
            environment={"HOME": str(tmp_path / "home"), "PATH": str(executable.parent)},
        )
        assert package_context.portable is True
        scanner_evidence = (package_context.to_evidence(),)
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-package-a",
                harness="guard-cli",
                artifact_id="guard-cli:project:package-request:a",
                artifact_name="npm install left-pad",
                artifact_hash="hash-package-a",
                policy_action="require-reapproval",
                recommended_scope="workspace",
                changed_fields=("package_request",),
                source_scope="project",
                config_path=str(workspace_dir / "hol-guard.toml"),
                review_command="hol-guard approvals approve req-package-a",
                approval_url="http://127.0.0.1/pending",
                workspace=str(workspace_dir),
                artifact_type="package_request",
                scanner_evidence=scanner_evidence,
            ),
            "2026-04-11T00:00:00+00:00",
        )
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-package-b",
                harness="guard-cli",
                artifact_id="guard-cli:project:package-request:b",
                artifact_name="npm install chalk",
                artifact_hash="hash-package-b",
                policy_action="require-reapproval",
                recommended_scope="workspace",
                changed_fields=("package_request",),
                source_scope="project",
                config_path=str(workspace_dir / "hol-guard.toml"),
                review_command="hol-guard approvals approve req-package-b",
                approval_url="http://127.0.0.1/pending",
                workspace=str(workspace_dir),
                artifact_type="package_request",
                scanner_evidence=scanner_evidence,
            ),
            "2026-04-11T00:00:00+00:00",
        )

        resolved = apply_approval_resolution(
            store=store,
            request_id="req-package-a",
            action="allow",
            scope="workspace",
            workspace=str(workspace_dir),
            reason="trusted package request",
            now="2026-04-11T00:02:00+00:00",
        )

        assert resolved["status"] == "resolved"
        assert store.get_approval_request("req-package-a")["status"] == "resolved"
        assert store.get_approval_request("req-package-b")["status"] == "pending"
        package_a_workspace = package_request_portable_workspace_scope(
            artifact_id="guard-cli:project:package-request:a",
            artifact_hash="hash-package-a",
            artifact_type="package_request",
            execution_context=package_context,
        )
        package_b_workspace = package_request_portable_workspace_scope(
            artifact_id="guard-cli:project:package-request:b",
            artifact_hash="hash-package-b",
            artifact_type="package_request",
            execution_context=package_context,
        )
        assert package_a_workspace is not None
        assert package_b_workspace is not None
        assert (
            store.resolve_policy_decision(
                "guard-cli",
                "guard-cli:project:package-request:a",
                "hash-package-a",
                package_a_workspace,
                now="2026-04-11T00:03:00+00:00",
            )["action"]
            == "allow"
        )
        assert (
            store.resolve_policy_decision(
                "guard-cli",
                "guard-cli:project:package-request:b",
                "hash-package-b",
                package_b_workspace,
            )
            is None
        )
