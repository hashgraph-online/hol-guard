"""Saved approval integrity, race handling and policy expiry."""

from __future__ import annotations

from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.models import GuardApprovalRequest, PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_approvals_support import (
    _disable_real_desktop_notification_setup as _disable_real_desktop_notification_setup,
)


class TestGuardApprovals:
    def test_guard_package_artifact_approval_replay_fails_closed_without_integrity_key(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        artifact_id = "guard-cli:project:package-request:impeccable"
        artifact_hash = "hash-impeccable"
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-package-once",
                harness="guard-cli",
                artifact_id=artifact_id,
                artifact_name="impeccable",
                artifact_type="package_request",
                artifact_hash=artifact_hash,
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("package_request",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / "hol-guard.toml"),
                workspace=str(tmp_path / "workspace"),
                launch_target="npx impeccable update",
                review_command="hol-guard approvals approve req-package-once",
                approval_url="http://127.0.0.1:4455/approvals/req-package-once",
            ),
            "2026-04-11T00:00:00+00:00",
        )

        resolved = apply_approval_resolution(
            store=store,
            request_id="req-package-once",
            action="allow",
            scope="artifact",
            workspace=None,
            reason="approved once",
            now="2026-04-11T00:02:00+00:00",
        )

        with store._connect() as connection:
            policy_count = connection.execute("select count(*) from policy_decisions").fetchone()[0]
        assert policy_count == 1
        store._policy_integrity_secret_store = None
        store._clear_policy_integrity_cache()
        first_retry = store.resolve_policy_decision(
            "guard-cli",
            artifact_id,
            artifact_hash,
            str(tmp_path / "workspace"),
            now="2026-04-11T00:03:00+00:00",
        )
        second_retry = store.resolve_policy_decision(
            "guard-cli",
            artifact_id,
            artifact_hash,
            str(tmp_path / "workspace"),
            now="2026-04-11T00:04:00+00:00",
        )
        changed_request = store.resolve_policy_decision(
            "guard-cli",
            artifact_id,
            "hash-changed",
            str(tmp_path / "workspace"),
            now="2026-04-11T00:05:00+00:00",
        )

        assert resolved["status"] == "resolved"
        assert first_retry is None
        assert second_retry is None
        assert changed_request is None
        ignored = store.list_events(event_name="rule.ignored.local_integrity")
        assert any(event["payload"].get("source") == "approval-gate" for event in ignored)

    def test_guard_saved_scope_repairs_integrity_before_policy_write(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")
        calls = []

        def fake_repair(**kwargs):
            calls.append(kwargs)
            return {"mode": "protected", "trust_status": {"remembered_rules": "enforced"}}

        monkeypatch.setattr(store, "ensure_policy_integrity_ready_for_write", fake_repair)
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-package-save",
                harness="guard-cli",
                artifact_id="guard-cli:project:mcp:impeccable",
                artifact_name="impeccable",
                artifact_type="mcp_server",
                artifact_hash="hash-impeccable",
                policy_action="require-reapproval",
                recommended_scope="global",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / "hol-guard.toml"),
                workspace=str(tmp_path / "workspace"),
                launch_target="impeccable.update",
                review_command="hol-guard approvals approve req-package-save",
                approval_url="http://127.0.0.1:4455/approvals/req-package-save",
            ),
            "2026-04-11T00:00:00+00:00",
        )

        apply_approval_resolution(
            store=store,
            request_id="req-package-save",
            action="allow",
            scope="global",
            workspace=None,
            reason="remember globally",
            now="2026-04-11T00:02:00+00:00",
        )

        decisions = store.list_policy_decisions()
        assert calls
        assert decisions == []

    def test_guard_saved_scope_falls_back_to_once_when_integrity_repair_fails(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")
        workspace = str(tmp_path / "workspace")
        artifact_id = "guard-cli:project:mcp:impeccable"
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-package-degraded",
                harness="guard-cli",
                artifact_id=artifact_id,
                artifact_name="impeccable",
                artifact_type="mcp_server",
                artifact_hash="hash-impeccable",
                policy_action="require-reapproval",
                recommended_scope="global",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / "hol-guard.toml"),
                workspace=workspace,
                launch_target="impeccable.update",
                review_command="hol-guard approvals approve req-package-degraded",
                approval_url="http://127.0.0.1:4455/approvals/req-package-degraded",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        monkeypatch.setattr(
            store,
            "ensure_policy_integrity_ready_for_write",
            lambda **_kwargs: {"mode": "degraded", "trust_status": {"remembered_rules": "disabled_degraded"}},
        )

        apply_approval_resolution(
            store=store,
            request_id="req-package-degraded",
            action="allow",
            scope="global",
            workspace=None,
            reason="remember globally",
            now="2026-04-11T00:02:00+00:00",
        )

        first_retry = store.resolve_policy_decision(
            "guard-cli",
            artifact_id,
            "hash-impeccable",
            workspace,
            now="2026-04-11T00:03:00+00:00",
        )

        decisions = store.list_policy_decisions()
        assert decisions == []
        assert first_retry is not None
        assert first_retry["action"] == "allow"

    def test_guard_local_once_claim_returns_none_when_update_loses_race(self):
        class FakeCursor:
            rowcount = 0

        class FakeConnection:
            def execute(self, query, _params=()):
                if query.lstrip().startswith("select"):
                    return self
                return FakeCursor()

            def fetchone(self):
                return {
                    "action": "allow",
                    "approval_id": "approval-race",
                    "artifact_hash": "hash-impeccable",
                    "artifact_id": "guard-cli:project:tool-action:impeccable",
                    "created_at": "2026-04-11T00:00:00+00:00",
                    "expires_at": "2026-04-11T00:05:00+00:00",
                    "harness": "guard-cli",
                    "publisher": None,
                    "request_id": "req-race",
                    "workspace": None,
                }

        claimed = GuardStore._claim_local_once_approval_locked(
            FakeConnection(),
            harness="guard-cli",
            artifact_id="guard-cli:project:tool-action:impeccable",
            artifact_hash="hash-impeccable",
            workspace=None,
            publisher=None,
            now="2026-04-11T00:01:00+00:00",
        )

        assert claimed is None

    def test_guard_store_ignores_expired_policy_decisions(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.record_local_once_approval(
            request_id="req-expiring-once",
            harness="codex",
            artifact_id="codex:project:workspace_skill",
            artifact_hash="hash-123",
            workspace=None,
            publisher=None,
            action="allow",
            created_at="2026-04-11T00:00:00+00:00",
            expires_at="2026-04-11T01:00:00+00:00",
        )

        before_expiry = store.resolve_policy_decision(
            "codex",
            "codex:project:workspace_skill",
            "hash-123",
            now="2026-04-11T00:30:00+00:00",
        )
        after_expiry = store.resolve_policy_decision(
            "codex",
            "codex:project:workspace_skill",
            "hash-123",
            now="2026-04-11T02:00:00+00:00",
        )
        decisions = store.list_policy_decisions()

        assert before_expiry is not None
        assert before_expiry["action"] == "allow"
        assert after_expiry is None
        assert decisions == []

    def test_guard_store_ignores_expired_policy_decisions_without_explicit_now(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:workspace_skill",
                artifact_hash="hash-legacy",
                expires_at="2000-01-01T00:00:00+00:00",
            ),
            "1999-01-01T00:00:00+00:00",
        )

        resolved = store.resolve_policy("codex", "codex:project:workspace_skill", "hash-legacy")

        assert resolved is None

    def test_guard_store_does_not_match_hash_scoped_artifact_policy_without_current_hash(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:workspace_skill",
                artifact_hash="hash-locked",
            ),
            "2026-04-11T00:00:00+00:00",
        )

        resolved = store.resolve_policy(
            "codex",
            "codex:project:workspace_skill",
            None,
            now="2026-04-11T00:30:00+00:00",
        )

        assert resolved is None
