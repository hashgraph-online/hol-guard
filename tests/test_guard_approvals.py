"""Approval queue persistence and serialized payloads."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace

from codex_plugin_scanner.guard.approvals import build_runtime_snapshot
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_approvals_support import (
    _disable_real_desktop_notification_setup as _disable_real_desktop_notification_setup,
)


class TestGuardApprovals:
    def test_guard_queue_dedupes_harness_delivery_metadata(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        workspace = str(tmp_path / "workspace")
        base = GuardApprovalRequest(
            request_id="req-first",
            harness="codex",
            artifact_id="codex:project:tool-action:script",
            artifact_name="Bash unmatched tool action",
            artifact_type="tool_action_request",
            artifact_hash="hash-script",
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
                    "tool_use_id": "tool-first",
                    "transcript_path": "sessions/first.jsonl",
                    "model": "model-first",
                    "permission_mode": "ask",
                },
            },
            review_command="hol-guard approvals approve req-first",
            approval_url="http://127.0.0.1:5474/requests/req-first",
        )
        store.add_approval_request(base, "2026-08-11T00:00:00+00:00")
        first = store.get_approval_request("req-first")
        assert first is not None
        second = replace(
            base,
            request_id="req-second",
            action_envelope_json={
                **(base.action_envelope_json or {}),
                "raw_payload_redacted": {
                    "tool_name": "Bash",
                    "tool_input": {"command": "npm run guard:acquisition-loop"},
                    "tool_use_id": "tool-second",
                    "transcript_path": "sessions/second.jsonl",
                    "model": "model-second",
                    "permission_mode": "ask",
                },
            },
        )

        persisted = store.add_approval_request(second, "2026-08-11T00:01:00+00:00")

        assert persisted == "req-first"
        pending = store.list_approval_requests(limit=10)
        assert len(pending) == 1
        assert pending[0]["dedupe_count"] == 2
        assert pending[0]["scope_contract_digest"] == first["scope_contract_digest"]

    def test_guard_queue_keeps_permission_modes_separate(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        workspace = str(tmp_path / "workspace")

        def request(request_id: str, permission_mode: str) -> GuardApprovalRequest:
            return GuardApprovalRequest(
                request_id=request_id,
                harness="codex",
                artifact_id="codex:project:tool-action:script",
                artifact_name="Bash unmatched tool action",
                artifact_type="tool_action_request",
                artifact_hash=f"hash-{permission_mode}",
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
                        "permission_mode": permission_mode,
                    },
                },
                review_command=f"hol-guard approvals approve {request_id}",
                approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
            )

        store.add_approval_request(request("req-ask", "ask"), "2026-08-11T00:00:00+00:00")
        store.add_approval_request(
            request("req-bypass", "bypassPermissions"),
            "2026-08-11T00:01:00+00:00",
        )

        pending = store.list_approval_requests(limit=10)
        assert len(pending) == 2

    def test_guard_store_persists_and_resolves_approval_requests(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        workspace_dir = tmp_path / "workspace"
        action_envelope_json = {
            "schema_version": 1,
            "action_id": "action-123",
            "harness": "codex",
            "event_name": "PreToolUse",
            "action_type": "shell_command",
            "workspace": "~/workspace",
            "workspace_hash": "workspace-hash",
            "tool_name": "Bash",
            "command": "cat ~/.npmrc",
            "prompt_excerpt": None,
            "target_paths": ["~/.npmrc"],
            "network_hosts": [],
            "mcp_server": None,
            "mcp_tool": None,
            "package_manager": None,
            "package_name": None,
            "script_name": None,
            "raw_payload_redacted": {"tool_name": "Bash"},
        }
        decision_v2_json = {
            "action": "ask",
            "reason": "require-reapproval",
            "user_title": "Review workspace_skill",
            "user_body": "HOL Guard needs approval before this action continues.",
            "harness_message": "HOL Guard paused this action for approval.",
            "dashboard_primary_detail": "Shell command can read a local secret file.",
            "approval_scopes": ["artifact", "workspace"],
            "retry_instruction": "Approve it in HOL Guard, then retry.",
            "signals": [],
            "confidence": "likely",
        }
        request = GuardApprovalRequest(
            request_id="req-123",
            harness="codex",
            artifact_id="codex:project:workspace_skill",
            artifact_name="workspace_skill",
            artifact_hash="hash-123",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("args",),
            source_scope="project",
            config_path=str(workspace_dir / ".codex" / "config.toml"),
            workspace=str(workspace_dir),
            review_command="hol-guard approvals approve req-123",
            approval_url="http://127.0.0.1:4455/approvals/req-123",
            action_envelope_json=action_envelope_json,
            decision_v2_json=decision_v2_json,
        )

        store.add_approval_request(request, "2026-04-11T00:00:00+00:00")
        pending = store.list_approval_requests()
        store.resolve_approval_request(
            "req-123",
            resolution_action="allow",
            resolution_scope="artifact",
            reason="reviewed",
            resolved_at="2026-04-11T00:01:00+00:00",
        )
        resolved = store.get_approval_request("req-123")

        assert pending[0]["status"] == "pending"
        assert pending[0]["approval_url"] == "http://127.0.0.1:4455/approvals/req-123"
        assert pending[0]["workspace"] == str(workspace_dir)
        assert pending[0]["action_envelope_json"] == action_envelope_json
        pending_decision = pending[0]["decision_v2_json"]
        assert isinstance(pending_decision, dict)
        assert pending_decision["action"] == "ask"
        assert pending_decision["reason"] == "require-reapproval"
        assert pending_decision["user_title"] == "Fresh approval required"
        assert pending_decision["signals"] == []
        assert pending_decision["approval_scopes"] == ["artifact"]
        assert resolved is not None
        assert resolved["status"] == "resolved"
        assert resolved["resolution_action"] == "allow"
        assert resolved["resolution_scope"] == "artifact"
        assert resolved["action_envelope_json"] == action_envelope_json
        assert resolved["decision_v2_json"] == pending_decision

    def test_guard_store_runtime_snapshot_exposes_pending_request_payload_contract(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        request = GuardApprovalRequest(
            request_id="req-snapshot-contract",
            harness="codex",
            artifact_id="codex:project:workspace_skill",
            artifact_name="workspace_skill",
            artifact_hash="hash-snapshot-contract",
            policy_action="require-reapproval",
            recommended_scope="workspace",
            changed_fields=("args",),
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            workspace=str(tmp_path / "workspace"),
            review_command="hol-guard approvals approve req-snapshot-contract",
            approval_url="http://127.0.0.1:4455/approvals/req-snapshot-contract",
        )
        store.add_approval_request(request, "2026-04-11T00:00:00+00:00")
        store.upsert_runtime_state(
            session_id="session-snapshot-contract",
            daemon_host="127.0.0.1",
            daemon_port=4455,
            started_at="2026-04-11T00:00:00+00:00",
            last_heartbeat_at="2026-04-11T00:01:00+00:00",
        )

        snapshot = build_runtime_snapshot(
            store=store,
            approval_center_url="http://127.0.0.1:4455",
            now="2026-04-11T00:01:00+00:00",
        )
        queue_summary = snapshot["queue_summary"]
        items = snapshot["items"]

        assert snapshot["pending_count"] == 1
        assert snapshot["headline_state"] == "needs_decision"
        assert snapshot["headline_label"] == "Decision needed"
        assert "waiting for a decision" in snapshot["headline_detail"]
        assert "blocked" not in snapshot["headline_detail"].lower()
        assert isinstance(queue_summary, dict)
        assert queue_summary["next_request_id"] == "req-snapshot-contract"
        assert isinstance(items, list)
        assert items[0]["request_id"] == "req-snapshot-contract"
        assert items[0]["recommended_scope"] == "artifact"
        assert items[0]["review_command"] == "hol-guard approvals approve req-snapshot-contract"
        assert items[0]["approval_url"] == "http://127.0.0.1:4455/approvals/req-snapshot-contract"

    def test_guard_store_loads_old_approval_rows_without_action_envelope(self, tmp_path):
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(guard_home / "guard.db")
        try:
            connection.execute(
                """
                create table approval_requests (
                  request_id text primary key,
                  harness text not null,
                  artifact_id text not null,
                  artifact_name text not null,
                  artifact_type text not null,
                  artifact_hash text not null,
                  publisher text,
                  policy_action text not null,
                  recommended_scope text not null,
                  changed_fields_json text not null,
                  source_scope text not null,
                  config_path text not null,
                  workspace text,
                  launch_target text,
                  transport text,
                  risk_summary text,
                  risk_signals_json text not null default '[]',
                  artifact_label text,
                  source_label text,
                  trigger_summary text,
                  why_now text,
                  launch_summary text,
                  risk_headline text,
                  review_command text not null,
                  approval_url text not null,
                  status text not null,
                  resolution_action text,
                  resolution_scope text,
                  reason text,
                  created_at text not null,
                  resolved_at text
                )
                """
            )
            connection.execute(
                """
                insert into approval_requests (
                  request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher,
                  policy_action, recommended_scope, changed_fields_json, source_scope, config_path, workspace,
                  launch_target, transport, risk_summary, risk_signals_json, artifact_label, source_label,
                  trigger_summary, why_now, launch_summary, risk_headline, review_command, approval_url, status,
                  resolution_action, resolution_scope, reason, created_at, resolved_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "req-old",
                    "codex",
                    "codex:project:workspace_skill",
                    "workspace_skill",
                    "artifact",
                    "hash-old",
                    None,
                    "require-reapproval",
                    "artifact",
                    json.dumps(["args"]),
                    "project",
                    str(tmp_path / "workspace" / ".codex" / "config.toml"),
                    None,
                    None,
                    None,
                    None,
                    "[]",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    "hol-guard approvals approve req-old",
                    "http://127.0.0.1/pending",
                    "pending",
                    None,
                    None,
                    None,
                    "2026-04-11T00:00:00+00:00",
                    None,
                ),
            )
            connection.commit()
        finally:
            connection.close()

        store = GuardStore(guard_home)
        request = store.get_approval_request("req-old")

        assert request is not None
        assert request["request_id"] == "req-old"
        assert request["action_envelope_json"] is None
        assert request["decision_v2_json"]["action"] == "ask"
        assert "decision_contract_error" not in request

    def test_guard_store_ignores_malformed_action_and_decision_json(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        connection = sqlite3.connect(store.path)
        try:
            connection.execute(
                """
                insert into approval_requests (
                  request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher,
                  policy_action, recommended_scope, changed_fields_json, source_scope, config_path, workspace,
                  launch_target, transport, risk_summary, risk_signals_json, artifact_label, source_label,
                  trigger_summary, why_now, launch_summary, risk_headline, action_envelope_json, decision_v2_json,
                  review_command,
                  approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at
                )
                values (
                  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    "req-bad-envelope",
                    "codex",
                    "codex:project:workspace_skill",
                    "workspace_skill",
                    "artifact",
                    "hash-bad-envelope",
                    None,
                    "require-reapproval",
                    "artifact",
                    json.dumps(["args"]),
                    "project",
                    str(tmp_path / "workspace" / ".codex" / "config.toml"),
                    None,
                    None,
                    None,
                    None,
                    "[]",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    "{not-json",
                    "{also-not-json",
                    "hol-guard approvals approve req-bad-envelope",
                    "http://127.0.0.1/pending",
                    "pending",
                    None,
                    None,
                    None,
                    "2026-04-11T00:00:00+00:00",
                    None,
                ),
            )
            connection.commit()
        finally:
            connection.close()

        request = store.get_approval_request("req-bad-envelope")

        assert request is not None
        assert request["action_envelope_json"] is None
        assert request["decision_v2_json"]["action"] == "ask"
        assert request["decision_contract_error"] == "authoritative_decision_inconsistent"
