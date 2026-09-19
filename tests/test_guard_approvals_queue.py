"""Runtime risk, action labels and changed-artifact queueing."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.approvals import queue_blocked_approvals
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import artifact_hash, evaluate_detection
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_approvals_support import (
    _disable_real_desktop_notification_setup as _disable_real_desktop_notification_setup,
)


class TestGuardApprovals:
    def test_guard_queue_prefers_runtime_risk_metadata_from_evaluation(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        artifact = GuardArtifact(
            artifact_id="codex:runtime:project:danger_lab:dangerous_delete",
            name="danger_lab:dangerous_delete",
            harness="codex",
            artifact_type="tool_call",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="dangerous_delete",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        queued = queue_blocked_approvals(
            detection=detection,
            evaluation={
                "artifacts": [
                    {
                        "artifact_id": artifact.artifact_id,
                        "artifact_name": artifact.name,
                        "artifact_hash": "hash-runtime",
                        "artifact_type": artifact.artifact_type,
                        "source_scope": artifact.source_scope,
                        "config_path": artifact.config_path,
                        "changed_fields": ["runtime_tool_call"],
                        "policy_action": "require-reapproval",
                        "launch_target": "dangerous_delete .env",
                        "risk_summary": "Call arguments mention sensitive local files or secrets.",
                        "risk_signals": ["call arguments mention sensitive local files or secrets"],
                    }
                ]
            },
            store=store,
            approval_center_url="http://127.0.0.1:4455",
            now="2026-04-17T00:00:00+00:00",
        )

        assert queued[0]["risk_summary"] == "Call arguments mention sensitive local files or secrets."
        assert queued[0]["risk_signals"] == ["call arguments mention sensitive local files or secrets"]
        assert queued[0]["launch_summary"] == "Launches with `dangerous_delete .env`."

    @pytest.mark.parametrize(
        ("artifact_name", "action_envelope_json", "expected"),
        [
            (
                "Bash",
                {
                    "action_type": "shell_command",
                    "tool_name": "Bash",
                    "raw_command_text": "bash",
                    "command": "pnpm install @hashgraphonline/standards-sdk",
                },
                "pnpm install @hashgraphonline/standards-sdk",
            ),
            (
                "Read",
                {
                    "action_type": "file_read",
                    "tool_name": "Read",
                    "target_paths": ["~/workspace/.env.local"],
                },
                "Read ~/workspace/.env.local",
            ),
            (
                "file_read_request",
                {
                    "action_type": "file_read_request",
                    "tool_name": "file_read_request",
                    "target_path": "~/workspace/.npmrc",
                },
                "Read ~/workspace/.npmrc",
            ),
            (
                "mcp_tool",
                {
                    "action_type": "mcp_tool",
                    "tool_name": "mcp_tool",
                    "mcp_server": "linear",
                    "mcp_tool": "create_issue",
                },
                "linear.create_issue",
            ),
            (
                "package_request",
                {
                    "action_type": "package_script",
                    "package_manager": "pnpm",
                    "package_name": "tsx",
                    "package_targets": ["tsx@4.20.3"],
                },
                "pnpm install tsx@4.20.3",
            ),
        ],
    )
    def test_guard_queue_preserves_exact_action_label_after_redaction(
        self,
        tmp_path,
        artifact_name,
        action_envelope_json,
        expected,
    ):
        store = GuardStore(tmp_path / "guard-home")
        artifact = GuardArtifact(
            artifact_id=f"codex:runtime:project:{artifact_name}:review",
            name=artifact_name,
            harness="codex",
            artifact_type="tool_action_request",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            metadata={"raw_command_text": artifact_name},
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        queued = queue_blocked_approvals(
            detection=detection,
            evaluation={
                "artifacts": [
                    {
                        "artifact_id": artifact.artifact_id,
                        "artifact_name": artifact.name,
                        "artifact_hash": f"hash-{artifact_name}",
                        "artifact_type": artifact.artifact_type,
                        "source_scope": artifact.source_scope,
                        "config_path": artifact.config_path,
                        "changed_fields": ["runtime_tool_call"],
                        "policy_action": "require-reapproval",
                        "action_envelope_json": action_envelope_json,
                    }
                ]
            },
            store=store,
            approval_center_url="http://127.0.0.1:4455",
            now="2026-04-17T00:00:00+00:00",
            redaction_level="partial",
        )

        stored = store.get_approval_request(queued[0]["request_id"])

        assert queued[0]["raw_command_text"] == expected
        assert stored is not None
        assert stored["raw_command_text"] == expected
        assert stored["raw_command_text"] not in {"Bash", "Read", "mcp_tool", "package_request"}

    def test_guard_queue_blocked_approvals_creates_requests_for_changed_artifacts(self, tmp_path):
        guard_home = tmp_path / "guard-home"
        store = GuardStore(guard_home)
        baseline = GuardArtifact(
            artifact_id="codex:project:workspace_skill",
            name="workspace_skill",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="node",
            args=("server.js",),
            transport="stdio",
        )
        baseline_hash = artifact_hash(baseline)
        store.save_snapshot(
            "codex",
            baseline.artifact_id,
            {**baseline.to_dict(), "artifact_hash": baseline_hash},
            baseline_hash,
            "2026-04-10T00:00:00+00:00",
        )
        changed = GuardArtifact(
            artifact_id=baseline.artifact_id,
            name=baseline.name,
            harness=baseline.harness,
            artifact_type=baseline.artifact_type,
            source_scope=baseline.source_scope,
            config_path=baseline.config_path,
            command="node",
            args=("server.js", "--changed"),
            transport="stdio",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(baseline.config_path,),
            artifacts=(changed,),
        )
        config = GuardConfig(guard_home=guard_home, workspace=None)

        evaluation = evaluate_detection(detection, store, config, persist=True)
        approvals = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1:4455",
        )

        assert evaluation["blocked"] is True
        assert approvals[0]["artifact_id"] == "codex:project:workspace_skill"
        assert "args" in approvals[0]["changed_fields"]
