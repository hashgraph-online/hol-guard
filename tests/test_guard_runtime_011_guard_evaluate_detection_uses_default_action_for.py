"""Runtime regression tests: guard evaluate detection uses default action for."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardArtifact,
    GuardConfig,
    GuardStore,
    HarnessDetection,
    Path,
    artifact_hash,
    evaluate_detection,
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


class TestGuardRuntime:
    def test_guard_evaluate_detection_uses_default_action_for_first_seen_artifacts(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        config = GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=None,
            default_action="warn",
            changed_hash_action="require-reapproval",
        )
        artifact = GuardArtifact(
            artifact_id="codex:project:workspace-tools",
            name="workspace-tools",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="node",
            args=("workspace.js",),
            transport="stdio",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        evaluation = evaluate_detection(detection, store, config, default_action="allow", persist=False)

        assert evaluation["blocked"] is False
        assert evaluation["artifacts"][0]["changed_fields"] == ["first_seen"]
        assert evaluation["artifacts"][0]["policy_action"] == "allow"

    def test_guard_evaluate_detection_honors_runtime_review_default_action(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        config = GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=None,
        )
        artifact = GuardArtifact(
            artifact_id="codex:project:tool-output:review-default",
            name="Bash credential-looking output",
            harness="codex",
            artifact_type="tool_action_request",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            metadata={
                "guard_default_action": "review",
                "action_class": "credential exfiltration shell command",
            },
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        evaluation = evaluate_detection(detection, store, config, persist=False)

        assert evaluation["blocked"] is True
        assert evaluation["artifacts"][0]["policy_action"] == "review"

    def test_guard_run_keeps_prior_snapshot_when_reapproval_blocks(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        baseline = GuardArtifact(
            artifact_id="codex:project:workspace-tools",
            name="workspace-tools",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="node",
            args=("workspace.js",),
            transport="stdio",
        )
        changed = GuardArtifact(
            artifact_id=baseline.artifact_id,
            name=baseline.name,
            harness=baseline.harness,
            artifact_type=baseline.artifact_type,
            source_scope=baseline.source_scope,
            config_path=baseline.config_path,
            command="node",
            args=("workspace.js", "--changed"),
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
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(baseline.config_path,),
            artifacts=(changed,),
        )
        config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

        first = evaluate_detection(detection, store, config, default_action="allow", persist=True)
        stored_after_first = store.get_snapshot("codex", baseline.artifact_id)
        second = evaluate_detection(detection, store, config, default_action="allow", persist=True)

        assert first["blocked"] is True
        assert stored_after_first is not None
        assert stored_after_first["artifact_hash"] == baseline_hash
        assert second["blocked"] is True
        assert second["artifacts"][0]["changed"] is True

    def test_guard_diff_surfaces_removed_artifacts(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        removed = GuardArtifact(
            artifact_id="codex:global:global-tools",
            name="global-tools",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="global",
            config_path=str(tmp_path / "home" / ".codex" / "config.toml"),
            command="python",
            args=("-m", "http.server"),
            transport="stdio",
        )
        removed_hash = artifact_hash(removed)
        store.save_snapshot(
            "codex",
            removed.artifact_id,
            {**removed.to_dict(), "artifact_hash": removed_hash},
            removed_hash,
            "2026-04-10T00:00:00+00:00",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(),
            artifacts=(),
        )
        config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

        evaluation = evaluate_detection(detection, store, config, default_action="allow", persist=False)

        assert evaluation["blocked"] is True
        assert len(evaluation["artifacts"]) == 1
        artifact = evaluation["artifacts"][0]

        assert artifact["artifact_id"] == "codex:global:global-tools"
        assert artifact["artifact_name"] == "global-tools"
        assert artifact["changed"] is True
        assert artifact["changed_fields"] == ["removed"]
        assert artifact["policy_action"] == "require-reapproval"
        assert artifact["artifact_hash"] == removed_hash
        assert artifact["removed"] is True
        assert artifact["source_scope"] == "global"
        assert artifact["config_path"] == str(tmp_path / "home" / ".codex" / "config.toml")
        assert artifact["artifact_label"] == "MCP server"
        assert artifact["source_label"] == "global Codex config"
        assert "global-tools" in str(artifact["trigger_summary"])
        assert "disappeared" in str(artifact["why_now"]).lower()

    def test_guard_hook_records_receipt_from_stdin_event(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        event = {
            "event": "PreToolUse",
            "tool_name": "workspace-tools",
            "artifact_id": "claude-code:workspace-tools",
            "artifact_name": "workspace-tools",
            "policy_action": "allow",
            "changed_capabilities": ["tool_name", "arguments"],
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
        receipts = GuardStore(Path(home_dir)).list_receipts()

        assert rc == 0
        assert output["recorded"] is True
        assert output["artifact_id"] == "claude-code:workspace-tools"
        assert receipts[0]["artifact_id"] == "claude-code:workspace-tools"
        assert receipts[0]["user_override"] is None

    def test_guard_hook_records_mcp_usage_event(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc, _output = _run_guard_hook(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            harness="codex",
            event={
                "hook_event_name": "PostToolUse",
                "tool_name": "mcp__danger_lab__dangerous_delete",
                "tool_input": {"target": "fixture.txt"},
                "tool_call_id": "call-123",
                "session_id": "session-123",
                "policy_action": "allow",
            },
            capsys=capsys,
            monkeypatch=monkeypatch,
            as_json=True,
        )

        events = GuardStore(Path(home_dir)).list_guard_events_v1(uploaded=False)
        usage_events = [event for event in events if event["event_type"] == "harness.mcp.used"]
        payload = usage_events[0]["payload"]
        usage_payload = payload["payload"]

        assert rc == 0
        assert usage_payload["harness"] == "codex"
        assert usage_payload["eventName"] == "PostToolUse"
        assert usage_payload["mcpServer"] == "danger_lab"
        assert usage_payload["mcpTool"] == "dangerous_delete"
        assert usage_payload["status"] == "allowed"
        assert usage_payload["requestId"] == "call-123"
        assert "target" not in json.dumps(usage_payload)

    def test_guard_hook_records_blocked_mcp_usage_after_policy_decision(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc, _output = _run_guard_hook(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            harness="codex",
            event={
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__danger_lab__dangerous_delete",
                "tool_input": {"target": "fixture.txt"},
                "tool_call_id": "call-456",
                "policy_action": "require-reapproval",
            },
            capsys=capsys,
            monkeypatch=monkeypatch,
            as_json=True,
        )

        events = GuardStore(Path(home_dir)).list_guard_events_v1(uploaded=False)
        usage_events = [event for event in events if event["event_type"] == "harness.mcp.used"]
        payload = usage_events[0]["payload"]
        usage_payload = payload["payload"]

        assert rc == 1
        assert usage_payload["eventName"] == "PreToolUse"
        assert usage_payload["status"] == "blocked"

    def test_guard_hook_records_failed_mcp_usage_even_with_allow_policy(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc, _output = _run_guard_hook(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            harness="codex",
            event={
                "hook_event_name": "PostToolUseFailure",
                "tool_name": "mcp__danger_lab__dangerous_delete",
                "tool_input": {"target": "fixture.txt"},
                "tool_call_id": "call-789",
                "policy_action": "allow",
            },
            capsys=capsys,
            monkeypatch=monkeypatch,
            as_json=True,
        )

        events = GuardStore(Path(home_dir)).list_guard_events_v1(uploaded=False)
        usage_events = [event for event in events if event["event_type"] == "harness.mcp.used"]
        payload = usage_events[0]["payload"]
        usage_payload = payload["payload"]

        assert rc == 0
        assert usage_payload["eventName"] == "PostToolUseFailure"
        assert usage_payload["status"] == "failed"

    def test_guard_hook_records_skill_activation_event(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc, _output = _run_guard_hook(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            harness="claude-code",
            event={
                "hook_event_name": "UserPromptSubmit",
                "prompt": "Use the project skill.",
                "activated_skill": {
                    "id": "project-review",
                    "name": "Project Review",
                    "source": "workspace",
                    "path": str(workspace_dir / ".claude" / "skills" / "project-review" / "SKILL.md"),
                },
                "session_id": "session-456",
            },
            capsys=capsys,
            monkeypatch=monkeypatch,
            as_json=True,
        )

        events = GuardStore(Path(home_dir)).list_guard_events_v1(uploaded=False)
        usage_events = [event for event in events if event["event_type"] == "harness.skill.activated"]
        payload = usage_events[0]["payload"]
        usage_payload = payload["payload"]

        assert rc == 0
        assert usage_payload["harness"] == "claude-code"
        assert usage_payload["eventName"] == "UserPromptSubmit"
        assert usage_payload["skillName"] == "Project Review"
        assert usage_payload["skillId"] == "project-review"
        assert usage_payload["skillSource"] == "workspace"
        assert "skillPathHash" in usage_payload
        assert str(workspace_dir) not in json.dumps(usage_payload)

    def test_guard_hook_hashes_active_skill_path_activation(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc, _output = _run_guard_hook(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            harness="codex",
            event={
                "hook_event_name": "UserPromptSubmit",
                "prompt": "Use a project skill.",
                "active_skill_path": ".codex/skills/project-review/SKILL.md",
            },
            capsys=capsys,
            monkeypatch=monkeypatch,
            as_json=True,
        )

        events = GuardStore(Path(home_dir)).list_guard_events_v1(uploaded=False)
        usage_events = [event for event in events if event["event_type"] == "harness.skill.activated"]
        payload = usage_events[0]["payload"]
        usage_payload = payload["payload"]

        assert rc == 0
        assert str(usage_payload["skillId"]).startswith("path:")
        assert "skillPathHash" in usage_payload
        assert "SKILL.md" not in json.dumps(usage_payload)

    def test_guard_hook_ignores_tool_argument_skill_path(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc, _output = _run_guard_hook(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            harness="codex",
            event={
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {
                    "command": "echo hello",
                    "active_skill_path": ".codex/skills/project-review/SKILL.md",
                },
            },
            capsys=capsys,
            monkeypatch=monkeypatch,
            as_json=True,
        )

        events = GuardStore(Path(home_dir)).list_guard_events_v1(uploaded=False)
        usage_events = [event for event in events if event["event_type"] == "harness.skill.activated"]

        assert rc == 0
        assert usage_events == []
