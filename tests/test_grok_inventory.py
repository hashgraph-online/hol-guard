"""Tests for the Grok Build CLI harness adapter."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter
from codex_plugin_scanner.guard.adapters.grok_hooks import (
    _dedupe_grok_block_reason,
    grok_hook_response_from_guard,
)
from codex_plugin_scanner.guard.inventory_contract import _agent_type, inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import HarnessDetection
from codex_plugin_scanner.guard.runtime.actions import normalize_grok_hook_payload

from .grok_test_support import _ctx, _fixture


class TestGrokDetectExtended:
    def test_detects_mcp_servers_from_config(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".grok" / "config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            """
[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
""".strip()
            + "\n",
            encoding="utf-8",
        )
        result = GrokHarnessAdapter().detect(ctx)
        mcp = [artifact for artifact in result.artifacts if artifact.artifact_type == "mcp_server"]
        assert any(artifact.name == "github" for artifact in mcp)

    def test_mcp_env_keys_and_headers_in_metadata(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".grok" / "config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            """
[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]

[mcp_servers.github.env]
GITHUB_TOKEN = "redacted"

[mcp_servers.remote]
url = "https://mcp.example.com/mcp"

[mcp_servers.remote.headers]
Authorization = "Bearer redacted"
""".strip()
            + "\n",
            encoding="utf-8",
        )
        result = GrokHarnessAdapter().detect(ctx)
        github = next(artifact for artifact in result.artifacts if artifact.name == "github")
        remote = next(artifact for artifact in result.artifacts if artifact.name == "remote")
        assert github.metadata["env_keys"] == ["GITHUB_TOKEN"]
        assert remote.metadata["headers_keys"] == ["Authorization"]
        assert github.metadata["versionInfo"]["versionLabel"] == "github"
        assert remote.metadata["versionInfo"]["versionLabel"] == "remote"

    def test_mcp_env_change_changes_artifact_hash(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.consumer import artifact_hash

        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".grok" / "config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            """
[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
""".strip()
            + "\n",
            encoding="utf-8",
        )
        adapter = GrokHarnessAdapter()
        baseline = next(artifact for artifact in adapter.detect(ctx).artifacts if artifact.name == "github")
        config.write_text(
            """
[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]

[mcp_servers.github.env]
GITHUB_TOKEN = "redacted"
""".strip()
            + "\n",
            encoding="utf-8",
        )
        changed = next(artifact for artifact in adapter.detect(ctx).artifacts if artifact.name == "github")
        assert artifact_hash(baseline) != artifact_hash(changed)
        assert changed.metadata["env_keys"] == ["GITHUB_TOKEN"]

    def test_mcp_headers_change_changes_artifact_hash(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.consumer import artifact_hash

        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".grok" / "config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            """
[mcp_servers.remote]
url = "https://mcp.example.com/mcp"
""".strip()
            + "\n",
            encoding="utf-8",
        )
        adapter = GrokHarnessAdapter()
        baseline = next(artifact for artifact in adapter.detect(ctx).artifacts if artifact.name == "remote")
        config.write_text(
            """
[mcp_servers.remote]
url = "https://mcp.example.com/mcp"

[mcp_servers.remote.headers]
Authorization = "Bearer redacted"
""".strip()
            + "\n",
            encoding="utf-8",
        )
        changed = next(artifact for artifact in adapter.detect(ctx).artifacts if artifact.name == "remote")
        assert artifact_hash(baseline) != artifact_hash(changed)
        assert changed.metadata["headers_keys"] == ["Authorization"]
        assert baseline.metadata["versionInfo"]["contentHash"] != changed.metadata["versionInfo"]["contentHash"]

    def test_mcp_credential_env_emits_secret_risk_signals(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.risk import artifact_risk_signals_typed

        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".grok" / "config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            """
[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]

[mcp_servers.github.env]
GITHUB_TOKEN = "redacted"
""".strip()
            + "\n",
            encoding="utf-8",
        )
        artifact = next(
            artifact for artifact in GrokHarnessAdapter().detect(ctx).artifacts if artifact.name == "github"
        )
        signal_ids = {signal.signal_id for signal in artifact_risk_signals_typed(artifact)}
        assert "secret:env-keys" in signal_ids
        assert "secret:env-semantic" in signal_ids

    def test_detects_degraded_always_approve_signal(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".grok" / "config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text('sandbox = "off"\n', encoding="utf-8")
        result = GrokHarnessAdapter().detect(ctx)
        assert any("degraded" in warning.lower() or "sandbox" in warning.lower() for warning in result.warnings)

    def test_install_preserves_user_config(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        user_config = ctx.home_dir / ".grok" / "config.toml"
        user_config.parent.mkdir(parents=True, exist_ok=True)
        user_config.write_text("[ui]\nsimple_mode = true\n", encoding="utf-8")
        GrokHarnessAdapter().install(ctx)
        assert user_config.read_text(encoding="utf-8") == "[ui]\nsimple_mode = true\n"


class TestGrokInventoryAndResponses:
    def test_inventory_agent_type_is_grok(self) -> None:
        assert _agent_type("grok") == "grok"

    def test_inventory_snapshot_serializes_grok_harness(self, tmp_path: Path) -> None:
        detection = HarnessDetection(
            harness="grok",
            installed=True,
            command_available=True,
            config_paths=(str(tmp_path / ".grok" / "config.toml"),),
            artifacts=(),
            warnings=(),
        )
        snapshot = inventory_snapshot_from_detection(detection, home_dir=tmp_path, generated_at="2026-06-12T00:00:00Z")
        assert snapshot.agent_type == "grok"

    def test_dedupe_block_reason_removes_repeated_approval_copy(self) -> None:
        reason = (
            "Blocked. Open HOL Guard to approve or keep this blocked: http://127.0.0.1:8080/x. "
            "After you choose, retry the same Grok action. "
            "Open HOL Guard to approve or keep this blocked: http://127.0.0.1:8080/x. "
            "After you choose, retry the same Grok action."
        )
        deduped = _dedupe_grok_block_reason(reason)
        assert deduped.count("Open HOL Guard to approve or keep this blocked:") == 1

    def test_deny_response_uses_plain_language_not_raw_json(self) -> None:
        payload = grok_hook_response_from_guard(policy_action="block", reason="Grok tried to read a credential file.")
        assert payload["decision"] == "deny"
        assert "{" not in str(payload["reason"])

    def test_observe_events_never_deny(self) -> None:
        payload = grok_hook_response_from_guard(
            policy_action="block",
            reason="Blocked by HOL Guard.",
            event_name="SubagentStart",
        )
        assert payload == {}
        assert "allow" not in json.dumps(payload)
        session = grok_hook_response_from_guard(
            policy_action="allow",
            reason="",
            event_name="SessionStart",
        )
        assert session == {}

    def test_subagent_start_with_tool_name_is_not_prompt(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        envelope = normalize_grok_hook_payload(
            {
                "hookEventName": "subagent_start",
                "sessionId": "session-redacted-015",
                "cwd": str(workspace),
                "workspaceRoot": str(workspace),
                "subagentType": "explore",
                "toolName": "spawn_subagent",
            },
            workspace=workspace,
            home_dir=tmp_path,
        )
        assert envelope.event_name == "SubagentStart"
        assert envelope.action_type == "config_change"

    def test_session_start_with_read_tool_is_not_file_read(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        envelope = normalize_grok_hook_payload(
            {
                "hookEventName": "session_start",
                "sessionId": "session-redacted-016",
                "cwd": str(workspace),
                "workspaceRoot": str(workspace),
                "toolName": "read_file",
                "toolInput": {"target_file": str(tmp_path / ".env")},
            },
            workspace=workspace,
            home_dir=tmp_path,
        )
        assert envelope.event_name == "SessionStart"
        assert envelope.action_type == "config_change"

    def test_spawn_subagent_envelope_is_prompt(self, tmp_path: Path) -> None:
        envelope = normalize_grok_hook_payload(
            _fixture("pretooluse_spawn_subagent.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.action_type == "prompt"
        assert envelope.tool_name == "Task"

    def test_secret_spawn_prompt_keeps_secret_marker(self, tmp_path: Path) -> None:
        envelope = normalize_grok_hook_payload(
            _fixture("pretooluse_spawn_subagent_secret.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.action_type == "prompt"
        assert envelope.prompt_text is not None
        assert ".env" in envelope.prompt_text

    def test_grep_pipe_pattern_is_not_a_shell_pipeline(self, tmp_path: Path) -> None:
        envelope = normalize_grok_hook_payload(
            _fixture("pretooluse_grep_pipe_pattern.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.action_type == "file_read"
        assert envelope.command is not None
        assert "prepare_grok_hook_payload" in envelope.command

    def test_list_dir_maps_to_file_read_of_target(self, tmp_path: Path) -> None:
        envelope = normalize_grok_hook_payload(
            _fixture("pretooluse_list_dir.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.action_type == "file_read"
        assert any(".ssh" in path for path in envelope.target_paths)

    def test_qualified_mcp_envelope_is_mcp_tool(self, tmp_path: Path) -> None:
        envelope = normalize_grok_hook_payload(
            _fixture("pretooluse_mcp_qualified.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.action_type == "mcp_tool"
        assert envelope.mcp_server == "filesystem"
        assert envelope.mcp_tool == "write_file"

    def test_detects_workflow_and_agent_surfaces(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        grok_root = ctx.home_dir / ".grok"
        (grok_root / "workflows").mkdir(parents=True)
        (grok_root / "agents").mkdir(parents=True)
        (grok_root / "sandbox.toml").write_text('[profiles.project]\nextends = "workspace"\n', encoding="utf-8")
        result = GrokHarnessAdapter().detect(ctx)
        assert any(path.endswith(".grok/workflows") for path in result.config_paths)
        assert any(path.endswith(".grok/agents") for path in result.config_paths)
        assert any(path.endswith(".grok/sandbox.toml") for path in result.config_paths)


class TestGrokFixtureHygiene:
    _FORBIDDEN_PATTERNS = (
        "XAI_API_KEY",
        "/" + "Users" + "/",
        "/" + "home" + "/",
        "sk-",
        "g0_",
    )

    def test_grok_fixtures_do_not_contain_secrets_or_local_paths(self) -> None:
        fixture_dir = Path(__file__).parent / "fixtures" / "grok"
        for fixture_path in sorted(fixture_dir.glob("*.json")):
            contents = fixture_path.read_text(encoding="utf-8")
            for pattern in self._FORBIDDEN_PATTERNS:
                assert pattern not in contents, f"{fixture_path.name} contains forbidden pattern {pattern!r}"
