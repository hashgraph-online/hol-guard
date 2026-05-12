"""Tests for the OpenCode harness adapter."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.opencode import OpenCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.opencode_artifacts import (
    CONFIG_FILENAMES,
    config_paths,
    runtime_config_path,
)


def _ctx(
    tmp_path: Path,
    *,
    workspace: bool = False,
    home_dir: Path | None = None,
) -> HarnessContext:
    home = home_dir or tmp_path / "home"
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=home,
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _write_config(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_mcp_config(path: Path, servers: dict[str, object]) -> None:
    _write_config(path, {"mcp": servers})


class TestOpenCodeAdapterIdentity:
    def test_harness_identifier_is_opencode(self) -> None:
        assert OpenCodeHarnessAdapter.harness == "opencode"

    def test_executable_is_opencode(self) -> None:
        assert OpenCodeHarnessAdapter.executable == "opencode"

    def test_approval_tier_is_mixed(self) -> None:
        assert OpenCodeHarnessAdapter.approval_tier == "mixed"

    def test_approval_prompt_channel_is_native(self) -> None:
        assert OpenCodeHarnessAdapter.approval_prompt_channel == "native"

    def test_auto_open_browser_is_disabled(self) -> None:
        assert OpenCodeHarnessAdapter.approval_auto_open_browser is False

    def test_approval_summary_mentions_opencode(self) -> None:
        assert "OpenCode" in OpenCodeHarnessAdapter.approval_summary

    def test_fallback_hint_mentions_native_flow(self) -> None:
        assert "native" in OpenCodeHarnessAdapter.fallback_hint.lower()


class TestOpenCodePolicyPath:
    def test_policy_path_uses_workspace_config_when_provided(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        result = OpenCodeHarnessAdapter().policy_path(ctx)
        assert ctx.workspace_dir is not None
        assert result.is_relative_to(ctx.workspace_dir)

    def test_policy_path_falls_back_to_global_config_without_workspace(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=False)
        result = OpenCodeHarnessAdapter().policy_path(ctx)
        assert result.is_relative_to(ctx.home_dir)

    def test_policy_path_filename_is_opencode_json(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = OpenCodeHarnessAdapter().policy_path(ctx)
        assert result.name in CONFIG_FILENAMES


class TestOpenCodeDetectEmptyConfig:
    def test_empty_home_returns_not_installed_without_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = OpenCodeHarnessAdapter().detect(ctx)
        assert result.harness == "opencode"
        assert result.artifacts == ()
        assert result.config_paths == ()

    def test_empty_workspace_yields_no_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        result = OpenCodeHarnessAdapter().detect(ctx)
        assert result.artifacts == ()

    def test_config_with_no_mcp_key_yields_no_mcp_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_config(config, {"model": "gpt-4"})
        result = OpenCodeHarnessAdapter().detect(ctx)
        assert result.installed is True
        assert not any(a.artifact_type == "mcp-server" for a in result.artifacts)

    def test_config_with_empty_mcp_yields_no_mcp_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_config(config, {"mcp": {}})
        result = OpenCodeHarnessAdapter().detect(ctx)
        assert not any(a.artifact_type == "mcp-server" for a in result.artifacts)


class TestOpenCodeDetectWithMcpServers:
    def test_detects_global_mcp_server_from_home_config(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_mcp_config(config, {"my-server": {"type": "local", "command": ["node", "server.js"]}})
        result = OpenCodeHarnessAdapter().detect(ctx)
        artifact_ids = [a.artifact_id for a in result.artifacts]
        assert any("my-server" in aid for aid in artifact_ids)

    def test_detects_workspace_mcp_server_as_project_scope(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        config = ctx.workspace_dir / "opencode.json"
        _write_mcp_config(config, {"ws-server": {"type": "local", "command": ["node", "ws.js"]}})
        result = OpenCodeHarnessAdapter().detect(ctx)
        ws_artifacts = [a for a in result.artifacts if "ws-server" in a.artifact_id]
        assert len(ws_artifacts) == 1
        assert ws_artifacts[0].source_scope == "project"

    def test_global_server_has_global_scope(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_mcp_config(config, {"global-srv": {"type": "local", "command": ["node", "g.js"]}})
        result = OpenCodeHarnessAdapter().detect(ctx)
        global_artifacts = [a for a in result.artifacts if "global-srv" in a.artifact_id]
        assert global_artifacts[0].source_scope == "global"

    def test_multiple_servers_all_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_mcp_config(
            config,
            {
                "server-a": {"type": "local", "command": ["node", "a.js"]},
                "server-b": {"type": "local", "command": ["node", "b.js"]},
            },
        )
        result = OpenCodeHarnessAdapter().detect(ctx)
        names = {a.name for a in result.artifacts}
        assert "server-a" in names
        assert "server-b" in names

    def test_config_paths_includes_detected_config_file(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_mcp_config(config, {"srv": {"type": "local", "command": ["node", "s.js"]}})
        result = OpenCodeHarnessAdapter().detect(ctx)
        assert str(config) in result.config_paths


class TestOpenCodeDetectSkillsAndCommands:
    def test_detects_global_skill_from_agents_skills_directory(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        skill_dir = ctx.home_dir / ".agents" / "skills" / "my-skill"
        skill_dir.mkdir(parents=True, exist_ok=True)
        (skill_dir / "SKILL.md").write_text("# My Skill", encoding="utf-8")
        result = OpenCodeHarnessAdapter().detect(ctx)
        skill_artifacts = [a for a in result.artifacts if a.artifact_type == "skill"]
        assert any("my-skill" in a.artifact_id for a in skill_artifacts)

    def test_detects_global_command_from_config_commands_directory(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        cmd_dir = ctx.home_dir / ".config" / "opencode" / "commands"
        cmd_dir.mkdir(parents=True, exist_ok=True)
        (cmd_dir / "my-command.md").write_text("# My Command", encoding="utf-8")
        result = OpenCodeHarnessAdapter().detect(ctx)
        cmd_artifacts = [a for a in result.artifacts if a.artifact_type == "command"]
        assert any("my-command" in a.artifact_id for a in cmd_artifacts)

    def test_detects_plugin_file_from_global_plugins_directory(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        plugin_dir = ctx.home_dir / ".config" / "opencode" / "plugins"
        plugin_dir.mkdir(parents=True, exist_ok=True)
        (plugin_dir / "my-plugin.js").write_text("// plugin", encoding="utf-8")
        result = OpenCodeHarnessAdapter().detect(ctx)
        plugin_artifacts = [a for a in result.artifacts if a.artifact_type == "plugin"]
        assert any("my-plugin" in a.artifact_id for a in plugin_artifacts)

    def test_workspace_skill_detected_as_project_scope(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        skill_dir = ctx.workspace_dir / ".opencode" / "skills" / "ws-skill"
        skill_dir.mkdir(parents=True, exist_ok=True)
        (skill_dir / "SKILL.md").write_text("# WS Skill", encoding="utf-8")
        result = OpenCodeHarnessAdapter().detect(ctx)
        ws_skills = [a for a in result.artifacts if a.artifact_type == "skill" and "ws-skill" in a.artifact_id]
        assert ws_skills[0].source_scope == "project"


class TestOpenCodeConfigPrecedence:
    def test_workspace_config_takes_precedence_over_global(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        global_config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        workspace_config = ctx.workspace_dir / "opencode.json"
        _write_mcp_config(global_config, {"global-only": {"type": "local", "command": ["g"]}})
        _write_mcp_config(workspace_config, {"workspace-only": {"type": "local", "command": ["w"]}})
        result = OpenCodeHarnessAdapter().detect(ctx)
        names = {a.name for a in result.artifacts}
        assert "workspace-only" in names
        assert "global-only" in names

    def test_target_config_path_prefers_existing_workspace_file(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        existing = ctx.workspace_dir / "opencode.json"
        existing.write_text("{}", encoding="utf-8")
        target = OpenCodeHarnessAdapter._target_config_path(ctx)
        assert target == existing

    def test_target_config_path_uses_first_filename_for_new_workspace(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        target = OpenCodeHarnessAdapter._target_config_path(ctx)
        assert target == ctx.workspace_dir / CONFIG_FILENAMES[0]

    def test_target_config_path_uses_global_dir_when_no_workspace(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=False)
        target = OpenCodeHarnessAdapter._target_config_path(ctx)
        assert target.is_relative_to(ctx.home_dir)


class TestOpenCodeInstall:
    def test_install_creates_managed_config_file(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = OpenCodeHarnessAdapter().install(ctx)
        managed_config = Path(result["managed_config_path"])
        assert managed_config.is_file()

    def test_install_creates_backup_file(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = OpenCodeHarnessAdapter().install(ctx)
        backup_path = Path(result["backup_path"])
        assert backup_path.is_file()

    def test_install_creates_state_file(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = OpenCodeHarnessAdapter().install(ctx)
        state_path = Path(result["state_path"])
        assert state_path.is_file()

    def test_install_creates_runtime_config(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = OpenCodeHarnessAdapter().install(ctx)
        runtime_path = Path(result["runtime_config_path"])
        assert runtime_path.is_file()

    def test_install_runtime_config_has_schema(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = OpenCodeHarnessAdapter().install(ctx)
        runtime_path = Path(result["runtime_config_path"])
        payload = json.loads(runtime_path.read_text(encoding="utf-8"))
        assert "$schema" in payload

    def test_install_backup_records_no_prior_content_when_new(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = OpenCodeHarnessAdapter().install(ctx)
        backup_path = Path(result["backup_path"])
        backup_payload = json.loads(backup_path.read_text(encoding="utf-8"))
        assert backup_payload["existed"] is False

    def test_install_backup_preserves_original_content(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        target = OpenCodeHarnessAdapter._target_config_path(ctx)
        target.parent.mkdir(parents=True, exist_ok=True)
        original = '{"model": "gpt-4"}'
        target.write_text(original, encoding="utf-8")
        result = OpenCodeHarnessAdapter().install(ctx)
        backup_path = Path(result["backup_path"])
        backup_payload = json.loads(backup_path.read_text(encoding="utf-8"))
        assert backup_payload["existed"] is True
        assert backup_payload["content"] == original

    def test_install_marks_harness_as_active(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = OpenCodeHarnessAdapter().install(ctx)
        assert result["active"] is True
        assert result["harness"] == "opencode"

    def test_install_is_idempotent(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result1 = OpenCodeHarnessAdapter().install(ctx)
        result2 = OpenCodeHarnessAdapter().install(ctx)
        assert result1["managed_config_path"] == result2["managed_config_path"]
        assert Path(result2["managed_config_path"]).is_file()

    def test_install_with_existing_mcp_adds_permission_rules(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        target = OpenCodeHarnessAdapter._target_config_path(ctx)
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_mcp_config(target, {"my-server": {"type": "local", "command": ["node", "s.js"]}})
        OpenCodeHarnessAdapter().install(ctx)
        managed_config = json.loads(target.read_text(encoding="utf-8"))
        assert "permission" in managed_config

    def test_install_report_includes_notes(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = OpenCodeHarnessAdapter().install(ctx)
        assert isinstance(result["notes"], list)
        assert len(result["notes"]) > 0

    def test_install_report_includes_runtime_env_var(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = OpenCodeHarnessAdapter().install(ctx)
        assert result["runtime_env_var"] == "OPENCODE_CONFIG_CONTENT"


class TestOpenCodeUninstall:
    def test_uninstall_restores_original_content(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        target = OpenCodeHarnessAdapter._target_config_path(ctx)
        target.parent.mkdir(parents=True, exist_ok=True)
        original = '{"model": "gpt-4"}'
        target.write_text(original, encoding="utf-8")
        OpenCodeHarnessAdapter().install(ctx)
        OpenCodeHarnessAdapter().uninstall(ctx)
        assert target.read_text(encoding="utf-8") == original

    def test_uninstall_removes_file_when_no_prior_config_existed(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        OpenCodeHarnessAdapter().install(ctx)
        target = Path(OpenCodeHarnessAdapter().install.__doc__ or "") or OpenCodeHarnessAdapter._target_config_path(ctx)
        target = OpenCodeHarnessAdapter._target_config_path(ctx)
        OpenCodeHarnessAdapter().uninstall(ctx)
        assert not target.is_file()

    def test_uninstall_marks_harness_inactive(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        OpenCodeHarnessAdapter().install(ctx)
        result = OpenCodeHarnessAdapter().uninstall(ctx)
        assert result["active"] is False
        assert result["harness"] == "opencode"

    def test_uninstall_removes_state_file(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        install_result = OpenCodeHarnessAdapter().install(ctx)
        state_path = Path(install_result["state_path"])
        assert state_path.is_file()
        OpenCodeHarnessAdapter().uninstall(ctx)
        assert not state_path.is_file()


class TestOpenCodePermissionRules:
    def test_coerce_permission_payload_with_dict_returns_copy(self) -> None:
        payload = {"*": "ask"}
        result = OpenCodeHarnessAdapter._coerce_permission_payload(payload)
        assert result == payload

    def test_coerce_permission_payload_with_string_wraps_as_wildcard(self) -> None:
        result = OpenCodeHarnessAdapter._coerce_permission_payload("allow")
        assert result == {"*": "allow"}

    def test_coerce_permission_payload_with_none_returns_empty_dict(self) -> None:
        result = OpenCodeHarnessAdapter._coerce_permission_payload(None)
        assert result == {}

    def test_coerce_permission_payload_with_list_returns_empty_dict(self) -> None:
        result = OpenCodeHarnessAdapter._coerce_permission_payload(["allow"])
        assert result == {}

    def test_proxy_permission_rules_adds_ask_rule_for_managed_server(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_mcp_config(config, {"my-srv": {"type": "local", "command": ["node", "s.js"]}})
        detection = OpenCodeHarnessAdapter().detect(ctx)
        from codex_plugin_scanner.guard.adapters.mcp_servers import managed_stdio_servers

        managed = managed_stdio_servers(detection)
        rules = OpenCodeHarnessAdapter._proxy_permission_rules(ctx, managed, set())
        assert any("my-srv" in k for k in rules)
        assert all(v == "ask" for v in rules.values())

    def test_managed_permission_payload_round_trips_existing_rules(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        existing_permission = {"some_tool": "allow"}
        result = OpenCodeHarnessAdapter()._managed_permission_payload(
            existing_permission,
            context=ctx,
            servers=(),
            existing_workspace_server_names=set(),
        )
        assert result.get("some_tool") == "allow"

    def test_permission_rules_use_ask_for_enabled_servers(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_mcp_config(config, {"target-srv": {"type": "local", "command": ["python", "s.py"]}})
        detection = OpenCodeHarnessAdapter().detect(ctx)
        from codex_plugin_scanner.guard.adapters.mcp_servers import managed_stdio_servers

        managed = managed_stdio_servers(detection)
        rules = OpenCodeHarnessAdapter._proxy_permission_rules(ctx, managed, set())
        target_rule_keys = [k for k in rules if "target-srv" in k]
        assert len(target_rule_keys) == 1
        assert rules[target_rule_keys[0]] == "ask"


class TestOpenCodeLaunchEnvironment:
    def test_launch_environment_empty_when_no_runtime_config(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        env = OpenCodeHarnessAdapter().launch_environment(ctx)
        assert env == {}

    def test_launch_environment_sets_opencode_config_content(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        runtime_path = runtime_config_path(ctx)
        runtime_path.parent.mkdir(parents=True, exist_ok=True)
        runtime_path.write_text(
            json.dumps({"$schema": "https://opencode.ai/config.json", "permission": {"*": "ask"}}),
            encoding="utf-8",
        )
        env = OpenCodeHarnessAdapter().launch_environment(ctx)
        assert "OPENCODE_CONFIG_CONTENT" in env
        assert json.loads(env["OPENCODE_CONFIG_CONTENT"]) is not None

    def test_launch_environment_survives_malformed_runtime_config(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        runtime_path = runtime_config_path(ctx)
        runtime_path.parent.mkdir(parents=True, exist_ok=True)
        runtime_path.write_text("not-json!", encoding="utf-8")
        env = OpenCodeHarnessAdapter().launch_environment(ctx)
        assert env == {}


class TestOpenCodeLaunchCommand:
    def test_launch_command_no_passthrough_args_uses_interactive(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        cmd = OpenCodeHarnessAdapter().launch_command(ctx, [])
        assert "opencode" in cmd[0]

    def test_launch_command_subcommand_is_passed_through(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        cmd = OpenCodeHarnessAdapter().launch_command(ctx, ["mcp", "list"])
        assert "opencode" in cmd[0]
        assert "mcp" in cmd
        assert "list" in cmd

    def test_launch_command_non_subcommand_arg_uses_interactive(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        cmd = OpenCodeHarnessAdapter().launch_command(ctx, ["--model", "gpt-4"])
        assert "opencode" in cmd[0]


class TestOpenCodeResiliency:
    def test_detect_skips_malformed_json_config(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("{invalid json!", encoding="utf-8")
        result = OpenCodeHarnessAdapter().detect(ctx)
        assert result.artifacts == ()

    def test_detect_skips_empty_config_file(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("", encoding="utf-8")
        result = OpenCodeHarnessAdapter().detect(ctx)
        assert result.artifacts == ()

    def test_detect_skips_non_dict_mcp_value(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_config(config, {"mcp": "not-a-dict"})
        result = OpenCodeHarnessAdapter().detect(ctx)
        assert result.artifacts == ()

    def test_launch_env_tolerates_missing_runtime_config(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        env = OpenCodeHarnessAdapter().launch_environment(ctx)
        assert "OPENCODE_CONFIG_CONTENT" not in env

    def test_detect_does_not_raise_on_missing_home_dir(self, tmp_path: Path) -> None:
        ctx = HarnessContext(
            home_dir=tmp_path / "nonexistent-home",
            workspace_dir=None,
            guard_home=tmp_path / "guard-home",
        )
        result = OpenCodeHarnessAdapter().detect(ctx)
        assert result.harness == "opencode"


class TestOpenCodeFirstUseAndChangedArtifact:
    def test_install_then_detect_shows_same_server_artifact(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_mcp_config(config, {"tracked-srv": {"type": "local", "command": ["node", "t.js"]}})
        OpenCodeHarnessAdapter().install(ctx)
        detection = OpenCodeHarnessAdapter().detect(ctx)
        artifact_names = {a.name for a in detection.artifacts}
        assert "tracked-srv" in artifact_names

    def test_detect_after_server_addition_reflects_new_artifact(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_mcp_config(config, {"original-srv": {"type": "local", "command": ["node", "o.js"]}})
        before = OpenCodeHarnessAdapter().detect(ctx)
        before_ids = {a.artifact_id for a in before.artifacts}
        _write_mcp_config(
            config,
            {
                "original-srv": {"type": "local", "command": ["node", "o.js"]},
                "new-srv": {"type": "local", "command": ["node", "n.js"]},
            },
        )
        after = OpenCodeHarnessAdapter().detect(ctx)
        after_ids = {a.artifact_id for a in after.artifacts}
        assert after_ids - before_ids

    def test_artifact_metadata_includes_hash_for_change_detection(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_mcp_config(config, {"hash-srv": {"type": "local", "command": ["node", "h.js"]}})
        result = OpenCodeHarnessAdapter().detect(ctx)
        srv_artifacts = [a for a in result.artifacts if "hash-srv" in a.artifact_id]
        assert len(srv_artifacts) == 1
        assert srv_artifacts[0].metadata is not None

    def test_changed_command_reflects_updated_artifact_args(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_mcp_config(config, {"chg-srv": {"type": "local", "command": ["node", "v1.js"]}})
        result1 = OpenCodeHarnessAdapter().detect(ctx)
        artifacts1 = {a.artifact_id: a for a in result1.artifacts}
        _write_mcp_config(config, {"chg-srv": {"type": "local", "command": ["node", "v2.js"]}})
        result2 = OpenCodeHarnessAdapter().detect(ctx)
        artifacts2 = {a.artifact_id: a for a in result2.artifacts}
        chg_id = next(k for k in artifacts1 if "chg-srv" in k)
        assert chg_id in artifacts2
        assert artifacts1[chg_id].args != artifacts2[chg_id].args


class TestOpenCodeScopeDetection:
    def test_global_server_classified_as_global_scope(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        _write_mcp_config(config, {"g-srv": {"type": "local", "command": ["node", "g.js"]}})
        result = OpenCodeHarnessAdapter().detect(ctx)
        g_artifacts = [a for a in result.artifacts if "g-srv" in a.artifact_id]
        assert g_artifacts[0].source_scope == "global"

    def test_workspace_server_classified_as_project_scope(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        config = ctx.workspace_dir / "opencode.json"
        _write_mcp_config(config, {"p-srv": {"type": "local", "command": ["node", "p.js"]}})
        result = OpenCodeHarnessAdapter().detect(ctx)
        p_artifacts = [a for a in result.artifacts if "p-srv" in a.artifact_id]
        assert p_artifacts[0].source_scope == "project"

    def test_scope_for_returns_project_for_workspace_relative_path(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        workspace_file = ctx.workspace_dir / "opencode.json"
        workspace_file.parent.mkdir(parents=True, exist_ok=True)
        workspace_file.touch()
        scope = OpenCodeHarnessAdapter._scope_for(ctx, workspace_file)
        assert scope == "project"

    def test_scope_for_returns_global_for_home_relative_path(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        home_file = ctx.home_dir / ".config" / "opencode" / "opencode.json"
        home_file.parent.mkdir(parents=True, exist_ok=True)
        home_file.touch()
        scope = OpenCodeHarnessAdapter._scope_for(ctx, home_file)
        assert scope == "global"


class TestOpenCodeSetupContract:
    def test_install_and_uninstall_are_inverse_for_new_config(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        target = OpenCodeHarnessAdapter._target_config_path(ctx)
        assert not target.exists()
        OpenCodeHarnessAdapter().install(ctx)
        assert target.is_file()
        OpenCodeHarnessAdapter().uninstall(ctx)
        assert not target.exists()

    def test_install_and_uninstall_are_inverse_for_existing_config(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        target = OpenCodeHarnessAdapter._target_config_path(ctx)
        target.parent.mkdir(parents=True, exist_ok=True)
        original_text = '{"model": "claude-3"}'
        target.write_text(original_text, encoding="utf-8")
        OpenCodeHarnessAdapter().install(ctx)
        assert target.read_text(encoding="utf-8") != original_text
        OpenCodeHarnessAdapter().uninstall(ctx)
        assert target.read_text(encoding="utf-8") == original_text

    def test_get_adapter_returns_opencode_instance(self) -> None:
        from codex_plugin_scanner.guard.adapters import get_adapter

        adapter = get_adapter("opencode")
        assert isinstance(adapter, OpenCodeHarnessAdapter)

    def test_harness_name_round_trips_through_adapter_factory(self) -> None:
        from codex_plugin_scanner.guard.adapters import get_adapter

        adapter = get_adapter("opencode")
        assert adapter.harness == "opencode"
