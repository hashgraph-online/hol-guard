"""Tests for the Gemini harness adapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.gemini import GeminiHarnessAdapter


def _ctx(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class TestGeminiAdapterIdentity:
    def test_harness_identifier_is_gemini(self) -> None:
        assert GeminiHarnessAdapter.harness == "gemini"

    def test_executable_is_gemini(self) -> None:
        assert GeminiHarnessAdapter.executable == "gemini"

    def test_approval_tier_is_approval_center(self) -> None:
        assert GeminiHarnessAdapter.approval_tier == "approval-center"


class TestGeminiPolicyPath:
    def test_policy_path_uses_workspace_when_provided(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        expected = ctx.workspace_dir / ".gemini" / "settings.json"
        assert GeminiHarnessAdapter().policy_path(ctx) == expected

    def test_policy_path_falls_back_to_home_without_workspace(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=False)
        expected = (tmp_path / "home") / ".gemini" / "settings.json"
        assert GeminiHarnessAdapter().policy_path(ctx) == expected


class TestGeminiDetectEmptyConfig:
    def test_empty_dir_returns_no_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = GeminiHarnessAdapter().detect(ctx)
        assert result.harness == "gemini"
        assert result.artifacts == ()
        assert result.config_paths == ()

    def test_empty_settings_json_yields_no_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(ctx.home_dir / ".gemini" / "settings.json", {})
        result = GeminiHarnessAdapter().detect(ctx)
        assert result.artifacts == ()


class TestGeminiMCPFromSettings:
    def test_mcp_server_in_settings_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(
            ctx.home_dir / ".gemini" / "settings.json",
            {"mcpServers": {"my-server": {"command": "node", "args": ["server.js"]}}},
        )
        result = GeminiHarnessAdapter().detect(ctx)
        ids = [a.artifact_id for a in result.artifacts]
        assert "gemini:global:mcp:my-server" in ids

    def test_mcp_artifact_has_correct_fields(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(
            ctx.home_dir / ".gemini" / "settings.json",
            {"mcpServers": {"tools": {"command": "npx", "args": ["-y", "tools-server"]}}},
        )
        result = GeminiHarnessAdapter().detect(ctx)
        art = result.artifacts[0]
        assert art.name == "tools"
        assert art.artifact_type == "mcp_server"
        assert art.command == "npx"
        assert art.args == ("-y", "tools-server")
        assert art.transport == "stdio"

    def test_mcp_server_with_url_gets_http_transport(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(
            ctx.home_dir / ".gemini" / "settings.json",
            {"mcpServers": {"remote": {"url": "http://localhost:8080/mcp"}}},
        )
        result = GeminiHarnessAdapter().detect(ctx)
        art = result.artifacts[0]
        assert art.transport == "http"
        assert art.url == "http://localhost:8080/mcp"

    def test_multiple_mcp_servers_all_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(
            ctx.home_dir / ".gemini" / "settings.json",
            {
                "mcpServers": {
                    "a": {"command": "node", "args": ["a.js"]},
                    "b": {"command": "node", "args": ["b.js"]},
                    "c": {"url": "http://localhost:9000/mcp"},
                }
            },
        )
        result = GeminiHarnessAdapter().detect(ctx)
        ids = {a.artifact_id for a in result.artifacts if a.artifact_type == "mcp_server"}
        assert ids == {"gemini:global:mcp:a", "gemini:global:mcp:b", "gemini:global:mcp:c"}

    def test_settings_config_path_is_recorded(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".gemini" / "settings.json"
        _write_json(config, {"mcpServers": {"s": {"command": "x"}}})
        result = GeminiHarnessAdapter().detect(ctx)
        assert str(config) in result.config_paths


class TestGeminiHookDetection:
    def test_pretooluse_hook_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(
            ctx.home_dir / ".gemini" / "settings.json",
            {
                "hooks": {
                    "PreToolUse": [
                        {"hooks": [{"type": "command", "command": "python hook.py"}]}
                    ]
                }
            },
        )
        result = GeminiHarnessAdapter().detect(ctx)
        hook_artifacts = [a for a in result.artifacts if a.artifact_type == "hook"]
        assert len(hook_artifacts) == 1
        assert hook_artifacts[0].artifact_id == "gemini:global:hook:pretooluse:0"

    def test_hook_command_extracted_from_nested_structure(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(
            ctx.home_dir / ".gemini" / "settings.json",
            {
                "hooks": {
                    "PreToolUse": [
                        {"hooks": [{"type": "command", "command": "guard-hook.sh"}]}
                    ]
                }
            },
        )
        result = GeminiHarnessAdapter().detect(ctx)
        hook = next(a for a in result.artifacts if a.artifact_type == "hook")
        assert hook.command == "guard-hook.sh"

    def test_direct_command_in_hook_entry_extracted(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(
            ctx.home_dir / ".gemini" / "settings.json",
            {"hooks": {"PostToolUse": [{"command": "post-hook.sh"}]}},
        )
        result = GeminiHarnessAdapter().detect(ctx)
        hook = next(a for a in result.artifacts if a.artifact_type == "hook")
        assert hook.command == "post-hook.sh"

    def test_multiple_hooks_create_indexed_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(
            ctx.home_dir / ".gemini" / "settings.json",
            {
                "hooks": {
                    "PreToolUse": [
                        {"command": "hook-a.sh"},
                        {"command": "hook-b.sh"},
                    ]
                }
            },
        )
        result = GeminiHarnessAdapter().detect(ctx)
        hook_ids = {a.artifact_id for a in result.artifacts if a.artifact_type == "hook"}
        assert "gemini:global:hook:pretooluse:0" in hook_ids
        assert "gemini:global:hook:pretooluse:1" in hook_ids

    def test_non_list_hook_value_skipped_gracefully(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(
            ctx.home_dir / ".gemini" / "settings.json",
            {"hooks": {"PreToolUse": "not-a-list"}},
        )
        result = GeminiHarnessAdapter().detect(ctx)
        hook_artifacts = [a for a in result.artifacts if a.artifact_type == "hook"]
        assert hook_artifacts == []


class TestGeminiExtensionDetection:
    def test_extension_manifest_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        manifest = ctx.home_dir / ".gemini" / "extensions" / "my-ext" / "gemini-extension.json"
        _write_json(manifest, {"name": "my-ext", "contextFileName": "GEMINI.md"})
        result = GeminiHarnessAdapter().detect(ctx)
        ext_artifacts = [a for a in result.artifacts if a.artifact_type == "extension"]
        assert len(ext_artifacts) == 1
        assert ext_artifacts[0].artifact_id == "gemini:global:my-ext"

    def test_extension_publisher_preserved(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        manifest = ctx.home_dir / ".gemini" / "extensions" / "vendor-ext" / "gemini-extension.json"
        _write_json(manifest, {"name": "vendor-ext", "publisher": "acme-corp"})
        result = GeminiHarnessAdapter().detect(ctx)
        ext = next(a for a in result.artifacts if a.artifact_type == "extension")
        assert ext.publisher == "acme-corp"

    def test_extension_uses_directory_name_as_fallback_name(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        manifest = ctx.home_dir / ".gemini" / "extensions" / "dir-name-ext" / "gemini-extension.json"
        _write_json(manifest, {"contextFileName": "GEMINI.md"})
        result = GeminiHarnessAdapter().detect(ctx)
        ext = next(a for a in result.artifacts if a.artifact_type == "extension")
        assert ext.name == "dir-name-ext"
        assert ext.artifact_id == "gemini:global:dir-name-ext"

    def test_extension_with_embedded_mcp_servers(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        manifest = ctx.home_dir / ".gemini" / "extensions" / "ext-with-mcp" / "gemini-extension.json"
        _write_json(
            manifest,
            {
                "name": "ext-with-mcp",
                "mcpServers": {
                    "embedded-server": {"command": "node", "args": ["server.js"]}
                },
            },
        )
        result = GeminiHarnessAdapter().detect(ctx)
        mcp_artifacts = [a for a in result.artifacts if a.artifact_type == "mcp_server"]
        assert len(mcp_artifacts) == 1
        assert mcp_artifacts[0].artifact_id == "gemini:global:ext-with-mcp:embedded-server"

    def test_extension_manifest_config_path_recorded(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        manifest = ctx.home_dir / ".gemini" / "extensions" / "some-ext" / "gemini-extension.json"
        _write_json(manifest, {"name": "some-ext"})
        result = GeminiHarnessAdapter().detect(ctx)
        assert str(manifest) in result.config_paths

    def test_malformed_extension_manifest_skipped(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        manifest = ctx.home_dir / ".gemini" / "extensions" / "broken" / "gemini-extension.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text("{ broken json }", encoding="utf-8")
        result = GeminiHarnessAdapter().detect(ctx)
        ext_artifacts = [a for a in result.artifacts if a.artifact_type == "extension"]
        assert ext_artifacts == []

    def test_multiple_extensions_all_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        for name in ("ext-a", "ext-b", "ext-c"):
            manifest = ctx.home_dir / ".gemini" / "extensions" / name / "gemini-extension.json"
            _write_json(manifest, {"name": name})
        result = GeminiHarnessAdapter().detect(ctx)
        ext_ids = {a.artifact_id for a in result.artifacts if a.artifact_type == "extension"}
        assert ext_ids == {"gemini:global:ext-a", "gemini:global:ext-b", "gemini:global:ext-c"}


class TestGeminiSkillDetection:
    def test_skill_md_at_root_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        skill = ctx.home_dir / ".gemini" / "skills" / "my-skill" / "SKILL.md"
        _write_text(skill, "---\nname: my-skill\ndescription: test\n---\n")
        result = GeminiHarnessAdapter().detect(ctx)
        skill_artifacts = [a for a in result.artifacts if a.artifact_type == "skill"]
        assert len(skill_artifacts) == 1
        assert "my-skill" in skill_artifacts[0].artifact_id

    def test_skill_artifact_type_is_skill(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        skill = ctx.home_dir / ".gemini" / "skills" / "guard-skill" / "SKILL.md"
        _write_text(skill, "content")
        result = GeminiHarnessAdapter().detect(ctx)
        skill_arts = [a for a in result.artifacts if a.artifact_type == "skill"]
        assert all(a.harness == "gemini" for a in skill_arts)

    def test_nested_skill_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        nested = ctx.home_dir / ".gemini" / "skills" / "category" / "sub-skill" / "SKILL.md"
        _write_text(nested, "content")
        result = GeminiHarnessAdapter().detect(ctx)
        skill_arts = [a for a in result.artifacts if a.artifact_type == "skill"]
        assert len(skill_arts) == 1
        assert "category/sub-skill" in skill_arts[0].artifact_id

    def test_multiple_skills_all_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        for skill_name in ("skill-a", "skill-b"):
            path = ctx.home_dir / ".gemini" / "skills" / skill_name / "SKILL.md"
            _write_text(path, "content")
        result = GeminiHarnessAdapter().detect(ctx)
        skill_arts = [a for a in result.artifacts if a.artifact_type == "skill"]
        assert len(skill_arts) == 2


class TestGeminiMultiScope:
    def test_global_and_project_configs_both_scanned(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        _write_json(
            ctx.home_dir / ".gemini" / "settings.json",
            {"mcpServers": {"global-srv": {"command": "x"}}},
        )
        _write_json(
            ctx.workspace_dir / ".gemini" / "settings.json",
            {"mcpServers": {"project-srv": {"command": "y"}}},
        )
        result = GeminiHarnessAdapter().detect(ctx)
        ids = {a.artifact_id for a in result.artifacts}
        assert "gemini:global:mcp:global-srv" in ids
        assert "gemini:project:mcp:project-srv" in ids

    def test_project_scope_assigned_to_workspace_config(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        _write_json(
            ctx.workspace_dir / ".gemini" / "settings.json",
            {"mcpServers": {"ws-srv": {"command": "x"}}},
        )
        result = GeminiHarnessAdapter().detect(ctx)
        art = next(a for a in result.artifacts if "ws-srv" in a.artifact_id)
        assert art.source_scope == "project"

    def test_no_workspace_means_only_home_scanned(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=False)
        _write_json(
            ctx.home_dir / ".gemini" / "settings.json",
            {"mcpServers": {"g": {"command": "x"}}},
        )
        result = GeminiHarnessAdapter().detect(ctx)
        assert all(a.source_scope == "global" for a in result.artifacts)


class TestGeminiHookCommandHelper:
    def test_direct_command_returned_as_is(self) -> None:
        entry = {"command": "my-hook.sh"}
        result = GeminiHarnessAdapter._hook_command(entry)
        assert result == "my-hook.sh"

    def test_nested_hook_command_extracted(self) -> None:
        entry = {"hooks": [{"type": "command", "command": "nested-hook.sh"}]}
        result = GeminiHarnessAdapter._hook_command(entry)
        assert result == "nested-hook.sh"

    def test_multiple_nested_commands_joined_with_newline(self) -> None:
        entry = {
            "hooks": [
                {"type": "command", "command": "hook-a.sh"},
                {"type": "command", "command": "hook-b.sh"},
            ]
        }
        result = GeminiHarnessAdapter._hook_command(entry)
        assert result == "hook-a.sh\nhook-b.sh"

    def test_no_command_returns_none(self) -> None:
        entry = {"type": "other", "data": "value"}
        result = GeminiHarnessAdapter._hook_command(entry)
        assert result is None

    def test_non_string_command_ignored(self) -> None:
        entry = {"command": 42}
        result = GeminiHarnessAdapter._hook_command(entry)
        assert result is None

    def test_empty_nested_hooks_list_returns_none(self) -> None:
        entry = {"hooks": []}
        result = GeminiHarnessAdapter._hook_command(entry)
        assert result is None

    def test_direct_and_nested_commands_both_collected(self) -> None:
        entry = {
            "command": "direct.sh",
            "hooks": [{"type": "command", "command": "nested.sh"}],
        }
        result = GeminiHarnessAdapter._hook_command(entry)
        assert result == "direct.sh\nnested.sh"


class TestGeminiAdapterContract:
    def test_adapter_has_setup_contract(self) -> None:
        contract = GeminiHarnessAdapter().setup_contract()
        assert contract.harness == "gemini"
        assert contract.display_name

    def test_adapter_has_connect_step(self) -> None:
        contract = GeminiHarnessAdapter().setup_contract()
        step_ids = {s.step_id for s in contract.setup_steps}
        assert "connect" in step_ids

    def test_installed_true_when_settings_json_present(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(ctx.home_dir / ".gemini" / "settings.json", {"theme": "dark"})
        result = GeminiHarnessAdapter().detect(ctx)
        assert result.installed is True

    def test_installed_false_when_no_config_and_no_cli(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = GeminiHarnessAdapter().detect(ctx)
        assert result.installed is False or result.installed is True


class TestGeminiDetectResiliency:
    def test_malformed_settings_json_skipped(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        settings = ctx.home_dir / ".gemini" / "settings.json"
        settings.parent.mkdir(parents=True, exist_ok=True)
        settings.write_text("not valid json {{{", encoding="utf-8")
        result = GeminiHarnessAdapter().detect(ctx)
        assert result.artifacts == ()

    def test_missing_extension_root_does_not_crash(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = GeminiHarnessAdapter().detect(ctx)
        assert isinstance(result.artifacts, tuple)

    def test_extension_mcp_non_dict_server_skipped(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        manifest = ctx.home_dir / ".gemini" / "extensions" / "bad-ext" / "gemini-extension.json"
        _write_json(manifest, {"name": "bad-ext", "mcpServers": {"srv": "not-a-dict"}})
        result = GeminiHarnessAdapter().detect(ctx)
        mcp_arts = [a for a in result.artifacts if a.artifact_type == "mcp_server"]
        assert mcp_arts == []

    def test_config_paths_deduplicated(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        settings = ctx.home_dir / ".gemini" / "settings.json"
        _write_json(settings, {"mcpServers": {"s": {"command": "x"}}})
        result = GeminiHarnessAdapter().detect(ctx)
        assert len(result.config_paths) == len(set(result.config_paths))
