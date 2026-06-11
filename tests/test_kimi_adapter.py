"""Tests for the Kimi Code CLI harness adapter."""

from __future__ import annotations

import json

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.kimi import KimiHarnessAdapter


def _ctx(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _write_toml(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


class TestKimiAdapterIdentity:
    def test_harness_identifier_is_kimi(self) -> None:
        assert KimiHarnessAdapter.harness == "kimi"

    def test_executable_is_kimi(self) -> None:
        assert KimiHarnessAdapter.executable == "kimi"

    def test_approval_tier_is_approval_center(self) -> None:
        assert KimiHarnessAdapter.approval_tier == "approval-center"


class TestKimiPolicyPath:
    def test_policy_path_uses_workspace_when_provided(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        expected = ctx.workspace_dir / ".kimi-code" / "config.toml"
        assert KimiHarnessAdapter().policy_path(ctx) == expected

    def test_policy_path_falls_back_to_home_without_workspace(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        expected = (tmp_path / "home") / ".kimi-code" / "config.toml"
        assert KimiHarnessAdapter().policy_path(ctx) == expected


class TestKimiDetectEmptyConfig:
    def test_empty_dir_returns_no_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = KimiHarnessAdapter().detect(ctx)
        assert result.harness == "kimi"
        assert result.artifacts == ()
        assert result.config_paths == ()

    def test_empty_config_toml_yields_no_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_toml(ctx.home_dir / ".kimi-code" / "config.toml", "")
        result = KimiHarnessAdapter().detect(ctx)
        assert result.artifacts == ()
        assert str(ctx.home_dir / ".kimi-code" / "config.toml") in result.config_paths


class TestKimiDetectHooks:
    def test_pretooluse_hook_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_toml(
            ctx.home_dir / ".kimi-code" / "config.toml",
            '''[[hooks]]
event = "PreToolUse"
matcher = "Bash"
command = "bash hook.sh"
timeout = 10
''',
        )
        result = KimiHarnessAdapter().detect(ctx)
        hook_artifacts = [a for a in result.artifacts if a.artifact_type == "hook"]
        assert len(hook_artifacts) == 1
        assert hook_artifacts[0].artifact_id == "kimi:global:hook:pretooluse:0"
        assert hook_artifacts[0].command == "bash hook.sh"
        assert hook_artifacts[0].metadata["matcher"] == "Bash"
        assert hook_artifacts[0].metadata["timeout"] == 10

    def test_user_prompt_submit_hook_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_toml(
            ctx.home_dir / ".kimi-code" / "config.toml",
            '''[[hooks]]
event = "UserPromptSubmit"
command = "bash prompt-hook.sh"
''',
        )
        result = KimiHarnessAdapter().detect(ctx)
        hook_artifacts = [a for a in result.artifacts if a.artifact_type == "hook"]
        assert hook_artifacts[0].artifact_id == "kimi:global:hook:userpromptsubmit:0"

    def test_multiple_hooks_create_indexed_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_toml(
            ctx.home_dir / ".kimi-code" / "config.toml",
            '''[[hooks]]
event = "PreToolUse"
command = "a.sh"

[[hooks]]
event = "PostToolUse"
command = "b.sh"
''',
        )
        result = KimiHarnessAdapter().detect(ctx)
        hook_ids = {a.artifact_id for a in result.artifacts if a.artifact_type == "hook"}
        assert "kimi:global:hook:pretooluse:0" in hook_ids
        assert "kimi:global:hook:posttooluse:1" in hook_ids

    def test_workspace_config_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        _write_toml(
            ctx.workspace_dir / ".kimi-code" / "config.toml",
            '''[[hooks]]
event = "PreToolUse"
command = "ws.sh"
''',
        )
        result = KimiHarnessAdapter().detect(ctx)
        assert any(a.source_scope == "project" for a in result.artifacts)

    def test_invalid_toml_is_skipped_gracefully(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_toml(ctx.home_dir / ".kimi-code" / "config.toml", "not valid toml [[")
        result = KimiHarnessAdapter().detect(ctx)
        assert result.artifacts == ()


class TestKimiDetectMCP:
    def test_mcp_server_in_mcp_json_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(
            ctx.home_dir / ".kimi-code" / "mcp.json",
            {"mcpServers": {"my-server": {"command": "node", "args": ["server.js"]}}},
        )
        result = KimiHarnessAdapter().detect(ctx)
        ids = [a.artifact_id for a in result.artifacts]
        assert "kimi:global:mcp:my-server" in ids

    def test_mcp_server_with_url_gets_http_transport(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(
            ctx.home_dir / ".kimi-code" / "mcp.json",
            {"mcpServers": {"remote": {"url": "http://localhost:8080/mcp"}}},
        )
        result = KimiHarnessAdapter().detect(ctx)
        art = result.artifacts[0]
        assert art.transport == "http"
        assert art.url == "http://localhost:8080/mcp"


class TestKimiInstallUninstall:
    def test_install_writes_managed_hooks(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        manifest = KimiHarnessAdapter().install(ctx)
        assert manifest["harness"] == "kimi"
        assert manifest["active"] is True
        config_path = Path(str(manifest["config_path"]))
        assert config_path.is_file()
        text = config_path.read_text(encoding="utf-8")
        assert "# BEGIN HOL GUARD MANAGED HOOKS" in text
        assert "# END HOL GUARD MANAGED HOOKS" in text
        assert 'event = "PreToolUse"' in text
        assert 'event = "UserPromptSubmit"' in text
        assert "hol-guard" in text or "codex_plugin_scanner.cli" in text

    def test_uninstall_removes_managed_hooks(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        adapter = KimiHarnessAdapter()
        adapter.install(ctx)
        manifest = adapter.uninstall(ctx)
        assert manifest["active"] is False
        config_path = Path(str(manifest["config_path"]))
        text = config_path.read_text(encoding="utf-8")
        assert "BEGIN HOL GUARD MANAGED HOOKS" not in text
        assert "END HOL GUARD MANAGED HOOKS" not in text

    def test_install_preserves_user_hooks(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config_path = ctx.home_dir / ".kimi-code" / "config.toml"
        _write_toml(
            config_path,
            '''[[hooks]]
event = "PostToolUse"
command = "user-format.sh"
''',
        )
        KimiHarnessAdapter().install(ctx)
        text = config_path.read_text(encoding="utf-8")
        assert "user-format.sh" in text
        assert "BEGIN HOL GUARD MANAGED HOOKS" in text

    def test_install_idempotent(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        adapter = KimiHarnessAdapter()
        adapter.install(ctx)
        adapter.install(ctx)
        config_path = ctx.home_dir / ".kimi-code" / "config.toml"
        text = config_path.read_text(encoding="utf-8")
        assert text.count("BEGIN HOL GUARD MANAGED HOOKS") == 1


class TestKimiManagedBlock:
    def test_managed_block_escapes_quotes_and_backslashes(self) -> None:
        from codex_plugin_scanner.guard.adapters.kimi import _toml_escape

        command = 'python -c "print(\\"hello\\")"'
        block = KimiHarnessAdapter._build_managed_block(command)
        parsed = tomllib.loads(block)
        hooks = parsed.get("hooks", [])
        assert len(hooks) == 5
        assert hooks[0]["command"] == command
        assert _toml_escape('a"b\\c') == 'a\\"b\\\\c'


class TestKimiLaunchCommand:
    def test_launch_command_passes_workspace(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        command = KimiHarnessAdapter().launch_command(ctx, ["--version"])
        assert "kimi" in command[0]
        assert "--version" in command
