"""Detection tests for the z.ai ZCode harness adapter."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters import get_adapter
from tests.zcode_test_support import write_cli_config as _write_cli_config
from tests.zcode_test_support import zcode_context as _ctx


def _write_plugin_cache(home: Path, marketplace: str, plugin: str, version: str) -> Path:
    plugin_root = home / ".zcode" / "cli" / "plugins" / "cache" / marketplace / plugin / version
    plugin_root.mkdir(parents=True, exist_ok=True)
    (plugin_root / ".zcode-plugin").mkdir(parents=True, exist_ok=True)
    (plugin_root / ".zcode-plugin" / "plugin.json").write_text(
        json.dumps({"name": plugin, "version": version, "author": {"name": "Z.ai"}, "skills": "skills"}),
        encoding="utf-8",
    )
    (plugin_root / ".zcode-plugin-seed.json").write_text(
        json.dumps(
            {
                "hash": "abc123def456",
                "marketplace": marketplace,
                "plugin": plugin,
                "pluginVersion": version,
                "source": "filesystem",
                "version": 1,
            }
        ),
        encoding="utf-8",
    )
    (plugin_root / "hooks").mkdir(parents=True, exist_ok=True)
    (plugin_root / "hooks" / "hooks.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "matcher": "startup|resume|clear|compact",
                            "hooks": [
                                {"type": "command", "command": "echo session-start", "async": False},
                            ],
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    (plugin_root / "skills" / "demo").mkdir(parents=True, exist_ok=True)
    (plugin_root / "skills" / "demo" / "SKILL.md").write_text("# Demo skill\n", encoding="utf-8")
    (plugin_root / "commands").mkdir(parents=True, exist_ok=True)
    (plugin_root / "commands" / "demo.md").write_text("---\ndescription: demo\n---\n", encoding="utf-8")
    return plugin_root


def _write_marketplace(home: Path, marketplace: str, plugins: list[dict[str, object]]) -> Path:
    marketplace_file = home / ".zcode" / "cli" / "plugins" / "marketplaces" / marketplace / "marketplace.json"
    marketplace_file.parent.mkdir(parents=True, exist_ok=True)
    marketplace_file.write_text(
        json.dumps({"name": marketplace, "version": 1, "plugins": plugins}),
        encoding="utf-8",
    )
    return marketplace_file


class TestZCodeDetect:
    def test_detects_cli_config_mcp_and_plugins(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(
            ctx.home_dir,
            {
                "mcp": {
                    "servers": {
                        "lean-ctx": {
                            "type": "stdio",
                            "command": "/usr/local/bin/lean-ctx",
                            "args": [],
                            "env": {"LEAN_CTX_DATA_DIR": "/data"},
                        }
                    }
                },
                "plugins": {"enabledPlugins": {"demo@mp": True}},
            },
        )
        result = get_adapter("zcode").detect(ctx)
        assert result.harness == "zcode"
        assert any(".zcode/cli/config.json" in path for path in result.config_paths)
        mcp = [a for a in result.artifacts if a.artifact_type == "mcp_server"]
        assert len(mcp) == 1
        assert mcp[0].name == "lean-ctx"
        assert mcp[0].command == "/usr/local/bin/lean-ctx"
        assert mcp[0].transport == "stdio"
        plugins = [a for a in result.artifacts if a.artifact_type == "plugin"]
        assert any(p.name == "demo@mp" for p in plugins)

    def test_detects_plugin_cache_manifests_hooks_skills_commands(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(ctx.home_dir, {})
        _write_plugin_cache(ctx.home_dir, "zcode-plugins-official", "demo-plugin", "1.0.0")
        result = get_adapter("zcode").detect(ctx)
        artifacts = result.artifacts
        plugins = [a for a in artifacts if a.artifact_type == "plugin"]
        assert any(a.name == "demo-plugin" for a in plugins)
        plugin_artifact = next(a for a in plugins if a.name == "demo-plugin")
        assert plugin_artifact.metadata.get("marketplace") == "zcode-plugins-official"
        assert plugin_artifact.metadata.get("provenance_hash") == "abc123def456"
        hooks = [a for a in artifacts if a.artifact_type == "hook"]
        assert any(a.metadata.get("event") == "SessionStart" for a in hooks)
        skills = [a for a in artifacts if a.artifact_type == "skill"]
        assert any(a.name == "demo" for a in skills)
        commands = [a for a in artifacts if a.artifact_type == "command"]
        assert any(a.name == "demo" for a in commands)

    def test_detects_marketplace_manifest(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(ctx.home_dir, {})
        _write_marketplace(
            ctx.home_dir,
            "zcode-plugins-official",
            [{"name": "demo", "version": "1.0.0", "source": "filesystem"}],
        )
        result = get_adapter("zcode").detect(ctx)
        marketplaces = [a for a in result.artifacts if a.artifact_type == "marketplace"]
        assert len(marketplaces) == 1
        assert marketplaces[0].name == "zcode-plugins-official"
        assert marketplaces[0].metadata.get("entries") == 1

    def test_detects_runtime_env_signal_without_config(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setenv("__CFBundleIdentifier", "dev.zcode.app")
        result = get_adapter("zcode").detect(ctx)
        assert result.installed is True
        assert any("runtime was detected through process environment" in w for w in result.warnings)

    def test_detects_http_mcp_transport(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(
            ctx.home_dir,
            {"mcp": {"servers": {"remote": {"url": "https://example.com/mcp", "transport": "http"}}}},
        )
        result = get_adapter("zcode").detect(ctx)
        mcp = [a for a in result.artifacts if a.artifact_type == "mcp_server"]
        assert len(mcp) == 1
        assert mcp[0].transport == "http"
        assert mcp[0].url == "https://example.com/mcp"

    def test_detect_inventories_hooks_from_events_schema(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(
            ctx.home_dir,
            {
                "hooks": {
                    "enabled": True,
                    "events": {
                        "PreToolUse": [
                            {
                                "matcher": "Bash",
                                "hooks": [{"type": "command", "command": "echo events-hook"}],
                            }
                        ]
                    },
                }
            },
        )
        result = get_adapter("zcode").detect(ctx)
        hooks = [a for a in result.artifacts if a.artifact_type == "hook"]
        assert len(hooks) == 1
        assert hooks[0].metadata.get("event") == "PreToolUse"
        assert hooks[0].metadata.get("matcher") == "Bash"
        assert hooks[0].command == "echo events-hook"

    def test_detect_inventories_hooks_from_legacy_layout(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(
            ctx.home_dir,
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "echo legacy-hook"}],
                        }
                    ]
                }
            },
        )
        result = get_adapter("zcode").detect(ctx)
        hooks = [a for a in result.artifacts if a.artifact_type == "hook"]
        assert len(hooks) == 1
        assert hooks[0].command == "echo legacy-hook"

    def test_detect_deduplicates_identical_handlers_across_layouts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        user_handler = {"type": "command", "command": "echo both-layouts"}
        group = {"matcher": "Bash", "hooks": [user_handler]}
        _write_cli_config(
            ctx.home_dir,
            {
                "hooks": {
                    "events": {"PreToolUse": [dict(group)]},
                    "PreToolUse": [dict(group)],
                }
            },
        )
        result = get_adapter("zcode").detect(ctx)
        hooks = [a for a in result.artifacts if a.artifact_type == "hook" and a.command == "echo both-layouts"]
        assert len(hooks) == 1

    def test_detect_uses_v2_config_as_install_signal(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        v2_config = ctx.home_dir / ".zcode" / "v2" / "config.json"
        v2_config.parent.mkdir(parents=True, exist_ok=True)
        v2_config.write_text(json.dumps({"provider": {}}), encoding="utf-8")
        result = get_adapter("zcode").detect(ctx)
        assert result.installed is True
        assert any(".zcode/v2/config.json" in path for path in result.config_paths)

    def test_project_scope_config_is_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        project_config = ctx.workspace_dir / ".zcode" / "cli" / "config.json"  # type: ignore[union-attr]
        project_config.parent.mkdir(parents=True, exist_ok=True)
        project_config.write_text(
            json.dumps({"mcp": {"servers": {"proj-server": {"command": "node"}}}}),
            encoding="utf-8",
        )
        result = get_adapter("zcode").detect(ctx)
        project_mcp = [a for a in result.artifacts if a.artifact_type == "mcp_server" and a.source_scope == "project"]
        assert any(a.name == "proj-server" for a in project_mcp)
