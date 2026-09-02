"""Tests for the z.ai ZCode harness adapter."""

from __future__ import annotations

import argparse
import io
import json
import re
from contextlib import redirect_stderr
from pathlib import Path

from codex_plugin_scanner.guard.adapters import get_adapter, list_adapters
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter, _merge_hook_entry
from codex_plugin_scanner.guard.adapters.zcode_config import (
    GUARD_MANAGED_MARKER,
    ZCODE_PRETOOL_MATCHERS,
    is_guard_managed_hook_command,
)
from codex_plugin_scanner.guard.inventory_contract import _agent_type
from codex_plugin_scanner.guard.models import HarnessDetection


def _ctx(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _fixture(name: str) -> dict[str, object]:
    payload = json.loads((Path(__file__).parent / "fixtures" / "zcode" / name).read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _write_cli_config(home: Path, payload: dict[str, object]) -> Path:
    config_path = home / ".zcode" / "cli" / "config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return config_path


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


class TestZCodeAdapterIdentity:
    def test_harness_identifier_is_zcode(self) -> None:
        assert ZCodeHarnessAdapter.harness == "zcode"

    def test_aliases_resolve(self) -> None:
        for alias in ("zai", "z-code", "zai-zcode"):
            assert get_adapter(alias).harness == "zcode"

    def test_get_adapter_returns_zcode_instance(self) -> None:
        assert isinstance(get_adapter("zcode"), ZCodeHarnessAdapter)

    def test_zcode_is_registered_in_adapter_list(self) -> None:
        assert "zcode" in {item.harness for item in list_adapters()}

    def test_contract_resolve(self) -> None:
        from codex_plugin_scanner.guard.adapters.contracts import contract_for

        c = contract_for("zcode")
        assert c is not None
        assert c.harness == "zcode"
        assert c.smoke_command == "hol-guard install zcode --dry-run"

    def test_agent_type_attributes_zcode(self) -> None:
        assert _agent_type("zcode") == "zcode"


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
        result = ZCodeHarnessAdapter().detect(ctx)
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
        result = ZCodeHarnessAdapter().detect(ctx)
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
        result = ZCodeHarnessAdapter().detect(ctx)
        marketplaces = [a for a in result.artifacts if a.artifact_type == "marketplace"]
        assert len(marketplaces) == 1
        assert marketplaces[0].name == "zcode-plugins-official"
        assert marketplaces[0].metadata.get("entries") == 1

    def test_detects_runtime_env_signal_without_config(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setenv("__CFBundleIdentifier", "dev.zcode.app")
        result = ZCodeHarnessAdapter().detect(ctx)
        assert result.installed is True
        assert any("runtime was detected through process environment" in w for w in result.warnings)

    def test_detects_http_mcp_transport(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(
            ctx.home_dir,
            {"mcp": {"servers": {"remote": {"url": "https://example.com/mcp", "transport": "http"}}}},
        )
        result = ZCodeHarnessAdapter().detect(ctx)
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
        result = ZCodeHarnessAdapter().detect(ctx)
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
        result = ZCodeHarnessAdapter().detect(ctx)
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
        result = ZCodeHarnessAdapter().detect(ctx)
        hooks = [a for a in result.artifacts if a.artifact_type == "hook" and a.command == "echo both-layouts"]
        assert len(hooks) == 1

    def test_detect_uses_v2_config_as_install_signal(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        v2_config = ctx.home_dir / ".zcode" / "v2" / "config.json"
        v2_config.parent.mkdir(parents=True, exist_ok=True)
        v2_config.write_text(json.dumps({"provider": {}}), encoding="utf-8")
        result = ZCodeHarnessAdapter().detect(ctx)
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
        result = ZCodeHarnessAdapter().detect(ctx)
        project_mcp = [a for a in result.artifacts if a.artifact_type == "mcp_server" and a.source_scope == "project"]
        assert any(a.name == "proj-server" for a in project_mcp)


class TestZCodeInstallUninstall:
    def _patch_shims(self, monkeypatch, ctx: HarnessContext) -> None:
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.zcode.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-zcode"), "notes": []},
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.zcode.remove_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-zcode"), "notes": []},
        )

    def test_install_writes_managed_hooks_under_events(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        self._patch_shims(monkeypatch, ctx)
        manifest = ZCodeHarnessAdapter().install(ctx)
        config_path = ctx.home_dir / ".zcode" / "cli" / "config.json"
        assert manifest["active"] is True
        assert config_path.is_file()
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        hooks = payload["hooks"]
        # Current ZCode requires hook groups nested under hooks.events; the
        # legacy flat layout makes ZCode reject the whole config file.
        assert set(hooks.keys()) == {"events"}
        events = hooks["events"]
        assert set(events.keys()) == {"PreToolUse", "UserPromptSubmit"}
        pretool_matchers = {
            entry["matcher"]
            for entry in events["PreToolUse"]
            if isinstance(entry, dict) and isinstance(entry.get("matcher"), str)
        }
        assert set(ZCODE_PRETOOL_MATCHERS).issubset(pretool_matchers)
        assert isinstance(events["UserPromptSubmit"], list)
        managed_commands = [
            handler["command"]
            for entry in events["PreToolUse"]
            if isinstance(entry, dict)
            for handler in entry.get("hooks", [])
            if isinstance(handler, dict) and is_guard_managed_hook_command(handler.get("command"))
        ]
        assert managed_commands, "Guard-managed PreToolUse handlers must be present"

    def test_install_hook_command_uses_bounded_bridge_for_interpreters(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        self._patch_shims(monkeypatch, ctx)
        monkeypatch.setattr("codex_plugin_scanner.guard.adapters.zcode.sys.frozen", False, raising=False)
        ZCodeHarnessAdapter().install(ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        handler = payload["hooks"]["events"]["PreToolUse"][0]["hooks"][0]
        command = handler["command"]
        assert "bounded_cli_hook_bridge" in command
        assert GUARD_MANAGED_MARKER in command
        assert handler["timeout"] == 30

    def test_install_hook_command_avoids_interpreter_flags_when_frozen(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        self._patch_shims(monkeypatch, ctx)
        monkeypatch.setattr("codex_plugin_scanner.guard.adapters.zcode.sys.frozen", True, raising=False)
        ZCodeHarnessAdapter().install(ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        handler = payload["hooks"]["events"]["PreToolUse"][0]["hooks"][0]
        command = handler["command"]
        import shlex

        tokens = shlex.split(command.split(" # ", 1)[0])
        assert tokens[1] == "__guard-bounded-hook", tokens[:3]
        bridge_config = json.loads(tokens[2])
        assert bridge_config["harness"] == "zcode"
        assert bridge_config["frozen_launcher"] is True
        assert GUARD_MANAGED_MARKER in command

    def test_install_deduplicates_handlers_present_in_both_layouts(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        user_handler = {"type": "command", "command": "echo user-pretool"}
        _write_cli_config(
            ctx.home_dir,
            {
                "hooks": {
                    "events": {
                        "PreToolUse": [
                            {"matcher": "Bash", "hooks": [dict(user_handler)]},
                        ]
                    },
                    "PreToolUse": [
                        {"matcher": "Bash", "hooks": [dict(user_handler)]},
                    ],
                }
            },
        )
        self._patch_shims(monkeypatch, ctx)
        ZCodeHarnessAdapter().install(ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        events = payload["hooks"]["events"]
        assert "PreToolUse" not in payload["hooks"], "legacy keys must be migrated away"
        bash_entry = next(e for e in events["PreToolUse"] if e.get("matcher") == "Bash")
        user_commands = [
            handler["command"] for handler in bash_entry["hooks"] if handler.get("command") == "echo user-pretool"
        ]
        assert user_commands == ["echo user-pretool"]

    def test_install_preserves_user_mcp_and_plugins(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(
            ctx.home_dir,
            {
                "mcp": {"servers": {"user-server": {"command": "node"}}},
                "plugins": {"enabledPlugins": {"user-plugin@mp": True}},
            },
        )
        self._patch_shims(monkeypatch, ctx)
        ZCodeHarnessAdapter().install(ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        assert payload["mcp"]["servers"]["user-server"]["command"] == "node"
        assert payload["plugins"]["enabledPlugins"]["user-plugin@mp"] is True

    def test_install_preserves_user_hooks(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(
            ctx.home_dir,
            {
                "hooks": {
                    "SessionStart": [
                        {"matcher": "startup", "hooks": [{"type": "command", "command": "echo user-start"}]}
                    ]
                }
            },
        )
        self._patch_shims(monkeypatch, ctx)
        ZCodeHarnessAdapter().install(ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        events = payload["hooks"]["events"]
        session_start = events["SessionStart"]
        user_commands = [
            handler["command"]
            for entry in session_start
            if isinstance(entry, dict)
            for handler in entry.get("hooks", [])
            if isinstance(handler, dict) and handler.get("command") == "echo user-start"
        ]
        assert user_commands == ["echo user-start"]

    def test_install_migrates_legacy_hook_layout(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        legacy_managed = f"old-guard-command # {GUARD_MANAGED_MARKER}"
        _write_cli_config(
            ctx.home_dir,
            {
                "hooks": {
                    "enabled": True,
                    "timeoutMs": 60000,
                    "SessionStart": [
                        {"matcher": "startup", "hooks": [{"type": "command", "command": "echo user-start"}]}
                    ],
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {"type": "command", "command": "echo user-pretool"},
                                {"type": "command", "command": legacy_managed, "timeout": 30},
                            ],
                        }
                    ],
                }
            },
        )
        self._patch_shims(monkeypatch, ctx)
        ZCodeHarnessAdapter().install(ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        hooks = payload["hooks"]
        # User settings beside events survive and no legacy event keys remain.
        assert hooks["enabled"] is True
        assert hooks["timeoutMs"] == 60000
        assert set(hooks.keys()) == {"enabled", "timeoutMs", "events"}
        events = hooks["events"]
        user_start = [handler["command"] for entry in events["SessionStart"] for handler in entry.get("hooks", [])]
        assert user_start == ["echo user-start"]
        bash_entry = next(e for e in events["PreToolUse"] if e.get("matcher") == "Bash")
        bash_commands = [handler["command"] for handler in bash_entry["hooks"]]
        assert "echo user-pretool" in bash_commands
        assert legacy_managed not in bash_commands, "stale managed handlers must be replaced"
        assert any(is_guard_managed_hook_command(command) for command in bash_commands)

    def test_repeated_install_is_idempotent(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        self._patch_shims(monkeypatch, ctx)
        adapter = ZCodeHarnessAdapter()
        adapter.install(ctx)
        first = (ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8")
        adapter.install(ctx)
        second = (ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8")
        assert first.count(GUARD_MANAGED_MARKER) == len(ZCODE_PRETOOL_MATCHERS) + 1
        assert second.count(GUARD_MANAGED_MARKER) == len(ZCODE_PRETOOL_MATCHERS) + 1

    def test_uninstall_removes_only_guard_managed_entries(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(
            ctx.home_dir,
            {
                "mcp": {"servers": {"user-server": {"command": "node"}}},
                "plugins": {"enabledPlugins": {"user-plugin@mp": True}},
                "hooks": {
                    "SessionStart": [
                        {"matcher": "startup", "hooks": [{"type": "command", "command": "echo user-start"}]}
                    ],
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "echo user-pretool"}],
                        }
                    ],
                },
            },
        )
        self._patch_shims(monkeypatch, ctx)
        adapter = ZCodeHarnessAdapter()
        adapter.install(ctx)
        adapter.uninstall(ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        # User MCP/plugins preserved.
        assert payload["mcp"]["servers"]["user-server"]["command"] == "node"
        assert payload["plugins"]["enabledPlugins"]["user-plugin@mp"] is True
        # User hooks preserved (migrated into events during install), Guard-managed hooks removed.
        events = payload["hooks"]["events"]
        session_commands = [
            handler["command"]
            for entry in events["SessionStart"]
            for handler in entry.get("hooks", [])
            if handler.get("command") == "echo user-start"
        ]
        assert session_commands == ["echo user-start"]
        pretool_commands = [handler["command"] for entry in events["PreToolUse"] for handler in entry.get("hooks", [])]
        assert pretool_commands == ["echo user-pretool"]
        assert GUARD_MANAGED_MARKER not in json.dumps(payload)

    def test_uninstall_prunes_legacy_guard_entries(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(
            ctx.home_dir,
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {"type": "command", "command": f"stale # {GUARD_MANAGED_MARKER}"},
                                {"type": "command", "command": "echo user-pretool"},
                            ],
                        }
                    ]
                }
            },
        )
        self._patch_shims(monkeypatch, ctx)
        ZCodeHarnessAdapter().uninstall(ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        pretool_commands = [
            handler["command"] for entry in payload["hooks"]["PreToolUse"] for handler in entry.get("hooks", [])
        ]
        assert pretool_commands == ["echo user-pretool"]
        assert GUARD_MANAGED_MARKER not in json.dumps(payload)

    def test_uninstall_drops_empty_hooks_section(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(ctx.home_dir, {})
        self._patch_shims(monkeypatch, ctx)
        adapter = ZCodeHarnessAdapter()
        adapter.install(ctx)
        adapter.uninstall(ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        assert "hooks" not in payload


class TestZCodeManagedHelpers:
    def test_is_guard_managed_hook_command_detects_marker(self) -> None:
        assert is_guard_managed_hook_command(f"python -c '...' # {GUARD_MANAGED_MARKER}")

    def test_is_guard_managed_hook_command_rejects_user_command(self) -> None:
        assert not is_guard_managed_hook_command("echo user-start")

    def test_hook_event_groups_reads_both_schema_generations(self) -> None:
        from codex_plugin_scanner.guard.adapters.zcode_config import hook_event_groups

        groups = hook_event_groups(
            {
                "enabled": True,
                "events": {"PreToolUse": [{"matcher": "Bash", "hooks": []}]},
                "Stop": [{"hooks": []}],
            }
        )
        assert set(groups.keys()) == {"PreToolUse", "Stop"}
        # Settings keys are never mistaken for event groups.
        assert hook_event_groups({"enabled": True, "timeoutMs": 1000}) == {}
        assert hook_event_groups(None) == {}

    def test_merge_hook_entry_preserves_user_handlers(self) -> None:
        handler = {"type": "command", "command": f"x # {GUARD_MANAGED_MARKER}"}
        user_handler = {"type": "command", "command": "echo user"}
        entries: list[object] = [{"matcher": "Bash", "hooks": [user_handler]}]
        result = _merge_hook_entry(entries, "Bash", handler)
        bash_entry = next(e for e in result if isinstance(e, dict) and e.get("matcher") == "Bash")
        commands = [h["command"] for h in bash_entry["hooks"]]
        assert "echo user" in commands
        assert f"x # {GUARD_MANAGED_MARKER}" in commands

    def test_merge_hook_entry_refreshes_existing_managed_handler(self) -> None:
        old = {"type": "command", "command": f"old # {GUARD_MANAGED_MARKER}"}
        new = {"type": "command", "command": f"new # {GUARD_MANAGED_MARKER}"}
        entries: list[object] = [{"matcher": "Read", "hooks": [old]}]
        result = _merge_hook_entry(entries, "Read", new)
        read_entry = next(e for e in result if isinstance(e, dict) and e.get("matcher") == "Read")
        commands = [h["command"] for h in read_entry["hooks"]]
        assert commands == [f"new # {GUARD_MANAGED_MARKER}"]

    def test_merge_hook_entry_preserves_non_dict_entries(self) -> None:
        # Non-dict entries (defensively kept by _prune_managed_entries) must
        # survive the merge so user data is never silently dropped on install.
        handler = {"type": "command", "command": f"x # {GUARD_MANAGED_MARKER}"}
        entries: list[object] = ["raw-user-string", 42, {"matcher": "Bash", "hooks": []}]
        result = _merge_hook_entry(entries, "Bash", handler)
        assert "raw-user-string" in result
        assert 42 in result
        assert any(isinstance(e, dict) and e.get("matcher") == "Bash" for e in result)


class TestZCodeGenericEmitterBlock:
    def test_block_emits_deny_json_and_exit_two(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.cli.commands_hook_generic import _run_hook_generic_payload
        from codex_plugin_scanner.guard.config import GuardConfig
        from codex_plugin_scanner.guard.store import GuardStore

        guard_home = tmp_path / ".hol-guard"
        store = GuardStore(guard_home)
        config = GuardConfig(guard_home=guard_home, workspace=tmp_path)
        args = argparse.Namespace(
            harness="zcode",
            json=False,
            policy_action="block",
            artifact_id=None,
            artifact_name=None,
        )
        payload = {
            "hookEventName": "pre_tool_use",
            "toolName": "run_terminal_command",
            "toolInput": {"command": "rm -rf /"},
        }
        stderr_capture = io.StringIO()
        stdout_capture = io.StringIO()
        with redirect_stderr(stderr_capture):
            rc = _run_hook_generic_payload(
                args,
                action_envelope=None,
                config=config,
                output_stream=stdout_capture,
                payload=payload,
                home_dir=tmp_path,
                runtime_workspace=tmp_path,
                store=store,
            )
        assert rc == 2
        response = json.loads(stdout_capture.getvalue())
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"


class TestZCodeFixturesAreRedacted:
    def test_fixtures_do_not_include_real_local_paths_or_tokens(self) -> None:
        fixture_dir = Path(__file__).parent / "fixtures" / "zcode"
        home_prefix = "/" + "Users" + "/"
        unix_home_prefix = "/" + "home" + "/"
        secret_marker = "ZAI_" + "API_KEY"
        forbidden = re.compile(
            rf"({re.escape(home_prefix)}|{re.escape(unix_home_prefix)}|{secret_marker}|sk-[A-Za-z0-9]{{8,}}|Bearer\s+\S+)"
        )
        for path in fixture_dir.glob("*.json"):
            contents = path.read_text(encoding="utf-8")
            assert forbidden.search(contents) is None, f"fixture {path.name} contains forbidden content"


class TestZCodeDetectionModel:
    def test_detection_to_dict_roundtrip(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(ctx.home_dir, {"mcp": {"servers": {"x": {"command": "node"}}}})
        detection = ZCodeHarnessAdapter().detect(ctx)
        payload = detection.to_dict()
        assert payload["harness"] == "zcode"
        restored = HarnessDetection(
            harness=payload["harness"],
            installed=bool(payload["installed"]),
            command_available=bool(payload["command_available"]),
            config_paths=tuple(payload["config_paths"]),
            artifacts=tuple(),
            warnings=tuple(payload["warnings"]),
        )
        assert restored.harness == "zcode"
