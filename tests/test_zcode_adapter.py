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
from codex_plugin_scanner.guard.adapters.zcode_hooks import (
    emit_zcode_hook_response,
    prepare_zcode_hook_payload,
    zcode_hook_response_from_guard,
    zcode_hook_should_block,
)
from codex_plugin_scanner.guard.inventory_contract import _agent_type
from codex_plugin_scanner.guard.models import HarnessDetection
from codex_plugin_scanner.guard.runtime.actions import (
    normalize_harness_payload,
    normalize_zcode_hook_payload,
)


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

    def test_install_writes_managed_hooks(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        self._patch_shims(monkeypatch, ctx)
        manifest = ZCodeHarnessAdapter().install(ctx)
        config_path = ctx.home_dir / ".zcode" / "cli" / "config.json"
        assert manifest["active"] is True
        assert config_path.is_file()
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        hooks = payload["hooks"]
        pretool_matchers = {
            entry["matcher"]
            for entry in hooks["PreToolUse"]
            if isinstance(entry, dict) and isinstance(entry.get("matcher"), str)
        }
        assert set(ZCODE_PRETOOL_MATCHERS).issubset(pretool_matchers)
        assert isinstance(hooks["UserPromptSubmit"], list)
        managed_commands = [
            handler["command"]
            for entry in hooks["PreToolUse"]
            if isinstance(entry, dict)
            for handler in entry.get("hooks", [])
            if isinstance(handler, dict) and is_guard_managed_hook_command(handler.get("command"))
        ]
        assert managed_commands, "Guard-managed PreToolUse handlers must be present"

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
        session_start = payload["hooks"]["SessionStart"]
        user_commands = [
            handler["command"]
            for entry in session_start
            if isinstance(entry, dict)
            for handler in entry.get("hooks", [])
            if isinstance(handler, dict) and handler.get("command") == "echo user-start"
        ]
        assert user_commands == ["echo user-start"]

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
        # User hooks preserved, Guard-managed hooks removed.
        session_commands = [
            handler["command"]
            for entry in payload["hooks"]["SessionStart"]
            for handler in entry.get("hooks", [])
            if handler.get("command") == "echo user-start"
        ]
        assert session_commands == ["echo user-start"]
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


class TestZCodeHookPayload:
    def test_prepare_payload_maps_bash_fixture(self) -> None:
        normalized = prepare_zcode_hook_payload(_fixture("pretooluse_bash.json"))
        assert normalized["hook_event_name"] == "PreToolUse"
        assert normalized["tool_name"] == "Bash"
        assert normalized["session_id"] == "session-redacted-001"
        assert normalized["workspace_root"] == "<workspace>"

    def test_prepare_payload_maps_mcp_fixture(self) -> None:
        normalized = prepare_zcode_hook_payload(_fixture("pretooluse_mcp.json"))
        assert normalized["tool_name"] == "mcp__lean-ctx__ctx_call"
        assert normalized["tool_input"]["name"] == "ctx_call"

    def test_prepare_payload_maps_prompt_fixture(self) -> None:
        normalized = prepare_zcode_hook_payload(_fixture("user_prompt_submit.json"))
        assert normalized["hook_event_name"] == "UserPromptSubmit"
        assert normalized["prompt"] == "show me how to read a secret file"

    def test_prepare_payload_camelcase_keys(self) -> None:
        normalized = prepare_zcode_hook_payload(
            {"hookEventName": "PostToolUse", "toolName": "Read", "toolInput": {"path": "x"}, "sessionId": "s"}
        )
        assert normalized["hook_event_name"] == "PostToolUse"
        assert normalized["tool_name"] == "Read"
        assert normalized["session_id"] == "s"

    def test_prepare_payload_malformed_is_safe(self) -> None:
        assert prepare_zcode_hook_payload({}) == {}

    def test_normalize_zcode_hook_payload_builds_shell_envelope(self, tmp_path: Path) -> None:
        envelope = normalize_zcode_hook_payload(
            _fixture("pretooluse_bash.json"),
            workspace=tmp_path / "workspace",
            home_dir=tmp_path,
        )
        assert envelope.harness == "zcode"
        assert envelope.action_type == "shell_command"
        assert envelope.event_name == "PreToolUse"

    def test_normalize_harness_payload_accepts_zcode(self, tmp_path: Path) -> None:
        envelope = normalize_harness_payload(
            "zcode",
            "PreToolUse",
            _fixture("pretooluse_mcp.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.harness == "zcode"

    def test_normalize_harness_payload_accepts_zai_alias(self, tmp_path: Path) -> None:
        envelope = normalize_harness_payload(
            "zai",
            "UserPromptSubmit",
            _fixture("user_prompt_submit.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.harness == "zcode"


class TestZCodeHookResponses:
    def test_allow_pretool_response(self) -> None:
        payload = zcode_hook_response_from_guard(policy_action="allow", reason="")
        assert payload == {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}

    def test_block_pretool_response(self) -> None:
        payload = zcode_hook_response_from_guard(policy_action="block", reason="Blocked by HOL Guard.")
        assert payload == {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Blocked by HOL Guard.",
            }
        }

    def test_block_uses_default_reason_when_empty(self) -> None:
        payload = zcode_hook_response_from_guard(policy_action="block", reason="")
        reason = payload["hookSpecificOutput"]["permissionDecisionReason"]
        assert reason == "Blocked by HOL Guard."

    def test_block_userprompt_response(self) -> None:
        payload = zcode_hook_response_from_guard(
            policy_action="require-reapproval", reason="needs approval", event_name="UserPromptSubmit"
        )
        assert payload["decision"] == "block"
        assert payload["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"

    def test_should_block_flags_blocking_actions(self) -> None:
        assert zcode_hook_should_block(policy_action="block")
        assert zcode_hook_should_block(policy_action="sandbox-required")
        assert zcode_hook_should_block(policy_action="require-reapproval")
        assert not zcode_hook_should_block(policy_action="allow")

    def test_emit_writes_json_line(self) -> None:
        stream = io.StringIO()
        emit_zcode_hook_response(policy_action="allow", reason="", output_stream=stream)
        assert json.loads(stream.getvalue())["hookSpecificOutput"]["permissionDecision"] == "allow"


class TestZCodeManagedHelpers:
    def test_is_guard_managed_hook_command_detects_marker(self) -> None:
        assert is_guard_managed_hook_command(f"python -c '...' # {GUARD_MANAGED_MARKER}")

    def test_is_guard_managed_hook_command_rejects_user_command(self) -> None:
        assert not is_guard_managed_hook_command("echo user-start")

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
