"""Tests for the z.ai ZCode harness adapter."""

from __future__ import annotations

import json
import re
from pathlib import Path

from codex_plugin_scanner.guard import native_harness_ops as harness_ops
from codex_plugin_scanner.guard.inventory_contract import _agent_type
from codex_plugin_scanner.guard.models import HarnessDetection
from tests import harness_ops_support as harness_support
from tests.native_bounded_runtime import durable_copy, use_bounded_runtime
from tests.zcode_test_support import write_cli_config as _write_cli_config
from tests.zcode_test_support import zcode_context as _ctx

GUARD_MANAGED_MARKER = "HOL_GUARD_MANAGED_ZCODE"
# Tool matchers ZCode surfaces; mcp__.* keeps MCP calls behind the PreToolUse hook.
ZCODE_PRETOOL_MATCHERS = (
    "Bash",
    "Read",
    "Write",
    "Edit",
    "MultiEdit",
    "Grep",
    "WebFetch",
    "WebSearch",
    "mcp__.*",
    "run_terminal_command",
    "run_command",
    "read_file",
    "write_file",
    "search_replace",
    "multi_edit",
    "grep",
    "web_fetch",
    "web_search",
)


def is_guard_managed_hook_command(command: object) -> bool:
    return isinstance(command, str) and GUARD_MANAGED_MARKER in command


def _fixture(name: str) -> dict[str, object]:
    payload = json.loads((Path(__file__).parent / "fixtures" / "zcode" / name).read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


class TestZCodeAdapterIdentity:
    def test_harness_identifier_is_zcode(self) -> None:
        assert harness_ops.canonical_harness("zcode") == "zcode"

    def test_aliases_resolve(self) -> None:
        for alias in ("zai", "z-code", "zai-zcode"):
            assert harness_ops.canonical_harness(alias) == "zcode"

    def test_get_adapter_returns_zcode_instance(self) -> None:
        assert harness_ops.canonical_harness("zcode") == "zcode"

    def test_zcode_is_registered_in_adapter_list(self) -> None:
        assert "zcode" in set(harness_ops.list_harnesses())

    def test_contract_resolve(self) -> None:
        from codex_plugin_scanner.guard.setup_contracts import contract_for

        c = contract_for("zcode")
        assert c is not None
        assert c.harness == "zcode"
        assert c.smoke_command == "hol-guard install zcode --dry-run"

    def test_agent_type_attributes_zcode(self) -> None:
        assert _agent_type("zcode") == "zcode"


class TestZCodeInstallUninstall:
    def test_install_writes_managed_hooks_under_events(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        manifest = harness_support.install("zcode", ctx)
        config_path = ctx.home_dir / ".zcode" / "cli" / "config.json"
        assert manifest["active"] is True
        assert config_path.is_file()
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        hooks = payload["hooks"]
        # Current ZCode requires hook groups nested under hooks.events and
        # hooks.enabled to opt into executing either surface.
        assert set(hooks.keys()) == {"events", "enabled"}
        assert hooks["enabled"] is True
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
        managed_handlers = [
            handler
            for entry in events["PreToolUse"]
            if isinstance(entry, dict)
            for handler in entry.get("hooks", [])
            if isinstance(handler, dict) and is_guard_managed_hook_command(handler.get("command"))
        ]
        # Current ZCode renders statusMessage beside the hook in its Hooks
        # settings UI.
        assert {handler.get("statusMessage") for handler in managed_handlers} == {
            "HOL Guard runtime policy enforcement"
        }

    def test_install_hook_command_uses_bounded_bridge_for_interpreters(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setattr("sys.frozen", False, raising=False)
        harness_support.install("zcode", ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        handler = payload["hooks"]["events"]["PreToolUse"][0]["hooks"][0]
        command = handler["command"]
        assert " bounded-hook-bridge " in command
        assert GUARD_MANAGED_MARKER in command
        assert handler["timeout"] == 30

    def test_install_hook_command_names_the_runtime_when_frozen(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        runtime = tmp_path / "hol-guard-runtime"
        monkeypatch.setattr("sys.frozen", True, raising=False)
        digest = use_bounded_runtime(monkeypatch, runtime)
        harness_support.install("zcode", ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        handler = payload["hooks"]["events"]["PreToolUse"][0]["hooks"][0]
        command = handler["command"]
        import shlex

        tokens = shlex.split(command.split(" # ", 1)[0])
        # A frozen Guard names the verified durable copy of its runtime.
        assert tokens[:2] == [str(durable_copy(ctx.guard_home, runtime, digest)), "bounded-hook-bridge"], tokens[:3]
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
        harness_support.install("zcode", ctx)
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
        harness_support.install("zcode", ctx)
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
        harness_support.install("zcode", ctx)
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
        harness_support.install("zcode", ctx)
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
        harness_support.install("zcode", ctx)
        first = (ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8")
        harness_support.install("zcode", ctx)
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
        harness_support.install("zcode", ctx)
        harness_support.uninstall("zcode", ctx)
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
        harness_support.uninstall("zcode", ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        pretool_commands = [
            handler["command"] for entry in payload["hooks"]["PreToolUse"] for handler in entry.get("hooks", [])
        ]
        assert pretool_commands == ["echo user-pretool"]
        assert GUARD_MANAGED_MARKER not in json.dumps(payload)

    def test_uninstall_drops_empty_hooks_section(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        _write_cli_config(ctx.home_dir, {})
        harness_support.install("zcode", ctx)
        harness_support.uninstall("zcode", ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        assert "hooks" not in payload


class TestZCodeManagedHelpers:
    def test_is_guard_managed_hook_command_detects_marker(self) -> None:
        assert is_guard_managed_hook_command(f"python -c '...' # {GUARD_MANAGED_MARKER}")

    def test_is_guard_managed_hook_command_rejects_user_command(self) -> None:
        assert not is_guard_managed_hook_command("echo user-start")


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
        detection = harness_ops.detect("zcode", ctx)
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
