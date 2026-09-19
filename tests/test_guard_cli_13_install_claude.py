"""Guard CLI install claude behavior."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters import claude_code as claude_adapter_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import CLAUDE_GUARD_DAEMON_HOOK_MARKER, ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_fixture_support import _build_guard_fixture, _command_handler_argv, _write_json
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_install_and_uninstall_manage_claude_hooks(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        install_rc = main(
            [
                "guard",
                "install",
                "claude",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        install_output = json.loads(capsys.readouterr().out)
        settings_path = home_dir / ".claude" / "settings.json"
        install_settings_payload = json.loads(settings_path.read_text(encoding="utf-8"))

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "claude-code",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        uninstall_output = json.loads(capsys.readouterr().out)
        settings_payload = json.loads(settings_path.read_text(encoding="utf-8"))

        assert install_rc == 0
        assert install_output["managed_install"]["active"] is True
        assert install_output["managed_install"]["manifest"]["shim_command"] == "guard-claude"
        assert settings_path.exists()
        assert len(install_settings_payload["hooks"]["SessionStart"]) == 4
        pretool_entries = install_settings_payload["hooks"]["PreToolUse"]
        assert len(pretool_entries) == 2
        assert pretool_entries[0] == {"command": "python guard-pre.py"}
        guard_pretool_entry = pretool_entries[1]
        assert install_output["managed_install"]["manifest"]["notes"][0]
        context = HarnessContext(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            guard_home=home_dir,
        )
        expected_session_start_argv = ClaudeCodeHarnessAdapter._session_start_command_parts(context)
        assert guard_pretool_entry["matcher"] == "Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*"
        assert (
            _command_handler_argv(install_settings_payload["hooks"]["SessionStart"][0]["hooks"][0])
            == expected_session_start_argv
        )
        expected_hook_argv = ClaudeCodeHarnessAdapter._daemon_hook_command_parts(context)
        assert guard_pretool_entry["hooks"][0]["type"] == "command"
        assert _command_handler_argv(guard_pretool_entry["hooks"][0]) == expected_hook_argv
        assert "url" not in guard_pretool_entry["hooks"][0]
        assert install_settings_payload["hooks"].get("UserPromptSubmit", []) == []
        assert install_settings_payload["hooks"]["Notification"][0]["matcher"] == "permission_prompt"
        notification_handler = install_settings_payload["hooks"]["Notification"][0]["hooks"][0]
        assert notification_handler["type"] == "command"
        assert _command_handler_argv(notification_handler) == expected_hook_argv
        assert "url" not in notification_handler
        assert _command_handler_argv(install_settings_payload["hooks"]["Stop"][0]["hooks"][0]) == expected_hook_argv
        assert uninstall_rc == 0
        assert uninstall_output["managed_install"]["active"] is False
        assert settings_payload["hooks"]["SessionStart"] == []
        assert settings_payload["hooks"]["PreToolUse"] == [{"command": "python guard-pre.py"}]
        assert settings_payload["hooks"]["Notification"] == []
        assert settings_payload["hooks"]["Stop"] == []

    def test_guard_uninstall_handles_non_dict_claude_hook_entries(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        settings_path = home_dir / ".claude" / "settings.json"
        expected_hook_command = ClaudeCodeHarnessAdapter._hook_command(
            HarnessContext(
                home_dir=home_dir,
                workspace_dir=workspace_dir,
                guard_home=home_dir,
            )
        )
        _write_json(
            settings_path,
            {
                "hooks": {
                    "PreToolUse": ["unexpected-entry", {"command": expected_hook_command}],
                    "PostToolUse": [],
                }
            },
        )

        rc = main(
            [
                "guard",
                "uninstall",
                "claude-code",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        payload = json.loads(settings_path.read_text(encoding="utf-8"))

        assert rc == 0
        assert output["managed_install"]["active"] is False
        assert payload["hooks"]["PreToolUse"] == ["unexpected-entry"]

    def test_guard_uninstall_claude_does_not_boot_daemon_to_remove_hooks(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        settings_path = home_dir / ".claude" / "settings.json"

        install_rc = main(
            [
                "guard",
                "install",
                "claude-code",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        capsys.readouterr()

        def _fail_if_called(*args, **kwargs):
            raise AssertionError("guard_daemon_url_for_home should not be called during claude uninstall")

        monkeypatch.setattr(claude_adapter_module, "guard_daemon_url_for_home", _fail_if_called)

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "claude",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        payload = json.loads(settings_path.read_text(encoding="utf-8"))

        assert install_rc == 0
        assert uninstall_rc == 0
        assert output["managed_install"]["active"] is False
        assert payload["hooks"]["PreToolUse"] == [{"command": "python guard-pre.py"}]
        assert payload["hooks"].get("UserPromptSubmit", []) == []
        assert payload["hooks"]["Notification"] == []
        assert payload["hooks"]["Stop"] == []

    def test_guard_install_claude_alias_persists_canonical_managed_install(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "install",
                "claude",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        store = GuardStore(home_dir)

        assert rc == 0
        assert output["managed_install"]["harness"] == "claude-code"
        assert store.get_managed_install("claude-code") is not None
        assert store.get_managed_install("claude") is None

    def test_guard_install_omp_alias_dry_run_returns_omp_setup_plan(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        home_dir.mkdir(parents=True, exist_ok=True)
        workspace_dir.mkdir(parents=True, exist_ok=True)

        rc = main(
            [
                "guard",
                "install",
                "omp",
                "--dry-run",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        store = GuardStore(home_dir)

        assert rc == 0
        assert output["dry_run"] is True
        assert output["harness"] == "omp"
        assert output["contract"]["harness"] == "omp"
        assert "omp" in output["contract"]["install_aliases"]
        assert "oh-my-pi" in output["contract"]["install_aliases"]
        assert store.get_managed_install("omp") is None

    def test_guard_uninstall_claude_removes_legacy_claude_code_shim(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        shim_dir = home_dir / "bin"
        shim_dir.mkdir(parents=True, exist_ok=True)
        for shim_name in ("guard-claude", "guard-claude.cmd", "guard-claude-code", "guard-claude-code.cmd"):
            (shim_dir / shim_name).write_text("shim\n", encoding="utf-8")

        rc = main(
            [
                "guard",
                "uninstall",
                "claude-code",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        removed_paths = {Path(path).name for path in output["managed_install"]["manifest"]["removed_paths"]}

        assert rc == 0
        assert removed_paths == {
            "guard-claude",
            "guard-claude.cmd",
            "guard-claude-code",
            "guard-claude-code.cmd",
        }
        assert not any((shim_dir / shim_name).exists() for shim_name in removed_paths)

    def test_guard_install_replaces_legacy_claude_guard_hook_entries(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        settings_path = home_dir / ".claude" / "settings.json"
        legacy_command = ClaudeCodeHarnessAdapter._hook_command(
            HarnessContext(
                home_dir=home_dir,
                workspace_dir=workspace_dir,
                guard_home=tmp_path / "legacy-guard-home",
            )
        )
        _write_json(
            settings_path,
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "matcher": "startup",
                            "hooks": [{"type": "command", "command": legacy_command, "timeout": 5}],
                        }
                    ],
                    "PreToolUse": [
                        {
                            "matcher": "Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*",
                            "hooks": [{"type": "command", "command": legacy_command, "timeout": 30}],
                        }
                    ],
                    "PostToolUse": [
                        {
                            "matcher": "Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*",
                            "hooks": [{"type": "command", "command": legacy_command, "timeout": 30}],
                        }
                    ],
                    "UserPromptSubmit": [
                        {
                            "hooks": [{"type": "command", "command": legacy_command, "timeout": 20}],
                        }
                    ],
                    "Notification": [
                        {
                            "matcher": "permission_prompt",
                            "hooks": [{"type": "command", "command": legacy_command, "timeout": 10}],
                        }
                    ],
                }
            },
        )

        rc = main(
            [
                "guard",
                "install",
                "claude-code",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        payload = json.loads(settings_path.read_text(encoding="utf-8"))

        assert rc == 0
        assert output["managed_install"]["active"] is True
        assert len(payload["hooks"]["SessionStart"]) == 4
        assert len(payload["hooks"]["PreToolUse"]) == 1
        assert len(payload["hooks"]["PostToolUse"]) == 1
        assert payload["hooks"].get("UserPromptSubmit", []) == []
        assert len(payload["hooks"]["Notification"]) == 1
        assert len(payload["hooks"]["Stop"]) == 1
        pretool_hook_commands = [
            "\0".join(_command_handler_argv(hook))
            for hook in payload["hooks"]["PreToolUse"][0]["hooks"]
            if isinstance(hook, dict) and isinstance(hook.get("command"), str)
        ]
        assert len(pretool_hook_commands) == 1
        assert CLAUDE_GUARD_DAEMON_HOOK_MARKER in pretool_hook_commands[0]
        assert "legacy-guard-home" not in pretool_hook_commands[0]
        notification_hook_commands = [
            "\0".join(_command_handler_argv(hook))
            for hook in payload["hooks"]["Notification"][0]["hooks"]
            if isinstance(hook, dict) and isinstance(hook.get("command"), str)
        ]
        assert len(notification_hook_commands) == 1
        assert CLAUDE_GUARD_DAEMON_HOOK_MARKER in notification_hook_commands[0]
        assert "legacy-guard-home" not in notification_hook_commands[0]
