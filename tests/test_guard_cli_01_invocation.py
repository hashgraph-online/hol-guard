"""Guard CLI invocation behavior."""

from __future__ import annotations

import sys

import pytest
from rich.console import Console

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters import claude_code as claude_adapter_module
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.cli import prompt as guard_prompt_module
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_claude_guard_hook_command_detection_handles_legacy_and_pinned_commands(self):
        legacy_command = "/opt/python/bin/python3 -m codex_plugin_scanner.cli guard hook --guard-home /tmp/guard"
        pinned_command = (
            "/opt/python/bin/python3 -c "
            "\"import sys;sys.path.insert(0, '/tmp/src');from codex_plugin_scanner.cli import main;"
            "raise SystemExit(main(['guard', 'hook']))\""
        )

        assert claude_adapter_module._is_guard_hook_command(legacy_command) is True
        assert claude_adapter_module._is_guard_hook_command(pinned_command) is True
        assert claude_adapter_module._is_guard_hook_command("python something-else.py") is False

    def test_guard_prompt_renders_untrusted_metadata_as_literal_text(self):
        console = Console(record=True, width=120)
        artifact = guard_prompt_module.PromptArtifact(
            harness="codex",
            artifact_id="codex:project:[blink]workspace[/blink]",
            artifact_name="[bold red]workspace[/bold red]\x1b[31m-tool",
            artifact_hash="hash-123",
            policy_action="review",
            changed_fields=("args",),
            provenance_summary="project artifact",
            recommendation="review",
            publisher="[green]hashgraph-online[/green]",
            config_path="/tmp/workspace/.codex/config.toml",
            source_scope="project",
            artifact_type="mcp_server",
            command="node",
            transport="stdio",
            metadata={},
            current_snapshot=None,
        )

        console.print(guard_prompt_module._build_prompt_panel(artifact))
        rendered = console.export_text()

        assert "[bold red]workspace[/bold red]" in rendered
        assert "[blink]workspace[/blink]" in rendered
        assert "[green]hashgraph-online[/green]" in rendered
        assert "\x1b" not in rendered

    def test_guard_requires_a_subcommand(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["guard"])

        assert exc_info.value.code == 2
        error_output = capsys.readouterr().err

        assert "the following arguments are required" in error_output
        assert "guard --help" in error_output

    def test_guard_invalid_subcommand_suggests_closest_match(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["guard", "updte"])

        assert exc_info.value.code == 2
        error_output = capsys.readouterr().err

        assert "Did you mean `update`?" in error_output
        assert "hook" not in error_output
        assert "daemon" not in error_output

    def test_bare_hol_guard_shows_help_without_side_effects(self, tmp_path, monkeypatch, capsys):
        side_effects: list[str] = []
        monkeypatch.setattr(sys, "argv", ["hol-guard"])
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.setattr(guard_commands_module.sys.stdin, "isatty", lambda: False)
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_guard_daemon",
            lambda *_args, **_kwargs: side_effects.append("dashboard"),
        )
        monkeypatch.setattr(
            guard_commands_module,
            "apply_managed_install",
            lambda *_args, **_kwargs: side_effects.append("apps"),
        )
        monkeypatch.setattr(
            guard_commands_module,
            "_run_guard_device_connect_flow",
            lambda **_kwargs: side_effects.append("cloud"),
        )
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_desktop_notification_setup",
            lambda *_args, **_kwargs: side_effects.append("notifications"),
        )

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 0
        assert side_effects == []
        output = capsys.readouterr().out
        assert "usage: hol-guard" in output
        assert "Run `hol-guard --help`" not in output

    def test_plugin_guard_program_routes_directly_to_guard_mode(self, monkeypatch) -> None:
        called: dict[str, object] = {}

        def _fake_run_guard_command(args):
            called["guard_command"] = args.guard_command
            called["harness"] = getattr(args, "harness", None)
            return 7

        monkeypatch.setattr(sys, "argv", ["plugin-guard"])
        monkeypatch.setattr("codex_plugin_scanner.cli.run_guard_command", _fake_run_guard_command)

        rc = main(["hook", "--harness", "pi"])

        assert rc == 7
        assert called == {"guard_command": "hook", "harness": "pi"}
