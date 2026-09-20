"""Guard CLI opencode launch behavior."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.opencode import OpenCodeHarnessAdapter
from tests.guard_cli_fixture_support import _write_json
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_install_keeps_disabled_opencode_servers_disabled(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            workspace_dir / "opencode.json",
            {
                "name": "workspace-opencode",
                "mcp": {
                    "sleep_lab": {
                        "type": "local",
                        "command": ["python3", "sleep-lab.py"],
                        "enabled": False,
                    }
                },
            },
        )

        rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        manifest = output["managed_install"]["manifest"]
        runtime_payload = json.loads(Path(str(manifest["runtime_config_path"])).read_text(encoding="utf-8"))

        assert rc == 0
        assert runtime_payload["mcp"]["sleep_lab"]["enabled"] is False
        assert "sleep_lab_*" not in runtime_payload["permission"]

    def test_guard_install_opencode_preserves_workspace_server_name_collisions(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".config" / "opencode" / "opencode.json",
            {
                "mcp": {
                    "shared_lab": {
                        "type": "local",
                        "command": ["python3", "global-shared.py"],
                    },
                    "global_only_lab": {
                        "type": "local",
                        "command": ["python3", "global-only.py"],
                    },
                }
            },
        )
        _write_json(
            workspace_dir / "opencode.json",
            {
                "name": "workspace-opencode",
                "mcp": {
                    "shared_lab": {
                        "type": "remote",
                        "url": "https://workspace.example/mcp",
                    }
                },
            },
        )

        rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        manifest = output["managed_install"]["manifest"]
        runtime_payload = json.loads(Path(str(manifest["runtime_config_path"])).read_text(encoding="utf-8"))

        assert rc == 0
        assert "shared_lab" not in runtime_payload["mcp"]
        assert "shared_lab_*" not in runtime_payload["permission"]
        assert runtime_payload["mcp"]["global_only_lab"]["type"] == "local"
        assert runtime_payload["permission"]["global_only_lab_*"] == "ask"

    def test_opencode_launch_command_treats_debug_tokens_as_interactive_prompt(self, tmp_path):
        adapter = OpenCodeHarnessAdapter()
        context = HarnessContext(
            home_dir=tmp_path / "home",
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        )

        command = adapter.launch_command(context, ["debug", "oauth"])

        assert command == ["opencode", str(context.workspace_dir), "--prompt", "debug oauth"]
