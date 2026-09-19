"""Guard CLI detect gemini behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from tests.guard_cli_fixture_support import _write_json
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_detect_tolerates_gemini_malformed_args(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".gemini" / "extensions" / "shared" / "gemini-extension.json",
            {
                "name": "shared",
                "mcpServers": {"shared-tools": {"command": "node", "args": True}},
            },
        )
        _write_json(
            home_dir / ".gemini" / "settings.json",
            {
                "mcpServers": {"settings-tools": {"command": "node", "args": True}},
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "gemini",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        detection = output["harnesses"][0]
        artifacts = {item["artifact_id"]: item for item in detection["artifacts"]}

        assert rc == 0
        assert artifacts["gemini:global:shared:shared-tools"]["args"] == []
        assert artifacts["gemini:global:mcp:settings-tools"]["args"] == []

    def test_guard_detect_hashes_full_gemini_hook_lists(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".gemini" / "settings.json",
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "write_file",
                            "hooks": [
                                {"type": "command", "command": "python first-hook.py", "timeout": 5},
                                {"type": "command", "command": "python second-hook.py", "name": "second"},
                            ],
                        }
                    ]
                }
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "gemini",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        hook_artifact = output["harnesses"][0]["artifacts"][0]

        assert rc == 0
        assert hook_artifact["artifact_id"] == "gemini:global:hook:pretooluse:0"
        assert hook_artifact["command"] == "python first-hook.py\npython second-hook.py"
        assert hook_artifact["metadata"]["hook_config"]["matcher"] == "write_file"
        assert hook_artifact["metadata"]["hook_config"]["hooks"][0]["timeout"] == 5
        assert hook_artifact["metadata"]["hook_config"]["hooks"][1]["name"] == "second"
