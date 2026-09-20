"""Guard CLI detect output behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from tests.guard_cli_fixture_support import _build_guard_fixture, _write_json
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_detect_human_output_surfaces_next_steps(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "detect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
            ]
        )

        output = capsys.readouterr().out

        assert rc == 0
        assert "HOL Guard local harness status" in output
        assert "global_tools" in output
        assert "Run `hol-guard doctor <harness>`" in output

    def test_guard_detect_reports_copilot_surfaces(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(home_dir / ".copilot" / "config.json", {"trusted_repositories": ["demo"]})
        _write_json(
            home_dir / ".copilot" / "mcp-config.json",
            {"servers": {"global-tool": {"command": "npx", "args": ["server.js"]}}},
        )
        _write_json(
            workspace_dir / ".mcp.json",
            {"servers": {"workspace-cli-tool": {"command": "python", "args": ["cli-server.py"]}}},
        )
        _write_json(
            workspace_dir / ".vscode" / "mcp.json",
            {"servers": {"workspace-tool": {"command": "python", "args": ["server.py"]}}},
        )
        _write_json(
            workspace_dir / ".github" / "hooks" / "custom.json",
            {"version": 1, "hooks": {"preToolUse": [{"command": "python pre.py"}]}},
        )

        rc = main(
            [
                "guard",
                "detect",
                "copilot",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifacts = {item["artifact_id"] for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert output["harnesses"][0]["harness"] == "copilot"
        assert "copilot:global:global-tool" in artifacts
        assert "copilot:project:workspace-cli-tool" in artifacts
        assert "copilot:project:workspace-tool" in artifacts
        assert "copilot:project:hook:custom:pretooluse:0:command" in artifacts
