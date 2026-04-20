"""Behavior tests for the Guard CLI surface."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters import cursor as cursor_adapter_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.opencode import OpenCodeHarnessAdapter
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.cli import connect_flow as guard_connect_flow_module
from codex_plugin_scanner.guard.cli import update_commands as guard_update_commands_module
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore

FIXTURES = Path(__file__).parent / "fixtures"


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _build_guard_fixture(home_dir: Path, workspace_dir: Path) -> None:
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
approval_policy = "never"

[mcp_servers.global_tools]
command = "python"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
""".strip()
        + "\n",
    )

    _write_json(
        home_dir / ".claude" / "settings.json",
        {
            "allowedMcpServers": ["global-tools"],
            "hooks": {"PreToolUse": [{"command": "python guard-pre.py"}]},
        },
    )
    _write_json(
        workspace_dir / ".mcp.json",
        {
            "mcpServers": {
                "workspace-tools": {"command": "python", "args": ["-m", "http.server", "9100"]},
            }
        },
    )
    _write_text(workspace_dir / ".claude" / "agents" / "reviewer.md", "# reviewer\n")

    _write_json(
        home_dir / ".cursor" / "mcp.json",
        {
            "mcpServers": {
                "cursor-browser": {"command": "npx", "args": ["@browser/mcp"]},
            }
        },
    )

    _write_json(
        home_dir / "Library" / "Application Support" / "Antigravity" / "User" / "settings.json",
        {
            "workbench.colorTheme": "Default Dark+",
        },
    )
    antigravity_extension_root = home_dir / ".antigravity" / "extensions" / "hashgraph.antigravity-tools-1.0.0"
    _write_json(
        home_dir / ".antigravity" / "extensions" / "extensions.json",
        [
            {
                "identifier": {"id": "hashgraph.antigravity-tools"},
                "location": {"path": str(antigravity_extension_root)},
                "metadata": {"publisherDisplayName": "Hashgraph"},
            }
        ],
    )
    _write_json(
        antigravity_extension_root / "package.json",
        {
            "name": "antigravity-tools",
            "publisher": "hashgraph",
            "displayName": "Antigravity Tools",
        },
    )
    _write_json(
        home_dir / ".gemini" / "antigravity" / "mcp_config.json",
        {
            "mcpServers": {
                "gravity-tools": {"command": "node", "args": ["gravity.js"]},
            }
        },
    )
    _write_text(
        home_dir / ".gemini" / "antigravity" / "skills" / "gravity-review" / "SKILL.md",
        "---\nname: gravity-review\ndescription: Gravity skill\n---\n",
    )

    _write_json(
        home_dir / ".gemini" / "settings.json",
        {
            "mcpServers": {
                "gemini-tools": {"command": "node", "args": ["gemini.js"]},
            },
            "hooks": {
                "PreToolUse": [
                    {
                        "hooks": [{"type": "command", "command": "python global-gemini-hook.py"}],
                    }
                ]
            },
        },
    )
    _write_text(
        home_dir / ".gemini" / "skills" / "gemini-review" / "SKILL.md",
        "---\nname: gemini-review\ndescription: Gemini skill\n---\n",
    )
    _write_json(
        home_dir / ".gemini" / "extensions" / "hashnet" / "gemini-extension.json",
        {
            "name": "hashnet",
            "version": "1.0.0",
            "description": "Hashnet extension",
            "mcpServers": {"hashnet": {"command": "node", "args": ["server.js"]}},
            "contextFileName": "GEMINI.md",
        },
    )
    _write_text(home_dir / ".gemini" / "extensions" / "hashnet" / "GEMINI.md", "context\n")
    _write_json(
        workspace_dir / ".gemini" / "settings.json",
        {
            "mcpServers": {
                "workspace-gemini": {"command": "node", "args": ["workspace-gemini.js"]},
            },
            "hooks": {
                "PreToolUse": [
                    {
                        "hooks": [{"type": "command", "command": "python workspace-gemini-hook.py"}],
                    }
                ]
            },
        },
    )
    _write_text(
        workspace_dir / ".gemini" / "skills" / "workspace-review" / "SKILL.md",
        "---\nname: workspace-review\ndescription: Workspace Gemini skill\n---\n",
    )

    _write_json(
        home_dir / ".config" / "opencode" / "opencode.json",
        {
            "mcp": {
                "playwright": {
                    "type": "local",
                    "command": ["pnpm", "dlx", "@playwright/mcp@latest"],
                    "enabled": True,
                }
            }
        },
    )
    _write_json(
        workspace_dir / "opencode.json",
        {
            "name": "workspace-opencode",
            "mcp": {"workspace": {"type": "local", "command": ["node", "server.js"]}},
        },
    )
    _write_text(workspace_dir / ".opencode" / "commands" / "triage.md", "# triage\n")


class _SyncRequestHandler(BaseHTTPRequestHandler):
    response_code = 200
    captured_headers: ClassVar[dict[str, str]] = {}
    captured_body: ClassVar[dict[str, object] | None] = None
    raw_response_body: ClassVar[str | None] = None
    response_payload: ClassVar[dict[str, object]] = {
        "syncedAt": "2026-04-09T00:00:00Z",
        "receiptsStored": 1,
    }

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        _SyncRequestHandler.captured_headers = {key.lower(): value for key, value in self.headers.items()}
        _SyncRequestHandler.captured_body = json.loads(body)
        self.send_response(self.response_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response_body = _SyncRequestHandler.raw_response_body
        if response_body is None:
            response_body = json.dumps(_SyncRequestHandler.response_payload)
        self.wfile.write(response_body.encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:
        return


class TestGuardCli:
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

    def test_root_guard_missing_subcommand_points_to_root_help(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["hol-guard"])

        with pytest.raises(SystemExit) as exc_info:
            main([])

        assert exc_info.value.code == 2
        assert "Run `hol-guard --help` to inspect available Guard commands." in capsys.readouterr().err

    def test_guard_detect_reports_supported_harnesses(self, tmp_path, capsys):
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
                "--json",
            ]
        )

        output = json.loads(capsys.readouterr().out)
        harnesses = {item["harness"]: item for item in output["harnesses"]}

        assert rc == 0
        assert {"codex", "claude-code", "cursor", "antigravity", "gemini", "opencode"} <= harnesses.keys()
        assert harnesses["codex"]["artifacts"][0]["source_scope"] == "global"
        assert harnesses["claude-code"]["artifacts"][0]["artifact_type"] in {"mcp_server", "hook", "agent"}

    def test_guard_detect_scopes_codex_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_text(
            home_dir / ".codex" / "config.toml",
            """
[mcp_servers.shared_tools]
command = "python"
args = ["-m", "http.server", "9000"]
""".strip()
            + "\n",
        )
        _write_text(
            workspace_dir / ".codex" / "config.toml",
            """
[mcp_servers.shared_tools]
command = "node"
args = ["workspace-skill.js"]
""".strip()
            + "\n",
        )

        rc = main(
            [
                "guard",
                "detect",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifact_ids = [item["artifact_id"] for item in output["harnesses"][0]["artifacts"]]

        assert rc == 0
        assert artifact_ids == ["codex:global:shared_tools", "codex:project:shared_tools"]

    def test_guard_detect_scopes_claude_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".claude" / "settings.json",
            {
                "mcpServers": {
                    "shared-tools": {"command": "python", "args": ["-m", "http.server", "9000"]},
                }
            },
        )
        _write_json(
            workspace_dir / ".mcp.json",
            {
                "mcpServers": {
                    "shared-tools": {"command": "node", "args": ["workspace.js"]},
                }
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "claude-code",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifact_ids = [item["artifact_id"] for item in output["harnesses"][0]["artifacts"]]

        assert rc == 0
        assert artifact_ids == ["claude-code:global:shared-tools", "claude-code:project:shared-tools"]

    def test_guard_detect_scopes_claude_hook_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".claude" / "settings.json",
            {
                "hooks": {
                    "PreToolUse": [{"command": "python global-hook.py"}],
                }
            },
        )
        _write_json(
            workspace_dir / ".claude" / "settings.local.json",
            {
                "hooks": {
                    "PreToolUse": [{"command": "python project-hook.py"}],
                }
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "claude-code",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifact_ids = [item["artifact_id"] for item in output["harnesses"][0]["artifacts"]]

        assert rc == 0
        assert artifact_ids == [
            "claude-code:global:pretooluse:0",
            "claude-code:project:pretooluse:0",
        ]

    def test_guard_detect_scopes_cursor_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".cursor" / "mcp.json",
            {
                "mcpServers": {
                    "shared-tools": {"command": "npx", "args": ["global-server"]},
                }
            },
        )
        _write_json(
            workspace_dir / ".cursor" / "mcp.json",
            {
                "mcpServers": {
                    "shared-tools": {"command": "npx", "args": ["project-server"]},
                }
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "cursor",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifact_ids = [item["artifact_id"] for item in output["harnesses"][0]["artifacts"]]

        assert rc == 0
        assert artifact_ids == ["cursor:global:shared-tools", "cursor:project:shared-tools"]

    def test_guard_detect_scopes_gemini_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".gemini" / "settings.json",
            {
                "mcpServers": {
                    "shared-settings": {"command": "node", "args": ["global-settings.js"]},
                },
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [{"type": "command", "command": "python global-hook.py"}],
                        }
                    ]
                },
            },
        )
        _write_text(
            home_dir / ".gemini" / "skills" / "shared-skill" / "SKILL.md",
            "---\nname: shared-skill\ndescription: Global Gemini skill\n---\n",
        )
        _write_json(
            home_dir / ".gemini" / "extensions" / "shared" / "gemini-extension.json",
            {
                "name": "shared",
                "mcpServers": {"shared-tools": {"command": "node", "args": ["global.js"]}},
            },
        )
        _write_json(
            home_dir / ".gemini" / "antigravity" / "mcp_config.json",
            {
                "mcpServers": {
                    "should-belong-to-antigravity": {"command": "node", "args": ["antigravity.js"]},
                }
            },
        )
        _write_json(
            workspace_dir / ".gemini" / "settings.json",
            {
                "mcpServers": {
                    "shared-settings": {"command": "node", "args": ["project-settings.js"]},
                },
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [{"type": "command", "command": "python project-hook.py"}],
                        }
                    ]
                },
            },
        )
        _write_text(
            workspace_dir / ".gemini" / "skills" / "shared-skill" / "SKILL.md",
            "---\nname: shared-skill\ndescription: Project Gemini skill\n---\n",
        )
        _write_json(
            workspace_dir / ".gemini" / "extensions" / "shared" / "gemini-extension.json",
            {
                "name": "shared",
                "mcpServers": {"shared-tools": {"command": "node", "args": ["project.js"]}},
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
        artifact_ids = [item["artifact_id"] for item in output["harnesses"][0]["artifacts"]]

        assert rc == 0
        assert artifact_ids == [
            "gemini:global:shared",
            "gemini:global:shared:shared-tools",
            "gemini:global:mcp:shared-settings",
            "gemini:global:hook:pretooluse:0",
            "gemini:global:skill:skills/shared-skill",
            "gemini:project:shared",
            "gemini:project:shared:shared-tools",
            "gemini:project:mcp:shared-settings",
            "gemini:project:hook:pretooluse:0",
            "gemini:project:skill:skills/shared-skill",
        ]

    def test_guard_detect_reports_antigravity_extensions_skills_and_mcp(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        antigravity_extension_root = home_dir / ".antigravity" / "extensions" / "hashgraph.tools-1.0.0"
        _write_json(
            home_dir / "Library" / "Application Support" / "Antigravity" / "User" / "settings.json",
            {"workbench.colorTheme": "Solarized Dark"},
        )
        _write_json(
            home_dir / ".antigravity" / "extensions" / "extensions.json",
            [
                {
                    "identifier": {"id": "hashgraph.tools"},
                    "location": {"path": str(antigravity_extension_root)},
                    "metadata": {"publisherDisplayName": "Hashgraph"},
                }
            ],
        )
        _write_json(
            antigravity_extension_root / "package.json",
            {"name": "tools", "publisher": "hashgraph", "displayName": "Hashgraph Tools"},
        )
        _write_json(
            home_dir / ".gemini" / "antigravity" / "mcp_config.json",
            {
                "mcpServers": {
                    "gravity-tools": {"command": "node", "args": ["gravity.js"]},
                }
            },
        )
        _write_text(
            home_dir / ".gemini" / "antigravity" / "skills" / "gravity-review" / "SKILL.md",
            "---\nname: gravity-review\ndescription: Gravity review skill\n---\n",
        )

        rc = main(
            [
                "guard",
                "detect",
                "antigravity",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        detection = output["harnesses"][0]
        artifact_ids = [item["artifact_id"] for item in detection["artifacts"]]

        assert rc == 0
        assert (
            str(home_dir / "Library" / "Application Support" / "Antigravity" / "User" / "settings.json")
            in (detection["config_paths"])
        )
        assert str(home_dir / ".gemini" / "antigravity" / "mcp_config.json") in detection["config_paths"]
        assert artifact_ids == [
            "antigravity:global:hashgraph.tools",
            "antigravity:global:mcp:bridge:gravity-tools",
            "antigravity:global:skill:skills/gravity-review",
        ]

    def test_guard_detect_recognizes_cross_platform_antigravity_settings(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".config" / "Antigravity" / "User" / "settings.json",
            {
                "antigravity.profile": "default",
                "mcpServers": {"gravity-tools": {"command": "node", "args": True}},
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "antigravity",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        detection = output["harnesses"][0]

        assert rc == 0
        assert str(home_dir / ".config" / "Antigravity" / "User" / "settings.json") in detection["config_paths"]
        assert [item["artifact_id"] for item in detection["artifacts"]] == [
            "antigravity:global:mcp:settings:xdg-user:gravity-tools"
        ]
        assert detection["artifacts"][0]["args"] == []

    def test_guard_detect_ignores_generic_workspace_vscode_settings_without_antigravity_ownership(
        self,
        tmp_path,
        capsys,
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            workspace_dir / ".vscode" / "settings.json",
            {
                "workbench.colorTheme": "Default Dark+",
                "mcpServers": {"generic-tools": {"command": "node", "args": ["generic.js"]}},
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "antigravity",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        detection = output["harnesses"][0]

        assert rc == 0
        assert detection["config_paths"] == []
        assert detection["artifacts"] == []

    def test_guard_detect_includes_workspace_vscode_settings_after_antigravity_ownership(
        self,
        tmp_path,
        capsys,
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".config" / "Antigravity" / "User" / "settings.json",
            {
                "antigravity.profile": "default",
            },
        )
        _write_json(
            workspace_dir / ".vscode" / "settings.json",
            {
                "workbench.colorTheme": "Default Dark+",
                "mcpServers": {"workspace-tools": {"command": "node", "args": ["workspace.js"]}},
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "antigravity",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        detection = output["harnesses"][0]
        artifact_ids = [item["artifact_id"] for item in detection["artifacts"]]

        assert rc == 0
        assert str(home_dir / ".config" / "Antigravity" / "User" / "settings.json") in detection["config_paths"]
        assert str(workspace_dir / ".vscode" / "settings.json") in detection["config_paths"]
        assert artifact_ids == ["antigravity:project:mcp:settings:workspace-vscode:workspace-tools"]

    def test_guard_detect_disambiguates_antigravity_mcp_sources(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / "Library" / "Application Support" / "Antigravity" / "User" / "settings.json",
            {
                "antigravity.profile": "default",
                "mcpServers": {"shared-tools": {"command": "node", "args": ["settings.js"]}},
            },
        )
        _write_json(
            home_dir / ".gemini" / "antigravity" / "mcp_config.json",
            {
                "mcpServers": {"shared-tools": {"command": "node", "args": ["bridge.js"]}},
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "antigravity",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifact_ids = [item["artifact_id"] for item in output["harnesses"][0]["artifacts"]]

        assert rc == 0
        assert artifact_ids == [
            "antigravity:global:mcp:bridge:shared-tools",
            "antigravity:global:mcp:settings:macos-user:shared-tools",
        ]

    def test_guard_detect_disambiguates_antigravity_settings_paths_with_same_server_name(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / "Library" / "Application Support" / "Antigravity" / "User" / "settings.json",
            {
                "antigravity.profile": "default",
                "mcpServers": {"shared-tools": {"command": "node", "args": ["macos.js"]}},
            },
        )
        _write_json(
            home_dir / ".config" / "Antigravity" / "User" / "settings.json",
            {
                "antigravity.profile": "default",
                "mcpServers": {"shared-tools": {"command": "node", "args": ["linux.js"]}},
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "antigravity",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifact_ids = [item["artifact_id"] for item in output["harnesses"][0]["artifacts"]]

        assert rc == 0
        assert artifact_ids == [
            "antigravity:global:mcp:settings:macos-user:shared-tools",
            "antigravity:global:mcp:settings:xdg-user:shared-tools",
        ]

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

    def test_guard_detect_scopes_opencode_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".config" / "opencode" / "opencode.json",
            {
                "mcp": {
                    "shared-tools": {"type": "local", "command": ["node", "global.js"]},
                }
            },
        )
        _write_json(
            workspace_dir / "opencode.json",
            {
                "mcp": {
                    "shared-tools": {"type": "local", "command": ["node", "project.js"]},
                }
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifact_ids = [item["artifact_id"] for item in output["harnesses"][0]["artifacts"]]

        assert rc == 0
        assert artifact_ids == ["opencode:global:shared-tools", "opencode:project:shared-tools"]

    def test_guard_detect_reports_opencode_plugins_skills_and_commands(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".config" / "opencode" / "opencode.json",
            {
                "plugins": [["opencode-global-plugin", {"mode": "strict", "token": "top-secret"}]],
                "command": {
                    "global-review": {
                        "template": "Review the current diff.",
                        "description": "Global review command",
                    }
                },
            },
        )
        _write_json(
            workspace_dir / "opencode.json",
            {
                "plugins": ["opencode-project-plugin"],
                "command": {
                    "project-review": {
                        "template": "Review the workspace change set.",
                        "description": "Project review command",
                    }
                },
            },
        )
        _write_text(home_dir / ".config" / "opencode" / "plugins" / "global-local.mjs", "export default {};\n")
        _write_text(workspace_dir / ".opencode" / "plugins" / "project-local.mjs", "export default {};\n")
        _write_text(home_dir / ".config" / "opencode" / "commands" / "global-cmd.md", "# global\n")
        _write_text(workspace_dir / ".opencode" / "commands" / "triage.md", "# triage\n")
        _write_text(
            home_dir / ".config" / "opencode" / "skills" / "global-skill" / "SKILL.md",
            "---\nname: global-skill\ndescription: Global skill\n---\n",
        )
        _write_text(
            workspace_dir / ".opencode" / "skills" / "repo-skill" / "SKILL.md",
            "---\nname: repo-skill\ndescription: Repo skill\n---\n",
        )
        _write_text(
            workspace_dir / ".claude" / "skills" / "claude-skill" / "SKILL.md",
            "---\nname: claude-skill\ndescription: Claude-compatible skill\n---\n",
        )

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifacts = {item["artifact_id"]: item for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert "opencode:global:plugin:opencode-global-plugin" in artifacts
        assert "opencode:project:plugin:opencode-project-plugin" in artifacts
        assert "opencode:global:plugin-file:plugins/global-local.mjs" in artifacts
        assert "opencode:project:plugin-file:plugins/project-local.mjs" in artifacts
        assert "opencode:global:config-command:global-review" in artifacts
        assert "opencode:project:config-command:project-review" in artifacts
        assert "opencode:global:command:global-cmd" in artifacts
        assert "opencode:project:command:triage" in artifacts
        assert "opencode:global:skill:opencode:skills/global-skill" in artifacts
        assert "opencode:project:skill:opencode:skills/repo-skill" in artifacts
        assert "opencode:project:skill:claude:skills/claude-skill" in artifacts
        assert artifacts["opencode:project:plugin-file:plugins/project-local.mjs"]["artifact_type"] == "plugin"
        assert artifacts["opencode:project:config-command:project-review"]["metadata"]["template"] == (
            "Review the workspace change set."
        )
        assert artifacts["opencode:global:plugin:opencode-global-plugin"]["metadata"]["mode"] == "strict"
        assert artifacts["opencode:global:plugin:opencode-global-plugin"]["metadata"]["token"] == "*****"
        assert artifacts["opencode:project:skill:claude:skills/claude-skill"]["artifact_type"] == "skill"

    def test_guard_detect_keeps_unique_opencode_file_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(workspace_dir / "opencode.json", {})
        _write_text(workspace_dir / ".opencode" / "plugin" / "shared.js", "export default {};\n")
        _write_text(workspace_dir / ".opencode" / "plugins" / "shared.mjs", "export default {};\n")
        _write_text(workspace_dir / ".opencode" / "plugins" / "nested" / "shared.mjs", "export default {};\n")
        _write_text(workspace_dir / ".opencode" / "skill" / "shared" / "SKILL.md", "---\nname: shared\n---\n")
        _write_text(
            workspace_dir / ".opencode" / "skills" / "nested" / "shared" / "SKILL.md",
            "---\nname: shared\n---\n",
        )

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifact_ids = {item["artifact_id"] for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert "opencode:project:plugin-file:plugin/shared.js" in artifact_ids
        assert "opencode:project:plugin-file:plugins/shared.mjs" in artifact_ids
        assert "opencode:project:plugin-file:plugins/nested/shared.mjs" in artifact_ids
        assert "opencode:project:skill:opencode:skill/shared" in artifact_ids
        assert "opencode:project:skill:opencode:skills/nested/shared" in artifact_ids

    def test_guard_detect_reads_opencode_config_from_environment_override(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_path = workspace_dir / "custom" / "guard-opencode.json"
        _write_json(custom_config_path, {"plugins": ["env-plugin"]})
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom_config_path))

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        detection = output["harnesses"][0]
        artifact_ids = [item["artifact_id"] for item in detection["artifacts"]]

        assert rc == 0
        assert "opencode:project:plugin:env-plugin" in artifact_ids
        assert str(custom_config_path) in detection["config_paths"]

    def test_guard_detect_prefers_project_opencode_config_over_environment_override(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_path = workspace_dir / "custom" / "guard-opencode.json"
        _write_json(custom_config_path, {"plugins": [["shared-plugin", {"mode": "custom"}]]})
        _write_json(workspace_dir / "opencode.json", {"plugins": [["shared-plugin", {"mode": "project"}]]})
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom_config_path))

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifacts = {item["artifact_id"]: item for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert artifacts["opencode:project:plugin:shared-plugin"]["metadata"]["mode"] == "project"

    def test_guard_detect_reads_opencode_config_dir_from_environment_override(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_dir = workspace_dir / "custom-dir"
        _write_text(custom_config_dir / "plugins" / "env-plugin.mjs", "export default {};\n")
        _write_text(custom_config_dir / "commands" / "env-command.md", "# env command\n")
        monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(custom_config_dir))

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifact_ids = {item["artifact_id"] for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert "opencode:project:plugin-file:plugins/env-plugin.mjs" in artifact_ids
        assert "opencode:project:command:env-command" in artifact_ids

    def test_guard_detect_prefers_opencode_environment_config_over_global_config(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_path = workspace_dir / "custom" / "guard-opencode.json"
        _write_json(
            home_dir / ".config" / "opencode" / "opencode.json",
            {"plugins": [["shared-plugin", {"mode": "global"}]]},
        )
        _write_json(custom_config_path, {"plugins": [["shared-plugin", {"mode": "custom"}]]})
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom_config_path))

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifacts = {item["artifact_id"]: item for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert artifacts["opencode:project:plugin:shared-plugin"]["metadata"]["mode"] == "custom"

    def test_guard_detect_prefers_opencode_config_dir_over_default_plugin_file(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_dir = workspace_dir / "custom-dir"
        _write_json(workspace_dir / "opencode.json", {})
        _write_text(workspace_dir / ".opencode" / "plugins" / "shared.mjs", "export default { name: 'default' };\n")
        _write_text(custom_config_dir / "plugins" / "shared.mjs", "export default { name: 'override' };\n")
        monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(custom_config_dir))

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifacts = {item["artifact_id"]: item for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert artifacts["opencode:project:plugin-file:plugins/shared.mjs"]["config_path"] == str(
            custom_config_dir / "plugins" / "shared.mjs"
        )

    def test_guard_detect_handles_unreadable_opencode_plugin_files(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(workspace_dir / "opencode.json", {})
        _write_text(workspace_dir / ".opencode" / "plugins" / "broken.mjs", "export default {};\n")
        original_read_bytes = Path.read_bytes

        def _patched_read_bytes(path: Path) -> bytes:
            if path.name == "broken.mjs":
                raise OSError("Permission denied")
            return original_read_bytes(path)

        monkeypatch.setattr(Path, "read_bytes", _patched_read_bytes)

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifacts = {item["artifact_id"]: item for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert (
            artifacts["opencode:project:plugin-file:plugins/broken.mjs"]["metadata"]["content_digest_unavailable"]
            is True
        )

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

    def test_guard_scan_emits_consumer_contract(self, capsys):
        rc = main(
            [
                "guard",
                "scan",
                str(FIXTURES / "good-plugin"),
                "--consumer-mode",
                "--json",
            ]
        )

        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["artifact_snapshot"]["artifact_hash"]
        assert output["capability_manifest"]["ecosystems"] == ["codex"]
        assert output["policy_recommendation"]["action"] in {"allow", "review", "block"}
        assert "trust_evidence_bundle" in output
        assert "provenance_record" in output

    def test_guard_scan_human_output_shows_artifact_path(self, capsys):
        rc = main(
            [
                "guard",
                "scan",
                str(FIXTURES / "good-plugin"),
                "--consumer-mode",
                "--json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)

        emit_guard_payload("scan", payload, as_json=False)
        output = capsys.readouterr().out

        assert rc == 0
        assert "Consumer scan" in output
        assert "Artifact" in output
        assert "good-plugin" in output
        assert "Recommended action" in output
        assert '"policy_recommendation"' not in output

    def test_guard_run_persists_receipts_and_policy(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')

        rc = main(
            [
                "guard",
                "allow",
                "codex",
                "--artifact-id",
                "codex:project:workspace_skill",
                "--scope",
                "artifact",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        assert rc == 0
        json.loads(capsys.readouterr().out)

        rc = main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--dry-run",
                "--json",
            ]
        )
        run_output = json.loads(capsys.readouterr().out)

        receipts_rc = main(
            [
                "guard",
                "receipts",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        receipts_output = json.loads(capsys.readouterr().out)

        assert run_output["blocked"] is False
        assert run_output["receipts_recorded"] >= 1
        assert receipts_rc == 0
        assert receipts_output["items"][0]["harness"] == "codex"

    def test_guard_receipts_human_output_renders_table(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--dry-run",
                "--default-action",
                "allow",
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        rc = main(["guard", "receipts", "--home", str(home_dir)])
        output = capsys.readouterr().out

        assert rc == 0
        assert "Recent Guard receipts" in output

    def test_guard_allow_supports_expiring_exception(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "allow",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--scope",
                "artifact",
                "--artifact-id",
                "codex:project:workspace_skill",
                "--expires-in-hours",
                "4",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["decision"]["scope"] == "artifact"
        assert output["decision"]["expires_at"].endswith("+00:00")
        assert output["decision"]["source"] == "local"

    def test_guard_preflight_enforce_returns_nonzero_for_non_allow_verdict(self, tmp_path, capsys, monkeypatch):
        target = tmp_path / "incoming-plugin"
        target.mkdir(parents=True)
        payload = {
            "schema_version": "guard-consumer.v2",
            "generated_at": "2026-04-11T00:00:00+00:00",
            "install_target": {
                "path": str(target),
                "intended_harness": "codex",
            },
            "artifact_snapshot": {
                "path": str(target),
                "artifact_hash": "abc123",
            },
            "capability_manifest": {
                "ecosystems": ["codex"],
                "packages": [],
                "category_names": ["Security"],
            },
            "artifact_diff": {
                "changed": False,
                "changed_fields": [],
            },
            "provenance_record": {
                "scope": "plugin",
                "plugin_dir": str(target),
                "trust_score": None,
            },
            "trust_evidence_bundle": {
                "findings": ["Posts environment secrets to a remote host."],
                "severity_counts": {"critical": 1},
                "integrations": [],
            },
            "policy_recommendation": {
                "action": "review",
                "reason": "Install-time scan found risky network and secret access behavior.",
            },
            "install_verdict": {
                "action": "review",
                "reason": "Install-time scan found risky network and secret access behavior.",
                "can_install": False,
            },
            "abom_entry": {
                "artifact_id": "preflight:incoming-plugin",
                "artifact_type": "plugin",
            },
            "threat_intelligence": {
                "verdict_source": "local-scan",
                "highest_severity": "critical",
            },
        }
        monkeypatch.setattr(
            guard_commands_module,
            "run_consumer_scan",
            lambda path, intended_harness=None, options=None: payload,
        )

        rc = main(
            [
                "guard",
                "preflight",
                str(target),
                "--harness",
                "codex",
                "--enforce",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["install_verdict"]["action"] == "review"
        assert output["install_target"]["intended_harness"] == "codex"
        assert output["threat_intelligence"]["verdict_source"] == "local-scan"

    def test_guard_preflight_human_output_stays_summary_first(self, tmp_path, capsys, monkeypatch):
        target = tmp_path / "incoming-plugin"
        target.mkdir(parents=True)
        payload = {
            "schema_version": "guard-consumer.v2",
            "generated_at": "2026-04-11T00:00:00+00:00",
            "install_target": {
                "path": str(target),
                "intended_harness": "codex",
            },
            "artifact_snapshot": {
                "path": str(target),
                "artifact_hash": "abc123",
            },
            "capability_manifest": {
                "ecosystems": ["codex"],
                "packages": [],
                "category_names": ["Security"],
            },
            "artifact_diff": {
                "changed": False,
                "changed_fields": [],
            },
            "provenance_record": {
                "scope": "plugin",
                "plugin_dir": str(target),
                "trust_score": None,
            },
            "trust_evidence_bundle": {
                "findings": ["Posts environment secrets to a remote host."],
                "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
                "integrations": [],
            },
            "policy_recommendation": {
                "action": "review",
                "reason": "Install-time scan found risky network and secret access behavior.",
            },
            "install_verdict": {
                "action": "review",
                "reason": "Install-time scan found risky network and secret access behavior.",
                "can_install": False,
            },
            "abom_entry": {
                "artifact_id": "preflight:incoming-plugin",
                "artifact_type": "plugin",
            },
            "threat_intelligence": {
                "verdict_source": "local-scan",
                "highest_severity": "critical",
                "finding_count": 1,
            },
        }
        monkeypatch.setattr(
            guard_commands_module,
            "run_consumer_scan",
            lambda path, intended_harness=None, options=None: payload,
        )

        rc = main(
            [
                "guard",
                "preflight",
                str(target),
                "--harness",
                "codex",
            ]
        )
        output = capsys.readouterr().out

        assert rc == 0
        assert "Install-time preflight" in output
        assert "Install verdict" in output
        assert "Highest severity" in output
        assert '"install_verdict"' not in output

    def test_guard_policies_and_exceptions_show_persisted_rules(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        allow_rc = main(
            [
                "guard",
                "allow",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--scope",
                "artifact",
                "--artifact-id",
                "codex:project:workspace_skill",
                "--expires-in-hours",
                "2",
                "--owner",
                "local-dev",
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)
        deny_rc = main(
            [
                "guard",
                "deny",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--scope",
                "publisher",
                "--publisher",
                "hashgraph-online",
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        policies_rc = main(["guard", "policies", "--home", str(home_dir), "--json"])
        policies_output = json.loads(capsys.readouterr().out)
        exceptions_rc = main(["guard", "exceptions", "--home", str(home_dir), "--json"])
        exceptions_output = json.loads(capsys.readouterr().out)

        assert allow_rc == 0
        assert deny_rc == 0
        assert policies_rc == 0
        assert exceptions_rc == 0
        assert len(policies_output["items"]) == 2
        assert {item["scope"] for item in policies_output["items"]} == {"artifact", "publisher"}
        assert exceptions_output["items"][0]["artifact_id"] == "codex:project:workspace_skill"
        assert exceptions_output["items"][0]["owner"] == "local-dev"
        assert exceptions_output["items"][0]["expires_at"].endswith("+00:00")

    def test_guard_inventory_and_abom_export_local_artifacts(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        run_rc = main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--dry-run",
                "--default-action",
                "allow",
                "--json",
            ]
        )
        run_output = json.loads(capsys.readouterr().out)

        inventory_rc = main(
            [
                "guard",
                "inventory",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        inventory_output = json.loads(capsys.readouterr().out)

        abom_rc = main(
            [
                "guard",
                "abom",
                "--home",
                str(home_dir),
                "--format",
                "json",
                "--json",
            ]
        )
        abom_output = json.loads(capsys.readouterr().out)

        assert run_rc == 0
        assert run_output["blocked"] is False
        assert inventory_rc == 0
        assert inventory_output["items"][0]["artifact_id"] == "codex:global:global_tools"
        assert inventory_output["items"][0]["present"] is True
        assert inventory_output["items"][0]["last_policy_action"] == "allow"
        assert inventory_output["items"][0]["first_seen_at"].endswith("+00:00")
        assert abom_rc == 0
        assert abom_output["artifacts"][0]["artifact_id"] == "codex:global:global_tools"
        assert abom_output["artifacts"][0]["trust_verdict"] == "allow"

    def test_guard_explain_uses_tracked_artifact_context(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        run_rc = main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--dry-run",
                "--default-action",
                "allow",
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        explain_rc = main(
            [
                "guard",
                "explain",
                "codex:project:workspace_skill",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        explain_output = json.loads(capsys.readouterr().out)

        assert run_rc == 0
        assert explain_rc == 0
        assert explain_output["artifact"]["artifact_id"] == "codex:project:workspace_skill"
        assert explain_output["latest_receipt"]["policy_decision"] == "allow"
        assert explain_output["latest_diff"]["current_hash"]

    def test_guard_diff_reports_config_changes(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')

        first_run = main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--dry-run",
                "--default-action",
                "allow",
                "--json",
            ]
        )
        assert first_run == 0
        json.loads(capsys.readouterr().out)

        _write_text(home_dir / "config.toml", 'changed_hash_action = "require-reapproval"\n')

        _write_text(
            workspace_dir / ".codex" / "config.toml",
            """
[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js", "--changed"]
""".strip()
            + "\n",
        )

        rc = main(
            [
                "guard",
                "diff",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["changed"] is True
        assert output["artifacts"][0]["changed_fields"]

        rerun_rc = main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--dry-run",
                "--default-action",
                "allow",
                "--json",
            ]
        )
        rerun_output = json.loads(capsys.readouterr().out)

        assert rerun_rc == 1
        assert rerun_output["blocked"] is True
        assert any(item["policy_action"] == "require-reapproval" for item in rerun_output["artifacts"])
        assert any(item["changed"] is True for item in rerun_output["artifacts"])

    def test_guard_run_returns_launched_harness_exit_code(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        monkeypatch.setattr(
            guard_commands_module,
            "guard_run",
            lambda *args, **kwargs: {
                "harness": "codex",
                "artifacts": [],
                "blocked": False,
                "receipts_recorded": 0,
                "launched": True,
                "return_code": 7,
            },
        )

        rc = main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert output["return_code"] == 7
        assert rc == 7

    def test_guard_allow_requires_publisher_for_publisher_scope(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "guard",
                    "allow",
                    "gemini",
                    "--scope",
                    "publisher",
                    "--home",
                    str(home_dir),
                    "--workspace",
                    str(workspace_dir),
                    "--json",
                ]
            )

        assert excinfo.value.code == 2
        assert "--publisher is required when --scope publisher" in capsys.readouterr().err

    def test_guard_allow_persists_publisher_scope(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "allow",
                "gemini",
                "--scope",
                "publisher",
                "--publisher",
                "hashgraph-online",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["decision"]["scope"] == "publisher"
        assert output["decision"]["publisher"] == "hashgraph-online"

    def test_guard_allow_requires_artifact_id_for_artifact_scope(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "guard",
                    "allow",
                    "codex",
                    "--scope",
                    "artifact",
                    "--home",
                    str(home_dir),
                    "--workspace",
                    str(workspace_dir),
                    "--json",
                ]
            )

        assert excinfo.value.code == 2
        assert "--artifact-id is required when --scope artifact" in capsys.readouterr().err

    def test_guard_allow_requires_workspace_for_workspace_scope(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "guard",
                    "allow",
                    "codex",
                    "--scope",
                    "workspace",
                    "--home",
                    str(home_dir),
                    "--json",
                ]
            )

        assert excinfo.value.code == 2
        assert "--workspace is required when --scope workspace" in capsys.readouterr().err

    def test_guard_harness_policy_overrides_across_workspaces(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_one = tmp_path / "workspace-one"
        workspace_two = tmp_path / "workspace-two"
        _build_guard_fixture(home_dir, workspace_one)
        _build_guard_fixture(home_dir, workspace_two)

        first_rc = main(
            [
                "guard",
                "allow",
                "codex",
                "--scope",
                "harness",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_one),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        second_rc = main(
            [
                "guard",
                "deny",
                "codex",
                "--scope",
                "harness",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_two),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        receipts_rc = main(["guard", "receipts", "--home", str(home_dir), "--json"])
        json.loads(capsys.readouterr().out)

        assert first_rc == 0
        assert second_rc == 0
        assert receipts_rc == 0

        run_rc = main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_one),
                "--dry-run",
                "--json",
            ]
        )
        run_output = json.loads(capsys.readouterr().out)

        assert run_rc == 1
        assert any(item["policy_action"] == "block" for item in run_output["artifacts"])

    def test_guard_install_and_uninstall_manage_claude_hooks(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

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
        install_output = json.loads(capsys.readouterr().out)
        settings_local = workspace_dir / ".claude" / "settings.local.json"
        install_settings_payload = json.loads(settings_local.read_text(encoding="utf-8"))

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
        settings_payload = json.loads(settings_local.read_text(encoding="utf-8"))

        assert install_rc == 0
        assert install_output["managed_install"]["active"] is True
        assert settings_local.exists()
        assert len(install_settings_payload["hooks"]["PreToolUse"]) == 1
        assert install_output["managed_install"]["manifest"]["notes"][0]
        expected_hook_command = ClaudeCodeHarnessAdapter._hook_command(
            HarnessContext(
                home_dir=home_dir,
                workspace_dir=workspace_dir,
                guard_home=home_dir,
            )
        )
        assert install_settings_payload["hooks"]["PreToolUse"][0]["command"] == expected_hook_command
        assert uninstall_rc == 0
        assert uninstall_output["managed_install"]["active"] is False
        assert settings_payload["hooks"]["PreToolUse"] == []

    def test_guard_uninstall_handles_non_dict_claude_hook_entries(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        settings_local = workspace_dir / ".claude" / "settings.local.json"
        expected_hook_command = ClaudeCodeHarnessAdapter._hook_command(
            HarnessContext(
                home_dir=home_dir,
                workspace_dir=workspace_dir,
                guard_home=home_dir,
            )
        )
        _write_json(
            settings_local,
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
        payload = json.loads(settings_local.read_text(encoding="utf-8"))

        assert rc == 0
        assert output["managed_install"]["active"] is False
        assert payload["hooks"]["PreToolUse"] == ["unexpected-entry"]

    def test_guard_install_auto_detects_configured_harnesses(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "install",
                "--all",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["auto_detected"] is True
        harnesses = {item["harness"] for item in output["managed_installs"]}
        assert {"codex", "claude-code", "cursor", "antigravity", "gemini", "opencode"} <= harnesses

    def test_guard_install_creates_opencode_runtime_overlay(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            workspace_dir / "opencode.json",
            {
                "name": "workspace-opencode",
                "mcp": {
                    "danger_lab": {
                        "type": "local",
                        "command": ["python3", "danger-server.py"],
                        "environment": {"API_BASE": "https://hol.org"},
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
        runtime_config_path = Path(str(manifest["runtime_config_path"]))
        runtime_payload = json.loads(runtime_config_path.read_text(encoding="utf-8"))
        managed_config_path = Path(str(manifest["managed_config_path"]))
        managed_payload = json.loads(managed_config_path.read_text(encoding="utf-8"))

        assert rc == 0
        assert output["managed_install"]["active"] is True
        assert manifest["shim_command"] == "guard-opencode"
        assert "skill" not in runtime_payload["permission"]
        assert runtime_payload["permission"]["danger_lab_*"] == "ask"
        assert runtime_payload["mcp"]["danger_lab"]["type"] == "local"
        assert runtime_payload["mcp"]["danger_lab"]["command"][0]
        assert runtime_payload["mcp"]["danger_lab"]["command"][3] == "guard"
        assert runtime_payload["mcp"]["danger_lab"]["command"][4] == "opencode-mcp-proxy"
        assert runtime_payload["mcp"]["danger_lab"]["environment"]["API_BASE"] == "https://hol.org"
        assert manifest["managed_config_path"] == str(workspace_dir / "opencode.json")
        assert Path(str(manifest["backup_path"])).is_file()
        assert managed_payload["permission"]["danger_lab_*"] == "ask"
        assert managed_payload["mcp"]["danger_lab"]["type"] == "local"
        assert managed_payload["mcp"]["danger_lab"]["command"][2] == "codex_plugin_scanner.cli"
        assert managed_payload["mcp"]["danger_lab"]["command"][3] == "guard"
        assert managed_payload["mcp"]["danger_lab"]["command"][4] == "opencode-mcp-proxy"
        assert managed_payload["mcp"]["danger_lab"]["environment"]["API_BASE"] == "https://hol.org"

    def test_guard_reinstall_does_not_double_wrap_opencode_mcp_proxies(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            workspace_dir / "opencode.json",
            {
                "mcp": {
                    "danger_lab": {
                        "type": "local",
                        "command": ["python3", "danger-server.py"],
                    }
                }
            },
        )

        first_rc = main(
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
        json.loads(capsys.readouterr().out)

        second_rc = main(
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
        second_output = json.loads(capsys.readouterr().out)
        managed_config_path = Path(str(second_output["managed_install"]["manifest"]["managed_config_path"]))
        managed_payload = json.loads(managed_config_path.read_text(encoding="utf-8"))
        proxy_command = managed_payload["mcp"]["danger_lab"]["command"]

        assert first_rc == 0
        assert second_rc == 0
        assert proxy_command.count("opencode-mcp-proxy") == 1
        assert proxy_command[proxy_command.index("--command") + 1] == "python3"
        assert "--arg=danger-server.py" in proxy_command

    def test_guard_install_prefers_existing_opencode_jsonc_target(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        jsonc_path = workspace_dir / "opencode.jsonc"
        jsonc_text = (
            "{\n"
            "  // keep jsonc target\n"
            '  "provider": {"openai": {}},\n'
            '  "mcp": {"danger_lab": {"type": "local", "command": ["python3", "danger-server.py"]}}\n'
            "}\n"
        )
        _write_text(
            jsonc_path,
            jsonc_text,
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
        managed_config_path = Path(str(output["managed_install"]["manifest"]["managed_config_path"]))
        managed_payload = json.loads(managed_config_path.read_text(encoding="utf-8"))

        assert rc == 0
        assert managed_config_path == jsonc_path
        assert managed_payload["provider"] == {"openai": {}}
        assert managed_payload["permission"]["danger_lab_*"] == "ask"

    def test_guard_install_prefers_opencode_environment_config_target(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_path = workspace_dir / "custom" / "guard-opencode.jsonc"
        _write_text(custom_config_path, '{\n  "provider": {"openrouter": {}}\n}\n')
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom_config_path))

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
        managed_config_path = Path(str(output["managed_install"]["manifest"]["managed_config_path"]))
        managed_payload = json.loads(managed_config_path.read_text(encoding="utf-8"))

        assert rc == 0
        assert managed_config_path == custom_config_path
        assert managed_payload["provider"] == {"openrouter": {}}

    def test_guard_install_prefers_workspace_target_over_existing_global_opencode_config(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        global_config_path = home_dir / ".config" / "opencode" / "opencode.json"
        global_text = '{\n  "provider": {"openai": {}}\n}\n'
        _write_text(global_config_path, global_text)

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
        managed_config_path = Path(str(output["managed_install"]["manifest"]["managed_config_path"]))

        assert rc == 0
        assert managed_config_path == workspace_dir / "opencode.json"
        assert managed_config_path.exists() is True
        assert global_config_path.read_text(encoding="utf-8") == global_text

    def test_guard_uninstall_restores_opencode_project_config(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        original_payload = {
            "name": "workspace-opencode",
            "mcp": {
                "danger_lab": {
                    "type": "local",
                    "command": ["python3", "danger-server.py"],
                    "environment": {"API_BASE": "https://hol.org"},
                }
            },
        }
        _write_json(workspace_dir / "opencode.json", original_payload)
        original_text = (workspace_dir / "opencode.json").read_text(encoding="utf-8")

        install_rc = main(
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
        install_output = json.loads(capsys.readouterr().out)
        backup_path = Path(str(install_output["managed_install"]["manifest"]["backup_path"]))

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        uninstall_output = json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        assert uninstall_output["managed_install"]["active"] is False
        assert (workspace_dir / "opencode.json").read_text(encoding="utf-8") == original_text
        assert backup_path.exists() is False

    def test_guard_install_keeps_pythonpath_in_opencode_runtime_overlay(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            workspace_dir / "opencode.json",
            {
                "name": "workspace-opencode",
                "mcp": {
                    "danger_lab": {
                        "type": "local",
                        "command": ["python3", "danger-server.py"],
                    }
                },
            },
        )
        monkeypatch.setenv("PYTHONPATH", str(tmp_path / "src"))

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
        runtime_config_path = Path(str(manifest["runtime_config_path"]))
        runtime_payload = json.loads(runtime_config_path.read_text(encoding="utf-8"))

        assert rc == 0
        assert runtime_payload["mcp"]["danger_lab"]["environment"]["PYTHONPATH"] == str(tmp_path / "src")

    def test_guard_uninstall_removes_generated_opencode_config_when_no_original_exists(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        config_path = workspace_dir / "opencode.json"

        install_rc = main(
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
        install_output = json.loads(capsys.readouterr().out)
        backup_path = Path(str(install_output["managed_install"]["manifest"]["backup_path"]))

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        assert config_path.exists() is False
        assert backup_path.exists() is False

    def test_guard_uninstall_uses_install_state_when_opencode_config_changes(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_path = workspace_dir / "custom" / "guard-opencode.jsonc"
        original_text = '{\n  "provider": {"openrouter": {}}\n}\n'
        _write_text(custom_config_path, original_text)
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom_config_path))

        install_rc = main(
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
        install_output = json.loads(capsys.readouterr().out)
        backup_path = Path(str(install_output["managed_install"]["manifest"]["backup_path"]))
        state_path = Path(str(install_output["managed_install"]["manifest"]["state_path"]))
        monkeypatch.delenv("OPENCODE_CONFIG")

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        uninstall_output = json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        assert uninstall_output["managed_install"]["manifest"]["managed_config_path"] == str(custom_config_path)
        assert custom_config_path.read_text(encoding="utf-8") == original_text
        assert backup_path.exists() is False
        assert state_path.exists() is False

    def test_guard_uninstall_uses_workspace_scoped_state(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_a = tmp_path / "workspace-a"
        workspace_b = tmp_path / "workspace-b"
        original_a = '{\n  "provider": {"openai": {}}\n}\n'
        original_b = '{\n  "provider": {"openrouter": {}}\n}\n'
        _write_text(workspace_a / "opencode.json", original_a)
        _write_text(workspace_b / "opencode.json", original_b)

        install_a_rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_a),
                "--json",
            ]
        )
        install_a_output = json.loads(capsys.readouterr().out)
        state_a_path = Path(str(install_a_output["managed_install"]["manifest"]["state_path"]))

        install_b_rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_b),
                "--json",
            ]
        )
        install_b_output = json.loads(capsys.readouterr().out)
        state_b_path = Path(str(install_b_output["managed_install"]["manifest"]["state_path"]))

        uninstall_a_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_a),
                "--json",
            ]
        )
        uninstall_a_output = json.loads(capsys.readouterr().out)

        assert install_a_rc == 0
        assert install_b_rc == 0
        assert uninstall_a_rc == 0
        assert uninstall_a_output["managed_install"]["manifest"]["managed_config_path"] == str(
            workspace_a / "opencode.json"
        )
        assert (workspace_a / "opencode.json").read_text(encoding="utf-8") == original_a
        assert (workspace_b / "opencode.json").read_text(encoding="utf-8") != original_b
        assert state_a_path.exists() is False
        assert state_b_path.exists() is True

    def test_guard_uninstall_uses_single_global_state_without_opencode_config(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        custom_config_path = home_dir / "custom" / "opencode.jsonc"
        original_text = '{\n  "provider": {"openrouter": {}}\n}\n'
        _write_text(custom_config_path, original_text)
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom_config_path))

        install_rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        install_output = json.loads(capsys.readouterr().out)
        state_path = Path(str(install_output["managed_install"]["manifest"]["state_path"]))
        monkeypatch.delenv("OPENCODE_CONFIG")

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        uninstall_output = json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        assert uninstall_output["managed_install"]["manifest"]["managed_config_path"] == str(custom_config_path)
        assert custom_config_path.read_text(encoding="utf-8") == original_text
        assert state_path.exists() is False

    def test_guard_uninstall_keeps_config_when_backup_metadata_is_unreadable(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"

        install_rc = main(
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
        install_output = json.loads(capsys.readouterr().out)
        backup_path = Path(str(install_output["managed_install"]["manifest"]["backup_path"]))
        config_path = Path(str(install_output["managed_install"]["manifest"]["managed_config_path"]))
        state_path = Path(str(install_output["managed_install"]["manifest"]["state_path"]))
        backup_path.write_text("{\n  bad json\n", encoding="utf-8")

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        assert config_path.exists() is True
        assert backup_path.exists() is True
        assert state_path.exists() is True

    def test_guard_uninstall_keeps_config_when_backup_content_is_missing(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"

        install_rc = main(
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
        install_output = json.loads(capsys.readouterr().out)
        backup_path = Path(str(install_output["managed_install"]["manifest"]["backup_path"]))
        config_path = Path(str(install_output["managed_install"]["manifest"]["managed_config_path"]))
        state_path = Path(str(install_output["managed_install"]["manifest"]["state_path"]))
        backup_path.write_text('{\n  "existed": true\n}\n', encoding="utf-8")

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        assert config_path.exists() is True
        assert backup_path.exists() is True
        assert state_path.exists() is True

    def test_guard_uninstall_keeps_state_when_opencode_backup_is_missing(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"

        install_rc = main(
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
        install_output = json.loads(capsys.readouterr().out)
        backup_path = Path(str(install_output["managed_install"]["manifest"]["backup_path"]))
        config_path = Path(str(install_output["managed_install"]["manifest"]["managed_config_path"]))
        state_path = Path(str(install_output["managed_install"]["manifest"]["state_path"]))
        backup_path.unlink()

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        assert config_path.exists() is True
        assert backup_path.exists() is False
        assert state_path.exists() is True

    def test_guard_uninstall_avoids_ambiguous_workspace_state_matches(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        config_a_path = workspace_dir / "custom-a" / "opencode.jsonc"
        config_b_path = workspace_dir / "custom-b" / "opencode.jsonc"
        _write_text(config_a_path, '{\n  "provider": {"openai": {}}\n}\n')
        _write_text(config_b_path, '{\n  "provider": {"openrouter": {}}\n}\n')

        monkeypatch.setenv("OPENCODE_CONFIG", str(config_a_path))
        install_a_rc = main(
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
        install_a_output = json.loads(capsys.readouterr().out)
        state_a_path = Path(str(install_a_output["managed_install"]["manifest"]["state_path"]))

        monkeypatch.setenv("OPENCODE_CONFIG", str(config_b_path))
        install_b_rc = main(
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
        install_b_output = json.loads(capsys.readouterr().out)
        state_b_path = Path(str(install_b_output["managed_install"]["manifest"]["state_path"]))
        monkeypatch.delenv("OPENCODE_CONFIG")
        config_a_before_uninstall = config_a_path.read_text(encoding="utf-8")
        config_b_before_uninstall = config_b_path.read_text(encoding="utf-8")

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        assert install_a_rc == 0
        assert install_b_rc == 0
        assert uninstall_rc == 0
        assert config_a_path.read_text(encoding="utf-8") == config_a_before_uninstall
        assert config_b_path.read_text(encoding="utf-8") == config_b_before_uninstall
        assert state_a_path.exists() is True
        assert state_b_path.exists() is True

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

    def test_guard_update_runs_pip_upgrade_in_current_environment(self, monkeypatch, capsys):
        commands: list[list[str]] = []

        def fake_run(command: list[str], **_: object):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="updated", stderr="")

        monkeypatch.setattr(guard_update_commands_module.subprocess, "run", fake_run)
        monkeypatch.setattr(guard_update_commands_module.sys, "prefix", "/opt/guard-venv")
        monkeypatch.setattr(guard_update_commands_module.sys, "executable", "/opt/guard-venv/bin/python")
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version_from_subprocess", lambda: "2.0.18")

        rc = main(["guard", "update", "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["installer"] == "pip"
        assert commands == [["/opt/guard-venv/bin/python", "-m", "pip", "install", "--upgrade", "hol-guard"]]
        assert output["status"] == "updated"
        assert output["stdout"] == "updated"

    def test_guard_update_uses_pipx_when_running_from_pipx(self, monkeypatch, capsys):
        commands: list[list[str]] = []

        def fake_run(command: list[str], **_: object):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="pipx-updated", stderr="")

        monkeypatch.setattr(guard_update_commands_module.subprocess, "run", fake_run)
        monkeypatch.setattr(guard_update_commands_module.sys, "prefix", "/mock-home/.local/pipx/venvs/hol-guard")
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version_from_subprocess", lambda: "2.0.18")

        rc = main(["guard", "update", "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["installer"] == "pipx"
        assert commands == [["pipx", "upgrade", "hol-guard"]]
        assert output["status"] == "updated"

    def test_guard_update_marks_already_current_pipx_runs_as_current(self, monkeypatch, capsys):
        commands: list[list[str]] = []

        def fake_run(command: list[str], **_: object):
            commands.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "hol-guard is already at latest version 2.0.36 "
                    "(location: /Users/michaelkantor/.local/pipx/venvs/hol-guard)"
                ),
                stderr="upgrading shared libraries...\nupgrading hol-guard...\n",
            )

        monkeypatch.setattr(guard_update_commands_module.subprocess, "run", fake_run)
        monkeypatch.setattr(guard_update_commands_module.sys, "prefix", "/mock-home/.local/pipx/venvs/hol-guard")
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "2.0.36")
        monkeypatch.setattr(guard_update_commands_module, "_current_version_from_subprocess", lambda: "2.0.36")

        rc = main(["guard", "update", "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["installer"] == "pipx"
        assert commands == [["pipx", "upgrade", "hol-guard"]]
        assert output["status"] == "current"
        assert output["message"] == "HOL Guard is already current."
        assert output["notes"] == ["upgrading shared libraries...", "upgrading hol-guard..."]
        assert output["stdout"].startswith("hol-guard is already at latest version 2.0.36")
        assert output["stderr"] == "upgrading shared libraries...\nupgrading hol-guard..."

    def test_guard_update_treats_first_install_as_updated_when_only_dependencies_are_current(self, monkeypatch, capsys):
        commands: list[list[str]] = []

        def fake_run(command: list[str], **_: object):
            commands.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "Requirement already satisfied: pip in /mock/python/site-packages\n"
                    "Successfully installed hol-guard-2.0.36"
                ),
                stderr="",
            )

        monkeypatch.setattr(guard_update_commands_module.subprocess, "run", fake_run)
        monkeypatch.setattr(guard_update_commands_module.sys, "prefix", "/opt/guard-venv")
        monkeypatch.setattr(guard_update_commands_module.sys, "executable", "/opt/guard-venv/bin/python")
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "unknown")
        monkeypatch.setattr(guard_update_commands_module, "_current_version_from_subprocess", lambda: "2.0.36")

        rc = main(["guard", "update", "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert commands == [["/opt/guard-venv/bin/python", "-m", "pip", "install", "--upgrade", "hol-guard"]]
        assert output["status"] == "updated"
        assert output["changed"] is True
        assert output["message"] == "HOL Guard update completed successfully."

    def test_guard_update_dry_run_emits_planned_command(self, monkeypatch, capsys):
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)

        rc = main(["guard", "update", "--dry-run", "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "planned"
        assert output["dry_run"] is True
        assert output["command"]

    def test_guard_update_skips_editable_installs(self, monkeypatch, capsys):
        monkeypatch.setattr(
            guard_update_commands_module,
            "_direct_url_payload",
            lambda: {"dir_info": {"editable": True}, "url": "file:///mock-workspace/ai-plugin-scanner"},
        )

        rc = main(["guard", "update", "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "skipped"
        assert output["editable_install"] is True
        assert "disabled for editable installs" in output["error"]

    def test_guard_update_human_output_uses_notes_instead_of_stderr_for_current(self, capsys):
        emit_guard_payload(
            "update",
            {
                "current_version": "2.0.36",
                "installer": "pipx",
                "command": ["pipx", "upgrade", "hol-guard"],
                "dry_run": False,
                "resulting_version": "2.0.36",
                "status": "current",
                "message": "HOL Guard is already current.",
                "notes": ["upgrading shared libraries...", "upgrading hol-guard..."],
                "stdout": "hol-guard is already at latest version 2.0.36",
                "stderr": "upgrading shared libraries...\nupgrading hol-guard...",
            },
            False,
        )

        output = capsys.readouterr().out

        assert "Guard update: current" in output
        assert "HOL Guard is already current." in output
        assert "Notes" in output
        assert "upgrading shared libraries..." in output
        assert "stdout" not in output
        assert "stderr" not in output

    def test_guard_update_failed_output_keeps_stdout_details(self, capsys):
        emit_guard_payload(
            "update",
            {
                "current_version": "2.0.36",
                "installer": "pipx",
                "command": ["pipx", "upgrade", "hol-guard"],
                "dry_run": False,
                "status": "failed",
                "message": "HOL Guard update failed.",
                "stdout": "pipx could not upgrade hol-guard in the current environment",
                "stderr": "",
                "error": "",
            },
            False,
        )

        output = capsys.readouterr().out

        assert "Guard update: failed" in output
        assert "stdout" in output
        assert "pipx could not upgrade hol-guard in the current environment" in output

    def test_guard_uninstall_auto_detects_managed_harnesses(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        install_rc = main(
            [
                "guard",
                "install",
                "--all",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "--all",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        assert all(item["active"] is False for item in output["managed_installs"])

    def test_guard_install_requires_harness_without_all(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "install",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
            ]
        )
        stderr = capsys.readouterr().err

        assert rc == 2
        assert "Guard install requires a harness or --all." in stderr

    @pytest.mark.parametrize("command", ["install", "uninstall"])
    def test_guard_install_commands_reject_harness_with_all(self, tmp_path, capsys, command: str):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                command,
                "codex",
                "--all",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
            ]
        )
        stderr = capsys.readouterr().err

        assert rc == 2
        assert "Pass either a harness or --all, not both." in stderr

    def test_guard_login_and_sync_posts_receipts(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
        _SyncRequestHandler.response_payload = {
            "syncedAt": "2026-04-09T00:00:00Z",
            "receiptsStored": 1,
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            login_rc = main(
                [
                    "guard",
                    "login",
                    "--home",
                    str(home_dir),
                    "--sync-url",
                    f"http://127.0.0.1:{server.server_port}/receipts",
                    "--token",
                    "demo-token",
                    "--json",
                ]
            )
            json.loads(capsys.readouterr().out)

            run_rc = main(
                [
                    "guard",
                    "run",
                    "codex",
                    "--home",
                    str(home_dir),
                    "--workspace",
                    str(workspace_dir),
                    "--dry-run",
                    "--default-action",
                    "allow",
                    "--json",
                ]
            )
            json.loads(capsys.readouterr().out)

            sync_rc = main(
                [
                    "guard",
                    "sync",
                    "--home",
                    str(home_dir),
                    "--json",
                ]
            )
            sync_output = json.loads(capsys.readouterr().out)
            status_rc = main(["guard", "status", "--home", str(home_dir), "--workspace", str(workspace_dir), "--json"])
            status_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert login_rc == 0
        assert run_rc == 0
        assert sync_rc == 0
        assert status_rc == 0
        assert sync_output["receipts_stored"] == 1
        assert sync_output["inventory"] == 0
        assert sync_output["inventory_tracked"] >= 1
        assert status_output["cloud_state"] == "paired_active"
        assert status_output["last_sync_at"] == "2026-04-09T00:00:00Z"
        assert _SyncRequestHandler.captured_headers["authorization"] == "Bearer demo-token"
        assert _SyncRequestHandler.captured_body is not None
        assert len(_SyncRequestHandler.captured_body["receipts"]) >= 1
        assert "inventory" not in _SyncRequestHandler.captured_body
        first_receipt = _SyncRequestHandler.captured_body["receipts"][0]
        assert "artifactId" in first_receipt
        assert "artifact_id" not in first_receipt
        assert "receiptId" in first_receipt
        assert "artifactSlug" in first_receipt
        assert "artifactHash" in first_receipt
        assert "recommendation" in first_receipt

    def test_guard_connect_pairs_browser_session_and_syncs(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
        _SyncRequestHandler.response_payload = {
            "syncedAt": "2026-04-09T00:00:00Z",
            "receiptsStored": 1,
            "advisories": [
                {
                    "id": "adv-001",
                    "publisher": "hashgraph-online",
                    "severity": "high",
                    "headline": "Publisher rotated to a new remote domain.",
                }
            ],
            "policy": {
                "mode": "enforce",
                "defaultAction": "warn",
                "unknownPublisherAction": "review",
                "changedHashAction": "allow",
                "newNetworkDomainAction": "warn",
                "subprocessAction": "block",
                "telemetryEnabled": False,
                "syncEnabled": True,
                "updatedAt": "2026-04-09T00:00:00Z",
            },
            "alertPreferences": {
                "emailEnabled": True,
                "digestMode": "daily",
                "watchlistEnabled": True,
                "advisoriesEnabled": True,
                "repeatedWarningsEnabled": True,
                "teamAlertsEnabled": True,
                "updatedAt": "2026-04-09T00:00:00Z",
            },
            "teamPolicyPack": {
                "name": "Security team default",
                "sharedHarnessDefaults": {"codex": "enforce"},
                "allowedPublishers": ["hashgraph-online"],
                "blockedArtifacts": [],
                "alertChannel": "email",
                "updatedAt": "2026-04-09T00:00:00Z",
                "auditTrail": [],
            },
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        store = GuardStore(home_dir)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_guard_daemon",
            lambda guard_home: f"http://127.0.0.1:{daemon.port}",
        )

        opened_urls: list[str] = []

        def open_browser(url: str) -> bool:
            opened_urls.append(url)
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            fragment = urllib.parse.parse_qs(parsed.fragment)
            request_id = query["guardPairRequest"][-1]
            daemon_url = query["guardDaemon"][-1]
            pairing_secret = fragment["guardPairSecret"][-1]

            def complete_pairing() -> None:
                request = urllib.request.Request(
                    f"{daemon_url}/v1/connect/complete",
                    data=urllib.parse.urlencode(
                        {
                            "request_id": request_id,
                            "pairing_secret": pairing_secret,
                            "token": "session-token-123",
                        }
                    ).encode("utf-8"),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": "https://hol.org",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=5):
                    pass

            threading.Thread(target=complete_pairing, daemon=True).start()
            return True

        monkeypatch.setattr(guard_commands_module.webbrowser, "open", open_browser)
        try:
            run_rc = main(
                [
                    "guard",
                    "run",
                    "codex",
                    "--home",
                    str(home_dir),
                    "--workspace",
                    str(workspace_dir),
                    "--dry-run",
                    "--default-action",
                    "allow",
                    "--json",
                ]
            )
            json.loads(capsys.readouterr().out)

            connect_rc = main(
                [
                    "guard",
                    "connect",
                    "--home",
                    str(home_dir),
                    "--sync-url",
                    f"http://127.0.0.1:{server.server_port}/receipts",
                    "--connect-url",
                    "https://hol.org/guard/connect",
                    "--json",
                ]
            )
            connect_output = json.loads(capsys.readouterr().out)
        finally:
            daemon.stop()
            server.shutdown()
            thread.join(timeout=5)

        assert run_rc == 0
        assert connect_rc == 0
        assert connect_output["connected"] is True
        assert connect_output["status"] == "connected"
        assert connect_output["milestone"] == "first_sync_succeeded"
        assert connect_output["sync"]["receipts_stored"] == 1
        assert connect_output["sync"]["inventory_tracked"] >= 1
        assert connect_output["browser_opened"] is True
        assert opened_urls and opened_urls[0].startswith("https://hol.org/guard/connect?")
        assert _SyncRequestHandler.captured_headers["authorization"] == "Bearer session-token-123"
        assert _SyncRequestHandler.captured_headers["user-agent"].startswith("hol-guard/")
        assert store.get_sync_credentials() == {
            "sync_url": f"http://127.0.0.1:{server.server_port}/receipts",
            "token": "session-token-123",
        }

    def test_guard_login_without_manual_credentials_runs_browser_pairing(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
        _SyncRequestHandler.response_payload = {
            "syncedAt": "2026-04-09T00:00:00Z",
            "receiptsStored": 1,
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        store = GuardStore(home_dir)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_guard_daemon",
            lambda guard_home: f"http://127.0.0.1:{daemon.port}",
        )

        opened_urls: list[str] = []

        def open_browser(url: str) -> bool:
            opened_urls.append(url)
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            fragment = urllib.parse.parse_qs(parsed.fragment)
            request_id = query["guardPairRequest"][-1]
            daemon_url = query["guardDaemon"][-1]
            pairing_secret = fragment["guardPairSecret"][-1]

            def complete_pairing() -> None:
                request = urllib.request.Request(
                    f"{daemon_url}/v1/connect/complete",
                    data=urllib.parse.urlencode(
                        {
                            "request_id": request_id,
                            "pairing_secret": pairing_secret,
                            "token": "session-token-compat",
                        }
                    ).encode("utf-8"),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": "https://hol.org",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=5):
                    pass

            threading.Thread(target=complete_pairing, daemon=True).start()
            return True

        monkeypatch.setattr(guard_commands_module.webbrowser, "open", open_browser)
        try:
            login_rc = main(
                [
                    "guard",
                    "login",
                    "--home",
                    str(home_dir),
                    "--sync-url",
                    f"http://127.0.0.1:{server.server_port}/receipts",
                    "--connect-url",
                    "https://hol.org/guard/connect",
                    "--json",
                ]
            )
            login_output = json.loads(capsys.readouterr().out)
            sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
            sync_output = json.loads(capsys.readouterr().out)
        finally:
            daemon.stop()
            server.shutdown()
            thread.join(timeout=5)

        assert login_rc == 0
        assert login_output["connected"] is True
        assert login_output["status"] == "connected"
        assert opened_urls and opened_urls[0].startswith("https://hol.org/guard/connect?")
        assert sync_rc == 0
        assert sync_output["receipts_stored"] == 1
        assert _SyncRequestHandler.captured_headers["authorization"] == "Bearer session-token-compat"
        assert store.get_sync_credentials() == {
            "sync_url": f"http://127.0.0.1:{server.server_port}/receipts",
            "token": "session-token-compat",
        }

    def test_guard_login_manual_mode_requires_sync_url_and_token(self, tmp_path, capsys):
        home_dir = tmp_path / "home"

        login_rc = main(
            [
                "guard",
                "login",
                "--home",
                str(home_dir),
                "--token",
                "demo-token",
            ]
        )

        assert login_rc == 2
        assert "Pass both --sync-url and --token to save credentials manually" in capsys.readouterr().err

    def test_guard_connect_preserves_pairing_when_first_sync_fails(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        store = GuardStore(home_dir)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_guard_daemon",
            lambda guard_home: f"http://127.0.0.1:{daemon.port}",
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.cli.connect_flow.sync_receipts",
            lambda current_store: (_ for _ in ()).throw(RuntimeError("sync_unreachable")),
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.cli.connect_flow.sync_runtime_session",
            lambda current_store, *, session: {
                "runtime_session_id": str(session.get("session_id") or session.get("sessionId")),
                "runtime_session_synced_at": "2026-04-15T00:00:01Z",
                "runtime_sessions_visible": 1,
            },
        )

        def open_browser(url: str) -> bool:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            fragment = urllib.parse.parse_qs(parsed.fragment)
            request_id = query["guardPairRequest"][-1]
            daemon_url = query["guardDaemon"][-1]
            pairing_secret = fragment["guardPairSecret"][-1]

            def complete_pairing() -> None:
                request = urllib.request.Request(
                    f"{daemon_url}/v1/connect/complete",
                    data=urllib.parse.urlencode(
                        {
                            "request_id": request_id,
                            "pairing_secret": pairing_secret,
                            "token": "session-token-123",
                        }
                    ).encode("utf-8"),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": "https://hol.org",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=5):
                    pass

            threading.Thread(target=complete_pairing, daemon=True).start()
            return True

        monkeypatch.setattr(guard_commands_module.webbrowser, "open", open_browser)
        try:
            connect_rc = main(
                [
                    "guard",
                    "connect",
                    "--home",
                    str(home_dir),
                    "--sync-url",
                    "https://hol.org/registry/api/v1",
                    "--connect-url",
                    "https://hol.org/guard/connect",
                    "--json",
                ]
            )
            connect_output = json.loads(capsys.readouterr().out)
        finally:
            daemon.stop()

        assert connect_rc == 0
        assert connect_output["connected"] is True
        assert connect_output["status"] == "connected"
        assert connect_output["milestone"] == "first_sync_pending"
        assert connect_output["reason"] == "sync_unreachable"
        assert connect_output["sync_message"] == "sync_unreachable"

    def test_guard_connect_surfaces_remote_sync_errors_cleanly(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _SyncRequestHandler.response_code = 403
        _SyncRequestHandler.response_payload = {
            "error": "Guard sync requires a Pro or Team plan.",
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        store = GuardStore(home_dir)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_guard_daemon",
            lambda guard_home: f"http://127.0.0.1:{daemon.port}",
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.cli.connect_flow.sync_runtime_session",
            lambda current_store, *, session: {
                "runtime_session_id": str(session.get("session_id") or session.get("sessionId")),
                "runtime_session_synced_at": "2026-04-15T00:00:01Z",
                "runtime_sessions_visible": 1,
            },
        )

        def open_browser(url: str) -> bool:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            fragment = urllib.parse.parse_qs(parsed.fragment)
            request_id = query["guardPairRequest"][-1]
            daemon_url = query["guardDaemon"][-1]
            pairing_secret = fragment["guardPairSecret"][-1]

            def complete_pairing() -> None:
                request = urllib.request.Request(
                    f"{daemon_url}/v1/connect/complete",
                    data=urllib.parse.urlencode(
                        {
                            "request_id": request_id,
                            "pairing_secret": pairing_secret,
                            "token": "session-token-123",
                        }
                    ).encode("utf-8"),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": "https://hol.org",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=5):
                    pass

            threading.Thread(target=complete_pairing, daemon=True).start()
            return True

        monkeypatch.setattr(guard_commands_module.webbrowser, "open", open_browser)
        try:
            connect_rc = main(
                [
                    "guard",
                    "connect",
                    "--home",
                    str(home_dir),
                    "--sync-url",
                    f"http://127.0.0.1:{server.server_port}/receipts",
                    "--connect-url",
                    "https://hol.org/guard/connect",
                    "--json",
                ]
            )
            connect_output = json.loads(capsys.readouterr().out)
        finally:
            daemon.stop()
            server.shutdown()
            thread.join(timeout=5)
            _SyncRequestHandler.response_code = 200
            _SyncRequestHandler.response_payload = {
                "syncedAt": "2026-04-09T00:00:00Z",
                "receiptsStored": 1,
            }

        assert connect_rc == 0
        assert connect_output["connected"] is True
        assert connect_output["status"] == "connected"
        assert connect_output["milestone"] == "sync_not_available"
        assert connect_output["reason"] == "Guard sync requires a Pro or Team plan."
        assert connect_output["sync_message"] == "Guard sync requires a Pro or Team plan."

    def test_guard_connect_pending_output_uses_product_copy_for_sign_in_gap(self, capsys):
        emit_guard_payload(
            "connect",
            {
                "browser_opened": True,
                "completed_at": "2026-04-20T00:00:00Z",
                "status": "connected",
                "milestone": "first_sync_pending",
                "connect_url": "https://hol.org/guard/connect",
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "sync": {
                    "receipts_stored": 0,
                    "inventory_tracked": 0,
                },
                "sync_message": "Guard is not logged in.",
            },
            False,
        )

        output = capsys.readouterr().out

        assert "This device is protected locally" in output
        assert "Sign in to finish Guard Cloud setup" in output
        assert "Local protection is active." in output
        assert "Sign in on the Guard connect page" in output
        assert "Machine registered, first proof pending" not in output
        assert "Dashboard proof is still syncing" not in output
        assert "Guard is not logged in." not in output
        assert "Receipts stored" not in output
        assert "Inventory tracked" not in output

    def test_guard_connect_pending_output_uses_product_copy_for_plan_limit(self, capsys):
        emit_guard_payload(
            "connect",
            {
                "browser_opened": True,
                "completed_at": "2026-04-20T00:00:00Z",
                "status": "connected",
                "milestone": "sync_not_available",
                "connect_url": "https://hol.org/guard/connect",
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "sync_message": "Guard Cloud sync requires a paid Guard plan",
            },
            False,
        )

        output = capsys.readouterr().out

        assert "This device is protected locally" in output
        assert "Upgrade to sync this device to Guard Cloud" in output
        assert "Local protection is active." in output
        assert "Upgrade your Guard plan" in output
        assert "shared proof" in output
        assert "devices to Guard Cloud" in output
        assert "Shared proof sync needs a paid Guard plan" not in output

    def test_guard_connect_pending_output_treats_upgrade_copy_as_plan_limit(self, capsys):
        emit_guard_payload(
            "connect",
            {
                "browser_opened": True,
                "completed_at": "2026-04-20T00:00:00Z",
                "status": "connected",
                "milestone": "sync_not_available",
                "connect_url": "https://hol.org/guard/connect",
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "sync_message": "Upgrade your plan to sync Guard Cloud receipts.",
            },
            False,
        )

        output = capsys.readouterr().out

        assert "This device is protected locally" in output
        assert "Upgrade to sync this device to Guard Cloud" in output
        assert "First Guard Cloud proof is on the way" not in output

    def test_guard_connect_rejects_invalid_sync_url(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        with pytest.raises(SystemExit) as exc_info:
            main(
                [
                    "guard",
                    "connect",
                    "--home",
                    str(home_dir),
                    "--workspace",
                    str(workspace_dir),
                    "--sync-url",
                    "not-a-url",
                ]
            )

        assert exc_info.value.code == 2
        assert "Guard URLs must be absolute http(s) URLs." in capsys.readouterr().err

    def test_guard_connect_uses_recovered_daemon_url_for_browser_pairing(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")
        opened_urls: list[str] = []

        class FakeDaemonClient:
            def __init__(self) -> None:
                self.daemon_url = "http://127.0.0.1:4781"

            def create_connect_request(self, *, sync_url: str, allowed_origin: str) -> dict[str, object]:
                return {
                    "request_id": "req-123",
                    "pairing_secret": "pair-secret",
                    "sync_url": sync_url,
                    "allowed_origin": allowed_origin,
                }

            def get_connect_state(self, *, request_id: str) -> dict[str, object]:
                return {
                    "request_id": request_id,
                    "status": "waiting",
                    "milestone": "waiting_for_browser",
                    "completed_at": None,
                    "expires_at": "2026-04-15T00:05:00Z",
                    "proof": {},
                }

            def report_connect_result(self, **kwargs) -> dict[str, object]:
                raise AssertionError("report_connect_result should not be called when the browser never completes")

        monkeypatch.setattr(
            guard_connect_flow_module, "ensure_guard_daemon", lambda guard_home: "http://127.0.0.1:4779"
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "load_guard_surface_daemon_client",
            lambda guard_home: FakeDaemonClient(),
        )
        monkeypatch.setattr(guard_connect_flow_module, "wait_for_connect_transition", lambda **kwargs: None)
        payload = guard_connect_flow_module.run_guard_connect_command(
            guard_home=tmp_path / "guard-home",
            store=store,
            sync_url="https://hol.org/api/guard/receipts/sync",
            connect_url="https://hol.org/guard/connect",
            opener=lambda url: opened_urls.append(url) or True,
            wait_timeout_seconds=1,
        )

        parsed = urllib.parse.urlparse(opened_urls[0])
        query = urllib.parse.parse_qs(parsed.query)
        assert payload["status"] == "waiting"
        assert payload["milestone"] == "waiting_for_browser"
        assert query["guardDaemon"] == ["http://127.0.0.1:4781"]

    def test_guard_connect_preserves_custom_connect_query_params(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")
        opened_urls: list[str] = []

        class FakeDaemonClient:
            daemon_url = "http://127.0.0.1:4781"

            def create_connect_request(self, *, sync_url: str, allowed_origin: str) -> dict[str, object]:
                return {
                    "request_id": "req-123",
                    "pairing_secret": "pair-secret",
                    "sync_url": sync_url,
                    "allowed_origin": allowed_origin,
                }

            def get_connect_state(self, *, request_id: str) -> dict[str, object]:
                return {
                    "request_id": request_id,
                    "status": "waiting",
                    "milestone": "waiting_for_browser",
                    "completed_at": None,
                    "expires_at": "2026-04-15T00:05:00Z",
                    "proof": {},
                }

            def report_connect_result(self, **kwargs) -> dict[str, object]:
                raise AssertionError("report_connect_result should not be called when the browser never completes")

        monkeypatch.setattr(
            guard_connect_flow_module, "ensure_guard_daemon", lambda guard_home: "http://127.0.0.1:4781"
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "load_guard_surface_daemon_client",
            lambda guard_home: FakeDaemonClient(),
        )
        monkeypatch.setattr(guard_connect_flow_module, "wait_for_connect_transition", lambda **kwargs: None)
        payload = guard_connect_flow_module.run_guard_connect_command(
            guard_home=tmp_path / "guard-home",
            store=store,
            sync_url="https://hol.org/api/guard/receipts/sync",
            connect_url="https://hol.org/guard/connect?tenant=enterprise&invite=abc123",
            opener=lambda url: opened_urls.append(url) or True,
            wait_timeout_seconds=1,
        )

        parsed = urllib.parse.urlparse(opened_urls[0])
        query = urllib.parse.parse_qs(parsed.query)
        assert payload["status"] == "waiting"
        assert payload["milestone"] == "waiting_for_browser"
        assert query["tenant"] == ["enterprise"]
        assert query["invite"] == ["abc123"]
        assert query["guardPairRequest"] == ["req-123"]
        assert query["guardDaemon"] == ["http://127.0.0.1:4781"]

    def test_guard_connect_wait_recovers_from_transient_daemon_poll_failures(self, monkeypatch):
        class FakeDaemonClient:
            def __init__(self) -> None:
                self.calls = 0

            def get_connect_state(self, *, request_id: str) -> dict[str, object]:
                self.calls += 1
                if self.calls == 1:
                    raise guard_connect_flow_module.GuardDaemonTransportError("daemon restarting")
                return {
                    "request_id": request_id,
                    "status": "connected",
                    "milestone": "first_sync_succeeded",
                    "completed_at": "2026-04-15T00:00:00Z",
                    "proof": {"receipts_stored": 3},
                }

        monotonic_values = iter((0.0, 0.0, 0.2))
        monkeypatch.setattr(guard_connect_flow_module.time, "monotonic", lambda: next(monotonic_values))
        monkeypatch.setattr(guard_connect_flow_module.time, "sleep", lambda seconds: None)

        state = guard_connect_flow_module.wait_for_connect_transition(
            daemon_client=FakeDaemonClient(),
            request_id="req-123",
            timeout_seconds=1,
            poll_interval_seconds=0,
        )

        assert state is not None
        assert state["status"] == "connected"
        assert state["milestone"] == "first_sync_succeeded"

    def test_guard_connect_wait_surfaces_permanent_daemon_poll_failures(self, monkeypatch):
        class FakeDaemonClient:
            def get_connect_state(self, *, request_id: str) -> dict[str, object]:
                raise guard_connect_flow_module.GuardDaemonRequestError("unauthorized")

        monotonic_values = iter((0.0, 0.0))
        monkeypatch.setattr(guard_connect_flow_module.time, "monotonic", lambda: next(monotonic_values))
        monkeypatch.setattr(guard_connect_flow_module.time, "sleep", lambda seconds: None)

        with pytest.raises(guard_connect_flow_module.GuardDaemonRequestError, match="unauthorized"):
            guard_connect_flow_module.wait_for_connect_transition(
                daemon_client=FakeDaemonClient(),
                request_id="req-123",
                timeout_seconds=1,
                poll_interval_seconds=0,
            )

    def test_guard_connect_wraps_sync_transport_failures(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")

        class FakeDaemonClient:
            daemon_url = "http://127.0.0.1:4781"

            def create_connect_request(self, *, sync_url: str, allowed_origin: str) -> dict[str, object]:
                return {
                    "request_id": "req-123",
                    "pairing_secret": "pair-secret",
                    "sync_url": sync_url,
                    "allowed_origin": allowed_origin,
                }

            def report_connect_result(
                self,
                *,
                request_id: str,
                status: str,
                milestone: str,
                reason: str | None = None,
                sync: dict[str, object] | None = None,
            ) -> dict[str, object]:
                return {
                    "request_id": request_id,
                    "status": status,
                    "milestone": milestone,
                    "completed_at": "2026-04-15T00:00:00Z",
                    "expires_at": "2026-04-15T00:05:00Z",
                    "reason": reason,
                    "proof": {
                        "pairing_completed_at": "2026-04-15T00:00:00Z",
                    },
                }

        monkeypatch.setattr(
            guard_connect_flow_module, "ensure_guard_daemon", lambda guard_home: "http://127.0.0.1:4781"
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "load_guard_surface_daemon_client",
            lambda guard_home: FakeDaemonClient(),
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "wait_for_connect_transition",
            lambda **kwargs: {
                "status": "waiting",
                "milestone": "first_sync_pending",
                "request_id": "req-123",
                "completed_at": "2026-04-15T00:00:00Z",
                "proof": {},
            },
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "sync_receipts",
            lambda current_store: (_ for _ in ()).throw(urllib.error.URLError("offline")),
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "sync_runtime_session",
            lambda current_store, *, session: {
                "runtime_session_id": str(session.get("session_id") or session.get("sessionId")),
                "runtime_session_synced_at": "2026-04-15T00:00:01Z",
                "runtime_sessions_visible": 1,
            },
        )

        payload = guard_connect_flow_module.run_guard_connect_command(
            guard_home=tmp_path / "guard-home",
            store=store,
            sync_url="https://hol.org/api/guard/receipts/sync",
            connect_url="https://hol.org/guard/connect",
            opener=lambda url: True,
            wait_timeout_seconds=1,
        )

        assert payload["connected"] is True
        assert payload["status"] == "connected"
        assert payload["milestone"] == "first_sync_pending"
        assert payload["sync_message"] == "<urlopen error offline>"

    def test_guard_connect_persists_success_when_daemon_result_write_fails(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")

        class FakeDaemonClient:
            daemon_url = "http://127.0.0.1:4781"

            def __init__(self) -> None:
                self.request_id = ""

            def create_connect_request(self, *, sync_url: str, allowed_origin: str) -> dict[str, object]:
                request = store.create_guard_connect_request(
                    sync_url=sync_url,
                    allowed_origin=allowed_origin,
                    now="2026-04-15T00:00:00Z",
                )
                self.request_id = str(request["request_id"])
                return request

            def report_connect_result(
                self,
                *,
                request_id: str,
                status: str,
                milestone: str,
                reason: str | None = None,
                sync: dict[str, object] | None = None,
            ) -> dict[str, object]:
                raise RuntimeError("daemon restarted")

        fake_daemon_client = FakeDaemonClient()
        monkeypatch.setattr(
            guard_connect_flow_module, "ensure_guard_daemon", lambda guard_home: "http://127.0.0.1:4781"
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "load_guard_surface_daemon_client",
            lambda guard_home: fake_daemon_client,
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "wait_for_connect_transition",
            lambda **kwargs: {
                "status": "waiting",
                "milestone": "first_sync_pending",
                "request_id": fake_daemon_client.request_id,
                "completed_at": "2026-04-15T00:00:00Z",
                "proof": {},
            },
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "sync_receipts",
            lambda current_store: {
                "receipts_stored": 3,
                "inventory_tracked": 1,
                "first_synced_at": "2026-04-15T00:00:01Z",
            },
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "sync_runtime_session",
            lambda current_store, *, session: {
                "runtime_session_id": str(session.get("session_id") or session.get("sessionId")),
                "runtime_session_synced_at": "2026-04-15T00:00:01Z",
                "runtime_sessions_visible": 1,
            },
        )

        payload = guard_connect_flow_module.run_guard_connect_command(
            guard_home=tmp_path / "guard-home",
            store=store,
            sync_url="https://hol.org/api/guard/receipts/sync",
            connect_url="https://hol.org/guard/connect",
            opener=lambda url: True,
            wait_timeout_seconds=1,
        )

        persisted_state = store.get_guard_connect_state(
            request_id=fake_daemon_client.request_id,
            now="2026-04-15T00:00:02Z",
        )

        assert payload["connected"] is True
        assert payload["status"] == "connected"
        assert payload["milestone"] == "first_sync_succeeded"
        assert payload["sync"]["receipts_stored"] == 3
        assert persisted_state is not None
        assert persisted_state["status"] == "connected"
        assert persisted_state["milestone"] == "first_sync_succeeded"
        assert persisted_state["proof"]["receipts_stored"] == 3

    def test_guard_connect_reports_paid_plan_limit_without_failing_pairing(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")

        class FakeDaemonClient:
            daemon_url = "http://127.0.0.1:4781"

            def create_connect_request(self, *, sync_url: str, allowed_origin: str) -> dict[str, object]:
                return {
                    "request_id": "req-123",
                    "pairing_secret": "pair-secret",
                    "sync_url": sync_url,
                    "allowed_origin": allowed_origin,
                }

            def report_connect_result(
                self,
                *,
                request_id: str,
                status: str,
                milestone: str,
                reason: str | None = None,
                sync: dict[str, object] | None = None,
            ) -> dict[str, object]:
                return {
                    "request_id": request_id,
                    "status": status,
                    "milestone": milestone,
                    "completed_at": "2026-04-15T00:00:00Z",
                    "expires_at": "2026-04-15T00:05:00Z",
                    "reason": reason,
                    "proof": {
                        "pairing_completed_at": "2026-04-15T00:00:00Z",
                    },
                }

        monkeypatch.setattr(
            guard_connect_flow_module, "ensure_guard_daemon", lambda guard_home: "http://127.0.0.1:4781"
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "load_guard_surface_daemon_client",
            lambda guard_home: FakeDaemonClient(),
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "wait_for_connect_transition",
            lambda **kwargs: {
                "status": "waiting",
                "milestone": "first_sync_pending",
                "request_id": "req-123",
                "completed_at": "2026-04-15T00:00:00Z",
                "proof": {},
            },
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "sync_receipts",
            lambda current_store: (_ for _ in ()).throw(RuntimeError("Guard Cloud sync requires a paid Guard plan")),
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "sync_runtime_session",
            lambda current_store, *, session: {
                "runtime_session_id": str(session.get("session_id") or session.get("sessionId")),
                "runtime_session_synced_at": "2026-04-15T00:00:01Z",
                "runtime_sessions_visible": 1,
            },
        )

        payload = guard_connect_flow_module.run_guard_connect_command(
            guard_home=tmp_path / "guard-home",
            store=store,
            sync_url="https://hol.org/api/guard/receipts/sync",
            connect_url="https://hol.org/guard/connect",
            opener=lambda url: True,
            wait_timeout_seconds=1,
        )

        assert payload["connected"] is True
        assert payload["status"] == "connected"
        assert payload["milestone"] == "first_sync_pending"
        assert payload["sync_message"] == "Guard Cloud sync requires a paid Guard plan"

    def test_guard_connect_reports_guard_plan_required_without_failing_pairing(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")

        class FakeDaemonClient:
            daemon_url = "http://127.0.0.1:4781"

            def create_connect_request(self, *, sync_url: str, allowed_origin: str) -> dict[str, object]:
                return {
                    "request_id": "req-124",
                    "pairing_secret": "pair-secret",
                    "sync_url": sync_url,
                    "allowed_origin": allowed_origin,
                }

            def report_connect_result(
                self,
                *,
                request_id: str,
                status: str,
                milestone: str,
                reason: str | None = None,
                sync: dict[str, object] | None = None,
            ) -> dict[str, object]:
                return {
                    "request_id": request_id,
                    "status": status,
                    "milestone": milestone,
                    "completed_at": "2026-04-15T00:00:00Z",
                    "expires_at": "2026-04-15T00:05:00Z",
                    "reason": reason,
                    "proof": {
                        "pairing_completed_at": "2026-04-15T00:00:00Z",
                    },
                }

        monkeypatch.setattr(
            guard_connect_flow_module, "ensure_guard_daemon", lambda guard_home: "http://127.0.0.1:4781"
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "load_guard_surface_daemon_client",
            lambda guard_home: FakeDaemonClient(),
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "wait_for_connect_transition",
            lambda **kwargs: {
                "status": "waiting",
                "milestone": "first_sync_pending",
                "request_id": "req-124",
                "completed_at": "2026-04-15T00:00:00Z",
                "proof": {},
            },
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "sync_receipts",
            lambda current_store: (_ for _ in ()).throw(RuntimeError("Guard plan required")),
        )
        monkeypatch.setattr(
            guard_connect_flow_module,
            "sync_runtime_session",
            lambda current_store, *, session: {
                "runtime_session_id": str(session.get("session_id") or session.get("sessionId")),
                "runtime_session_synced_at": "2026-04-15T00:00:01Z",
                "runtime_sessions_visible": 1,
            },
        )

        payload = guard_connect_flow_module.run_guard_connect_command(
            guard_home=tmp_path / "guard-home",
            store=store,
            sync_url="https://hol.org/api/guard/receipts/sync",
            connect_url="https://hol.org/guard/connect",
            opener=lambda url: True,
            wait_timeout_seconds=1,
        )

        assert payload["connected"] is True
        assert payload["status"] == "connected"
        assert payload["milestone"] == "first_sync_pending"
        assert payload["sync_message"] == "Guard plan required"

    def test_guard_sync_persists_advisories_from_endpoint(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
        _SyncRequestHandler.response_payload = {
            "syncedAt": "2026-04-09T00:00:00Z",
            "receiptsStored": 1,
            "advisories": [
                {
                    "id": "adv-001",
                    "publisher": "hashgraph-online",
                    "severity": "high",
                    "headline": "Publisher rotated to a new remote domain.",
                }
            ],
            "policy": {
                "mode": "enforce",
                "defaultAction": "warn",
                "unknownPublisherAction": "review",
                "changedHashAction": "allow",
                "newNetworkDomainAction": "warn",
                "subprocessAction": "block",
                "telemetryEnabled": False,
                "syncEnabled": True,
                "updatedAt": "2026-04-09T00:00:00Z",
            },
            "alertPreferences": {
                "emailEnabled": True,
                "digestMode": "daily",
                "watchlistEnabled": True,
                "advisoriesEnabled": True,
                "repeatedWarningsEnabled": True,
                "teamAlertsEnabled": True,
                "updatedAt": "2026-04-09T00:00:00Z",
            },
            "exceptions": [
                {
                    "exceptionId": "artifact:codex:project:workspace_skill",
                    "scope": "artifact",
                    "harness": None,
                    "artifactId": "codex:project:workspace_skill",
                    "publisher": None,
                    "reason": "Temporary allow for workspace skill",
                    "owner": "guard@example.com",
                    "source": "manual",
                    "expiresAt": "2099-01-01T00:00:00Z",
                    "createdAt": "2026-04-09T00:00:00Z",
                    "updatedAt": "2026-04-09T00:00:00Z",
                }
            ],
            "teamPolicyPack": {
                "name": "Security team default",
                "sharedHarnessDefaults": {"codex": "enforce"},
                "allowedPublishers": ["hashgraph-online"],
                "blockedArtifacts": [],
                "alertChannel": "email",
                "updatedAt": "2026-04-09T00:00:00Z",
                "auditTrail": [],
            },
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            login_rc = main(
                [
                    "guard",
                    "login",
                    "--home",
                    str(home_dir),
                    "--sync-url",
                    f"http://127.0.0.1:{server.server_port}/receipts",
                    "--token",
                    "demo-token",
                    "--json",
                ]
            )
            json.loads(capsys.readouterr().out)

            run_rc = main(
                [
                    "guard",
                    "run",
                    "codex",
                    "--home",
                    str(home_dir),
                    "--workspace",
                    str(workspace_dir),
                    "--dry-run",
                    "--default-action",
                    "allow",
                    "--json",
                ]
            )
            json.loads(capsys.readouterr().out)

            sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
            sync_output = json.loads(capsys.readouterr().out)

            advisories_rc = main(["guard", "advisories", "--home", str(home_dir), "--json"])
            advisories_output = json.loads(capsys.readouterr().out)
            policies_rc = main(["guard", "policies", "--home", str(home_dir), "--json"])
            policies_output = json.loads(capsys.readouterr().out)
            exceptions_rc = main(["guard", "exceptions", "--home", str(home_dir), "--json"])
            exceptions_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert login_rc == 0
        assert run_rc == 0
        assert sync_rc == 0
        assert advisories_rc == 0
        assert policies_rc == 0
        assert exceptions_rc == 0
        assert sync_output["advisories_stored"] == 1
        assert advisories_output["items"][0]["publisher"] == "hashgraph-online"
        assert advisories_output["items"][0]["headline"] == "Publisher rotated to a new remote domain."
        assert any(item["source"] == "cloud-sync" and item["action"] == "allow" for item in policies_output["items"])
        assert any(
            item["source"] == "team-policy" and item["publisher"] == "hashgraph-online"
            for item in policies_output["items"]
        )
        assert exceptions_output["items"][0]["artifact_id"] == "codex:project:workspace_skill"

    def test_guard_exceptions_handles_synced_naive_expiry_timestamps(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        _SyncRequestHandler.response_payload = {
            "syncedAt": "2026-04-09T00:00:00Z",
            "receiptsStored": 0,
            "inventoryStored": 0,
            "inventoryDiff": {"generatedAt": "2026-04-09T00:00:00Z", "items": []},
            "advisories": [],
            "exceptions": [
                {
                    "exceptionId": "artifact:codex:project:workspace_skill",
                    "scope": "artifact",
                    "artifactId": "codex:project:workspace_skill",
                    "reason": "Temporary allow for workspace skill",
                    "owner": "guard@example.com",
                    "source": "manual",
                    "expiresAt": "2099-01-01T00:00:00",
                }
            ],
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            login_rc = main(
                [
                    "guard",
                    "login",
                    "--home",
                    str(home_dir),
                    "--sync-url",
                    f"http://127.0.0.1:{server.server_port}/receipts",
                    "--token",
                    "demo-token",
                    "--json",
                ]
            )
            json.loads(capsys.readouterr().out)

            sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
            json.loads(capsys.readouterr().out)
            exceptions_rc = main(["guard", "exceptions", "--home", str(home_dir), "--json"])
            exceptions_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert login_rc == 0
        assert sync_rc == 0
        assert exceptions_rc == 0
        assert exceptions_output["items"][0]["expires_at"] == "2099-01-01T00:00:00+00:00"

    def test_guard_sync_clears_cached_policy_when_server_omits_it(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        _SyncRequestHandler.response_payload = {
            "syncedAt": "2026-04-09T00:00:00Z",
            "receiptsStored": 0,
            "inventoryStored": 0,
            "inventoryDiff": {"generatedAt": "2026-04-09T00:00:00Z", "items": []},
            "advisories": [],
            "policy": {
                "mode": "enforce",
                "defaultAction": "warn",
                "unknownPublisherAction": "review",
                "changedHashAction": "require-reapproval",
            },
            "alertPreferences": {
                "emailEnabled": True,
                "digestMode": "daily",
            },
            "teamPolicyPack": {
                "name": "Security team default",
                "allowedPublishers": ["hashgraph-online"],
            },
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            login_rc = main(
                [
                    "guard",
                    "login",
                    "--home",
                    str(home_dir),
                    "--sync-url",
                    f"http://127.0.0.1:{server.server_port}/receipts",
                    "--token",
                    "demo-token",
                    "--json",
                ]
            )
            json.loads(capsys.readouterr().out)

            first_sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
            json.loads(capsys.readouterr().out)

            _SyncRequestHandler.response_payload = {
                "syncedAt": "2026-04-10T00:00:00Z",
                "receiptsStored": 0,
                "inventoryStored": 0,
                "inventoryDiff": {"generatedAt": "2026-04-10T00:00:00Z", "items": []},
                "advisories": [],
            }

            second_sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
            json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        policy_rc = main(["guard", "policies", "--home", str(home_dir), "--json"])
        policy_output = json.loads(capsys.readouterr().out)
        store = GuardStore(home_dir)

        assert login_rc == 0
        assert first_sync_rc == 0
        assert second_sync_rc == 0
        assert policy_rc == 0
        assert not any(item["source"] == "cloud-sync" for item in policy_output["items"])
        assert store.get_sync_payload("policy") == {}
        assert store.get_sync_payload("alert_preferences") == {}
        assert store.get_sync_payload("team_policy_pack") == {}

    def test_guard_run_auto_syncs_cloud_policy_bundle(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
        _SyncRequestHandler.response_payload = {
            "syncedAt": "2026-04-09T00:00:00Z",
            "receiptsStored": 0,
            "inventoryStored": 0,
            "inventoryDiff": {"generatedAt": "2026-04-09T00:00:00Z", "items": []},
            "advisories": [],
            "policy": {
                "mode": "enforce",
                "defaultAction": "warn",
                "unknownPublisherAction": "review",
                "changedHashAction": "allow",
                "newNetworkDomainAction": "warn",
                "subprocessAction": "block",
                "telemetryEnabled": False,
                "syncEnabled": True,
                "updatedAt": "2026-04-09T00:00:00Z",
            },
            "alertPreferences": {
                "emailEnabled": True,
                "digestMode": "daily",
                "watchlistEnabled": True,
                "advisoriesEnabled": True,
                "repeatedWarningsEnabled": True,
                "teamAlertsEnabled": True,
                "updatedAt": "2026-04-09T00:00:00Z",
            },
            "exceptions": [],
            "teamPolicyPack": {
                "name": "Security team default",
                "sharedHarnessDefaults": {"codex": "enforce"},
                "allowedPublishers": [],
                "blockedArtifacts": ["codex:global:global_tools"],
                "alertChannel": "email",
                "updatedAt": "2026-04-09T00:00:00Z",
                "auditTrail": [],
            },
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            login_rc = main(
                [
                    "guard",
                    "login",
                    "--home",
                    str(home_dir),
                    "--sync-url",
                    f"http://127.0.0.1:{server.server_port}/receipts",
                    "--token",
                    "demo-token",
                    "--json",
                ]
            )
            json.loads(capsys.readouterr().out)

            run_rc = main(
                [
                    "guard",
                    "run",
                    "codex",
                    "--home",
                    str(home_dir),
                    "--workspace",
                    str(workspace_dir),
                    "--dry-run",
                    "--json",
                ]
            )
            run_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert login_rc == 0
        assert run_rc == 1
        assert _SyncRequestHandler.captured_body is not None
        assert run_output["blocked"] is True
        assert any(
            artifact["artifact_id"] == "codex:global:global_tools" and artifact["policy_action"] == "block"
            for artifact in run_output["artifacts"]
        )

    def test_guard_invalid_harness_returns_parser_error(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "guard",
                    "detect",
                    "codxe",
                    "--home",
                    str(home_dir),
                    "--workspace",
                    str(workspace_dir),
                ]
            )

        assert excinfo.value.code == 2
        assert "Unsupported harness: codxe" in capsys.readouterr().err

    def test_guard_sync_without_login_returns_cli_error(self, tmp_path, capsys):
        home_dir = tmp_path / "home"

        rc = main(
            [
                "guard",
                "sync",
                "--home",
                str(home_dir),
            ]
        )

        assert rc == 1
        stderr = capsys.readouterr().err
        assert "Guard Cloud is not connected yet." in stderr
        assert "Run `hol-guard connect`" in stderr

    def test_guard_sync_reports_remote_sync_errors_in_json_mode(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        _SyncRequestHandler.response_code = 403
        _SyncRequestHandler.response_payload = {
            "error": "Guard sync requires a Pro or Team plan.",
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            login_rc = main(
                [
                    "guard",
                    "login",
                    "--home",
                    str(home_dir),
                    "--sync-url",
                    f"http://127.0.0.1:{server.server_port}/receipts",
                    "--token",
                    "demo-token",
                    "--json",
                ]
            )
            json.loads(capsys.readouterr().out)

            sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
            sync_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            _SyncRequestHandler.response_code = 200
            _SyncRequestHandler.response_payload = {
                "syncedAt": "2026-04-09T00:00:00Z",
                "receiptsStored": 1,
            }

        assert login_rc == 0
        assert sync_rc == 1
        assert sync_output == {
            "synced": False,
            "error": "Guard sync requires a Pro or Team plan.",
        }

    def test_guard_sync_reports_non_string_url_errors_in_json_mode(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        main(
            [
                "guard",
                "login",
                "--home",
                str(home_dir),
                "--sync-url",
                "https://hol.org/api/guard/receipts/sync",
                "--token",
                "demo-token",
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.runtime.runner.urllib.request.urlopen",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))
            ),
        )

        sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
        sync_output = json.loads(capsys.readouterr().out)

        assert sync_rc == 1
        assert sync_output == {
            "synced": False,
            "error": "Guard sync failed: [Errno 61] Connection refused",
        }

    def test_guard_doctor_reports_runtime_mismatch_for_cursor(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        monkeypatch.setattr(cursor_adapter_module, "_command_available", lambda command: True)
        monkeypatch.setattr(
            cursor_adapter_module,
            "_run_command_probe",
            lambda command, timeout_seconds=5: {
                "command": command,
                "ok": True,
                "return_code": 0,
                "stdout": (
                    "Loading MCPs...\nNo MCP servers configured (expected in .cursor/mcp.json or ~/.cursor/mcp.json)"
                ),
                "stderr": "",
            },
        )

        rc = main(
            [
                "guard",
                "doctor",
                "cursor",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["runtime_probe"]["reported_artifacts"] == 0
        assert any("Cursor CLI reported no MCP servers" in warning for warning in output["warnings"])
