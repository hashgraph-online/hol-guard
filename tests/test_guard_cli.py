"""Behavior tests for the Guard CLI surface."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters import cursor as cursor_adapter_module
from codex_plugin_scanner.guard.cli import commands as guard_commands_module

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

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        _SyncRequestHandler.captured_headers = {key.lower(): value for key, value in self.headers.items()}
        _SyncRequestHandler.captured_body = json.loads(body)
        self.send_response(self.response_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"syncedAt":"2026-04-09T00:00:00Z","receiptsStored":1}')

    def log_message(self, fmt: str, *args) -> None:
        return


class TestGuardCli:
    def test_guard_requires_a_subcommand(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["guard"])

        assert exc_info.value.code == 2
        assert "the following arguments are required" in capsys.readouterr().err

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
        assert {"codex", "claude-code", "cursor", "gemini", "opencode"} <= harnesses.keys()
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
            home_dir / ".gemini" / "extensions" / "shared" / "gemini-extension.json",
            {
                "name": "shared",
                "mcpServers": {"shared-tools": {"command": "node", "args": ["global.js"]}},
            },
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
            "gemini:project:shared",
            "gemini:project:shared:shared-tools",
        ]

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
        assert "Changed" in output

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
        expected_hook_command = subprocess.list2cmdline(
            [
                sys.executable,
                "-m",
                "codex_plugin_scanner.cli",
                "guard",
                "hook",
                "--guard-home",
                str(home_dir),
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
            ]
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
        expected_hook_command = subprocess.list2cmdline(
            [
                sys.executable,
                "-m",
                "codex_plugin_scanner.cli",
                "guard",
                "hook",
                "--guard-home",
                str(home_dir),
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
            ]
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

    def test_guard_login_and_sync_posts_receipts(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')

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
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert login_rc == 0
        assert run_rc == 0
        assert sync_rc == 0
        assert sync_output["receipts_stored"] == 1
        assert _SyncRequestHandler.captured_headers["authorization"] == "Bearer demo-token"
        assert _SyncRequestHandler.captured_body is not None
        assert len(_SyncRequestHandler.captured_body["receipts"]) >= 1

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
        assert "Guard is not logged in." in capsys.readouterr().err

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
