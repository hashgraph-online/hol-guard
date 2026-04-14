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
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
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

    def test_guard_detect_reports_copilot_surfaces(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(home_dir / ".copilot" / "config.json", {"trusted_repositories": ["demo"]})
        _write_json(
            home_dir / ".copilot" / "mcp-config.json",
            {"servers": {"global-tool": {"command": "npx", "args": ["server.js"]}}},
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
        monkeypatch.setattr(guard_commands_module, "run_consumer_scan", lambda path, intended_harness=None: payload)

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
        assert {"codex", "claude-code", "cursor", "gemini", "opencode"} <= harnesses

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
        assert status_output["cloud_state"] == "paired_active"
        assert status_output["last_sync_at"] == "2026-04-09T00:00:00Z"
        assert _SyncRequestHandler.captured_headers["authorization"] == "Bearer demo-token"
        assert _SyncRequestHandler.captured_body is not None
        assert len(_SyncRequestHandler.captured_body["receipts"]) >= 1
        assert len(_SyncRequestHandler.captured_body["inventory"]) >= 1

    def test_guard_connect_save_only_surfaces_waiting_state(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        guard_home = tmp_path / "guard-home"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "connect",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--workspace",
                str(workspace_dir),
                "--sync-url",
                "https://hol.org/registry/api/v1/guard/receipts",
                "--token",
                "demo-token",
                "--save-only",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["credentials_saved"] is True
        assert output["sync_attempted"] is False
        assert output["cloud_state"] == "paired_waiting"
        assert output["sync_configured"] is True
        assert output["dashboard_url"] == "https://hol.org/guard"
        assert output["connect_url"] == "https://hol.org/guard/connect"

    def test_guard_connect_rejects_empty_credentials(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        guard_home = tmp_path / "guard-home"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "connect",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--workspace",
                str(workspace_dir),
                "--sync-url",
                "",
                "--token",
                "",
            ]
        )
        stderr = capsys.readouterr().err

        assert rc == 2
        assert "connect requires non-empty --sync-url and --token when saving credentials" in stderr

    def test_guard_connect_syncs_and_surfaces_cloud_state(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        guard_home = tmp_path / "guard-home"
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
        try:
            run_rc = main(
                [
                    "guard",
                    "run",
                    "codex",
                    "--home",
                    str(home_dir),
                    "--guard-home",
                    str(guard_home),
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
                    "--guard-home",
                    str(guard_home),
                    "--workspace",
                    str(workspace_dir),
                    "--sync-url",
                    f"http://127.0.0.1:{server.server_port}/receipts",
                    "--token",
                    "demo-token",
                    "--json",
                ]
            )
            connect_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert run_rc == 0
        assert connect_rc == 0
        assert connect_output["credentials_saved"] is True
        assert connect_output["sync_attempted"] is True
        assert connect_output["sync_succeeded"] is True
        assert connect_output["cloud_state"] == "paired_active"
        assert connect_output["dashboard_url"] == f"http://127.0.0.1:{server.server_port}/guard"
        assert connect_output["advisory_count"] == 1
        assert connect_output["team_policy_active"] is True
        assert _SyncRequestHandler.captured_headers["authorization"] == "Bearer demo-token"
        assert _SyncRequestHandler.captured_body is not None
        assert len(_SyncRequestHandler.captured_body["receipts"]) >= 1

    def test_guard_connect_save_only_clears_previous_sync_state(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        guard_home = tmp_path / "guard-home"
        _build_guard_fixture(home_dir, workspace_dir)
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
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            first_connect_rc = main(
                [
                    "guard",
                    "connect",
                    "--home",
                    str(home_dir),
                    "--guard-home",
                    str(guard_home),
                    "--workspace",
                    str(workspace_dir),
                    "--sync-url",
                    f"http://127.0.0.1:{server.server_port}/receipts",
                    "--token",
                    "demo-token",
                    "--json",
                ]
            )
            first_connect_output = json.loads(capsys.readouterr().out)

            second_connect_rc = main(
                [
                    "guard",
                    "connect",
                    "--home",
                    str(home_dir),
                    "--guard-home",
                    str(guard_home),
                    "--workspace",
                    str(workspace_dir),
                    "--sync-url",
                    "https://hol.org/registry/api/v1/guard/receipts",
                    "--token",
                    "second-token",
                    "--save-only",
                    "--json",
                ]
            )
            second_connect_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert first_connect_rc == 0
        assert first_connect_output["cloud_state"] == "paired_active"
        assert first_connect_output["advisory_count"] == 1
        assert second_connect_rc == 0
        assert second_connect_output["cloud_state"] == "paired_waiting"
        assert second_connect_output["advisory_count"] == 0
        assert second_connect_output["last_sync_at"] is None

    def test_guard_connect_handles_invalid_sync_response(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        guard_home = tmp_path / "guard-home"
        _build_guard_fixture(home_dir, workspace_dir)
        _SyncRequestHandler.raw_response_body = "not-json"

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connect_rc = main(
                [
                    "guard",
                    "connect",
                    "--home",
                    str(home_dir),
                    "--guard-home",
                    str(guard_home),
                    "--workspace",
                    str(workspace_dir),
                    "--sync-url",
                    f"http://127.0.0.1:{server.server_port}/receipts",
                    "--token",
                    "demo-token",
                    "--json",
                ]
            )
            connect_output = json.loads(capsys.readouterr().out)
        finally:
            _SyncRequestHandler.raw_response_body = None
            server.shutdown()
            thread.join(timeout=5)

        assert connect_rc == 1
        assert connect_output["sync_attempted"] is True
        assert connect_output["sync_succeeded"] is False
        assert connect_output["cloud_state"] == "paired_waiting"
        assert "Expecting value" in str(connect_output["sync_error"])

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
