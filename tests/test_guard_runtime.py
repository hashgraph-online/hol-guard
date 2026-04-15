"""Runtime behavior tests for Guard hook, proxy, and daemon surfaces."""

from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.cli import render as guard_render_module
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from codex_plugin_scanner.guard.config import GuardConfig, load_guard_config
from codex_plugin_scanner.guard.consumer import artifact_hash, evaluate_detection
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.policy import decide_action
from codex_plugin_scanner.guard.proxy import RemoteGuardProxy, StdioGuardProxy
from codex_plugin_scanner.guard.receipts import build_receipt
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore


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


class _RemoteProxyHandler(BaseHTTPRequestHandler):
    captured_headers: ClassVar[dict[str, str]] = {}
    captured_body: ClassVar[dict[str, object] | None] = None

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        _RemoteProxyHandler.captured_headers = {key.lower(): value for key, value in self.headers.items()}
        _RemoteProxyHandler.captured_body = json.loads(body)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}).encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:
        return


class TestGuardRuntime:
    def test_guard_store_initializes_runtime_tables_and_receipt_columns(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")

        assert {
            "artifact_diffs",
            "artifact_hashes",
            "artifact_snapshots",
            "harness_installations",
            "managed_installs",
            "policy_decisions",
            "publisher_cache",
            "runtime_receipts",
            "sync_state",
        } <= set(store.list_table_names())

        store.add_receipt(
            build_receipt(
                harness="codex",
                artifact_id="codex:project:workspace-tools",
                artifact_hash="hash-1",
                policy_decision="allow",
                capabilities_summary="mcp server • stdio • node",
                changed_capabilities=["first_seen"],
                provenance_summary="project artifact defined at .codex/config.toml",
                artifact_name="workspace-tools",
                source_scope="project",
            )
        )
        receipts = store.list_receipts(limit=1)

        assert receipts[0]["capabilities_summary"] == "mcp server • stdio • node"

    def test_guard_load_config_parses_override_sections(self, tmp_path):
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir(parents=True, exist_ok=True)
        _write_text(
            guard_home / "config.toml",
            "\n".join(
                [
                    'default_action = "warn"',
                    "[harnesses.codex]",
                    'action = "allow"',
                    '[publishers."hashgraph-online"]',
                    'action = "sandbox-required"',
                    '[artifacts."codex:project:workspace-tools"]',
                    'action = "block"',
                ]
            )
            + "\n",
        )

        config = load_guard_config(guard_home)

        assert config.resolve_action_override("codex", None, None) == "allow"
        assert config.resolve_action_override("codex", None, "hashgraph-online") == "sandbox-required"
        assert config.resolve_action_override("codex", "codex:project:workspace-tools", None) == "block"

    def test_guard_load_config_accepts_default_action_inside_override_sections(self, tmp_path):
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir(parents=True, exist_ok=True)
        _write_text(
            guard_home / "config.toml",
            "\n".join(
                [
                    "[harnesses.codex]",
                    'default_action = "allow"',
                    '[publishers."hashgraph-online"]',
                    'default_action = "sandbox-required"',
                    '[artifacts."codex:project:workspace-tools"]',
                    'default_action = "block"',
                ]
            )
            + "\n",
        )

        config = load_guard_config(guard_home)

        assert config.resolve_action_override("codex", None, None) == "allow"
        assert config.resolve_action_override("codex", None, "hashgraph-online") == "sandbox-required"
        assert config.resolve_action_override("codex", "codex:project:workspace-tools", None) == "block"

    def test_guard_load_config_parses_approval_wait_timeout(self, tmp_path):
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir(parents=True, exist_ok=True)
        _write_text(guard_home / "config.toml", "approval_wait_timeout_seconds = 7\n")

        config = load_guard_config(guard_home)

        assert config.approval_wait_timeout_seconds == 7

    def test_guard_evaluate_detection_uses_config_action_overrides(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        config = GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=None,
            harness_actions={"codex": "allow"},
            publisher_actions={"hashgraph-online": "sandbox-required"},
            artifact_actions={"codex:project:workspace-tools": "block"},
        )
        artifact = GuardArtifact(
            artifact_id="codex:project:workspace-tools",
            name="workspace-tools",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="node",
            args=("workspace.js",),
            transport="stdio",
            publisher="hashgraph-online",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        evaluation = evaluate_detection(detection, store, config, persist=True)
        receipts = store.list_receipts(limit=1)

        assert evaluation["blocked"] is True
        assert evaluation["artifacts"][0]["policy_action"] == "block"
        assert receipts[0]["capabilities_summary"] == "mcp server • stdio • node"

    def test_guard_evaluate_detection_blocks_for_sandbox_required_override(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        config = GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=None,
            publisher_actions={"hashgraph-online": "sandbox-required"},
        )
        artifact = GuardArtifact(
            artifact_id="codex:project:workspace-tools",
            name="workspace-tools",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="node",
            args=("workspace.js",),
            transport="stdio",
            publisher="hashgraph-online",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        evaluation = evaluate_detection(detection, store, config, persist=False)

        assert evaluation["blocked"] is True
        assert evaluation["artifacts"][0]["policy_action"] == "sandbox-required"

    def test_guard_evaluate_detection_uses_default_action_for_first_seen_artifacts(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        config = GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=None,
            default_action="warn",
            changed_hash_action="require-reapproval",
        )
        artifact = GuardArtifact(
            artifact_id="codex:project:workspace-tools",
            name="workspace-tools",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="node",
            args=("workspace.js",),
            transport="stdio",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        evaluation = evaluate_detection(detection, store, config, default_action="allow", persist=False)

        assert evaluation["blocked"] is False
        assert evaluation["artifacts"][0]["changed_fields"] == ["first_seen"]
        assert evaluation["artifacts"][0]["policy_action"] == "allow"

    def test_guard_run_keeps_prior_snapshot_when_reapproval_blocks(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        baseline = GuardArtifact(
            artifact_id="codex:project:workspace-tools",
            name="workspace-tools",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="node",
            args=("workspace.js",),
            transport="stdio",
        )
        changed = GuardArtifact(
            artifact_id=baseline.artifact_id,
            name=baseline.name,
            harness=baseline.harness,
            artifact_type=baseline.artifact_type,
            source_scope=baseline.source_scope,
            config_path=baseline.config_path,
            command="node",
            args=("workspace.js", "--changed"),
            transport="stdio",
        )
        baseline_hash = artifact_hash(baseline)
        store.save_snapshot(
            "codex",
            baseline.artifact_id,
            {**baseline.to_dict(), "artifact_hash": baseline_hash},
            baseline_hash,
            "2026-04-10T00:00:00+00:00",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(baseline.config_path,),
            artifacts=(changed,),
        )
        config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

        first = evaluate_detection(detection, store, config, default_action="allow", persist=True)
        stored_after_first = store.get_snapshot("codex", baseline.artifact_id)
        second = evaluate_detection(detection, store, config, default_action="allow", persist=True)

        assert first["blocked"] is True
        assert stored_after_first is not None
        assert stored_after_first["artifact_hash"] == baseline_hash
        assert second["blocked"] is True
        assert second["artifacts"][0]["changed"] is True

    def test_guard_diff_surfaces_removed_artifacts(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        removed = GuardArtifact(
            artifact_id="codex:global:global-tools",
            name="global-tools",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="global",
            config_path=str(tmp_path / "home" / ".codex" / "config.toml"),
            command="python",
            args=("-m", "http.server"),
            transport="stdio",
        )
        removed_hash = artifact_hash(removed)
        store.save_snapshot(
            "codex",
            removed.artifact_id,
            {**removed.to_dict(), "artifact_hash": removed_hash},
            removed_hash,
            "2026-04-10T00:00:00+00:00",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(),
            artifacts=(),
        )
        config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

        evaluation = evaluate_detection(detection, store, config, default_action="allow", persist=False)

        assert evaluation["blocked"] is True
        assert len(evaluation["artifacts"]) == 1
        artifact = evaluation["artifacts"][0]

        assert artifact["artifact_id"] == "codex:global:global-tools"
        assert artifact["artifact_name"] == "global-tools"
        assert artifact["changed"] is True
        assert artifact["changed_fields"] == ["removed"]
        assert artifact["policy_action"] == "require-reapproval"
        assert artifact["artifact_hash"] == removed_hash
        assert artifact["removed"] is True
        assert artifact["source_scope"] == "global"
        assert artifact["config_path"] == str(tmp_path / "home" / ".codex" / "config.toml")
        assert artifact["artifact_label"] == "MCP server"
        assert artifact["source_label"] == "global Codex config"
        assert "global-tools" in str(artifact["trigger_summary"])
        assert "disappeared" in str(artifact["why_now"]).lower()

    def test_guard_hook_records_receipt_from_stdin_event(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        event = {
            "event": "PreToolUse",
            "tool_name": "workspace-tools",
            "artifact_id": "claude-code:workspace-tools",
            "artifact_name": "workspace-tools",
            "policy_action": "allow",
            "changed_capabilities": ["tool_name", "arguments"],
            "provenance_summary": "project artifact defined at .mcp.json",
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

        rc = main(
            [
                "guard",
                "hook",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--harness",
                "claude-code",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        receipts = GuardStore(Path(home_dir)).list_receipts()

        assert rc == 0
        assert output["recorded"] is True
        assert output["artifact_id"] == "claude-code:workspace-tools"
        assert receipts[0]["artifact_id"] == "claude-code:workspace-tools"
        assert receipts[0]["user_override"] is None

    def test_guard_hook_blocks_require_reapproval(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        event = {
            "event": "PreToolUse",
            "tool_name": "workspace-tools",
            "artifact_id": "claude-code:project:workspace-tools",
            "artifact_name": "workspace-tools",
            "policy_action": "require-reapproval",
            "changed_capabilities": ["tool_name"],
            "provenance_summary": "project artifact defined at .mcp.json",
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

        rc = main(
            [
                "guard",
                "hook",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--harness",
                "claude-code",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["policy_action"] == "require-reapproval"

    def test_guard_hook_fallback_artifact_id_uses_scope(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        event = {
            "event": "PreToolUse",
            "tool_name": "workspace-tools",
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

        rc = main(
            [
                "guard",
                "hook",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--harness",
                "claude-code",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["artifact_id"] == "claude-code:project:workspace-tools"

    def test_guard_hook_uses_copilot_repo_hook_runtime_path(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "tool_name": "read_file",
            "tool_input": {"path": str(home_dir / ".env")},
            "policy_action": "require-reapproval",
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")

        rc = main(
            [
                "guard",
                "hook",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--harness",
                "copilot",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["artifact_type"] == "file_read_request"
        assert output["policy_action"] == "require-reapproval"
        assert output["path_summary"] == str(home_dir / ".env")

    def test_guard_hook_normalizes_copilot_camel_case_payload(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "toolName": "view",
            "toolArgs": json.dumps({"path": str(home_dir / ".env")}),
            "sourceScope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")

        rc = main(
            [
                "guard",
                "hook",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--harness",
                "copilot",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["artifact_type"] == "file_read_request"
        assert output["policy_action"] == "require-reapproval"
        assert output["path_summary"] == str(home_dir / ".env")

    def test_guard_hook_emits_copilot_native_deny_response(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "toolName": "view",
            "toolArgs": json.dumps({"path": str(home_dir / ".env")}),
            "sourceScope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")

        rc = main(
            [
                "guard",
                "hook",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--harness",
                "copilot",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["permissionDecision"] == "deny"
        assert "approve" in output["permissionDecisionReason"]
        assert "http://127.0.0.1:4455" in output["permissionDecisionReason"]

    def test_guard_hook_emits_copilot_native_allow_response_for_safe_requests(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "toolName": "view",
            "toolArgs": json.dumps({"path": str(workspace_dir / "README.md")}),
            "sourceScope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

        rc = main(
            [
                "guard",
                "hook",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--harness",
                "copilot",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output == {"permissionDecision": "allow"}

    def test_guard_run_returns_structured_error_when_executable_missing(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
        monkeypatch.setattr(
            guard_runner_module.subprocess,
            "run",
            lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("codex not found")),
        )

        rc = main(
            [
                "guard",
                "run",
                "claude-code",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--default-action",
                "allow",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 127
        assert output["launched"] is False
        assert output["return_code"] == 127
        assert "codex not found" in output["launch_error"]

    def test_guard_run_prompt_allow_once_launches_and_records_override(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        answers = iter(["1", "1"])
        monkeypatch.setattr(guard_commands_module.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("rich.console.Console.input", lambda self, prompt="": next(answers))
        monkeypatch.setattr(
            guard_runner_module.subprocess,
            "run",
            lambda *args, **kwargs: type("CompletedProcess", (), {"returncode": 0})(),
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
            ]
        )
        output = capsys.readouterr().out
        receipts = GuardStore(Path(home_dir)).list_receipts(limit=10)

        assert rc == 0
        assert "Launch allowed" in output
        assert any(item.get("user_override") == "allow-once" for item in receipts)

    def test_guard_run_prompt_allow_artifact_persists_for_next_run(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        answers = iter(["2", "2"])
        monkeypatch.setattr(guard_commands_module.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("rich.console.Console.input", lambda self, prompt="": next(answers))
        monkeypatch.setattr(
            guard_runner_module.subprocess,
            "run",
            lambda *args, **kwargs: type("CompletedProcess", (), {"returncode": 0})(),
        )

        first_rc = main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
            ]
        )
        first_output = capsys.readouterr().out

        second_rc = main(
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
        second_output = json.loads(capsys.readouterr().out)

        assert first_rc == 0
        assert "Launch allowed" in first_output
        assert second_rc == 0
        assert second_output["blocked"] is False
        assert all(item["policy_action"] == "allow" for item in second_output["artifacts"])

    def test_guard_run_headless_blocks_with_review_hint_without_opening_browser(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
        opened_urls: list[str] = []
        monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda url: opened_urls.append(url) or True)

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

        assert rc == 1
        assert output["approval_center_url"] == "http://127.0.0.1:4455"
        assert output["blocked"] is True
        assert output["approval_delivery"]["destination"] == "browser"
        assert opened_urls == []

    def test_headless_approval_resolver_skips_browser_for_hook_first_harnesses(self, tmp_path, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        store = GuardStore(home_dir)
        config = GuardConfig(guard_home=home_dir, workspace=workspace_dir, approval_wait_timeout_seconds=1)
        artifact = GuardArtifact(
            artifact_id="copilot:project:workspace-tools",
            name="workspace-tools",
            harness="copilot",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(workspace_dir / ".vscode" / "mcp.json"),
            command="python",
            args=("-m", "http.server", "9100"),
            transport="stdio",
        )
        detection = HarnessDetection(
            harness="copilot",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )
        payload = {
            "blocked": True,
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "artifact_hash": artifact_hash(artifact),
                    "policy_action": "require-reapproval",
                    "changed_fields": ["args"],
                    "artifact_type": artifact.artifact_type,
                    "source_scope": artifact.source_scope,
                    "config_path": artifact.config_path,
                    "launch_target": "python -m http.server 9100",
                }
            ],
        }
        opened_urls: list[str] = []
        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
        monkeypatch.setattr(guard_commands_module.webbrowser, "open", lambda url: opened_urls.append(url) or True)

        blocked_resolver = guard_commands_module._headless_approval_resolver(
            args=argparse.Namespace(harness="copilot"),
            context=HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
            store=store,
            config=config,
        )
        result = blocked_resolver(detection, payload)

        assert opened_urls == []
        assert result["approval_center_url"] == "http://127.0.0.1:4455"
        assert result["approval_delivery"]["destination"] == "harness"
        assert result["approval_delivery"]["prompt_channel"] == "hook"
        assert result["approval_wait"]["resolved"] is False

    def test_guard_run_dry_run_human_output_is_summary_first(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

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
            ]
        )
        output = capsys.readouterr().out

        assert rc == 1
        assert "What changed" in output
        assert "Next step" in output
        assert "rerun without --dry-run" in output.lower()
        assert "Fields" not in output
        assert "first_seen" not in output

    def test_guard_run_renderer_coalesces_replaced_artifacts(self, capsys):
        emit_guard_payload(
            "run",
            {
                "harness": "codex",
                "blocked": True,
                "dry_run": True,
                "launched": False,
                "receipts_recorded": 2,
                "artifacts": [
                    {
                        "artifact_id": "codex:project:chrome-devtools:new",
                        "artifact_name": "chrome-devtools",
                        "changed": True,
                        "changed_fields": ["first_seen"],
                        "policy_action": "require-reapproval",
                        "artifact_label": "MCP server",
                        "why_now": "It is new in this codex workspace, so Guard paused it for review.",
                        "risk_summary": "Connects to a remote server.",
                    },
                    {
                        "artifact_id": "codex:project:chrome-devtools:old",
                        "artifact_name": "chrome-devtools",
                        "changed": True,
                        "changed_fields": ["removed"],
                        "policy_action": "require-reapproval",
                        "artifact_label": "MCP server",
                        "why_now": (
                            "It disappeared from the harness config, so Guard paused the change until you "
                            "confirm the removal."
                        ),
                    },
                ],
            },
            False,
        )
        output = capsys.readouterr().out

        assert "chrome-devtools" in output
        assert output.lower().count("chrome-devtools") == 1
        assert "definition" in output.lower()
        assert "replaced" in output.lower()
        assert "first_seen" not in output
        assert "removed" not in output

    def test_guard_run_renderer_keeps_same_named_artifacts_separate_across_configs(self, capsys):
        emit_guard_payload(
            "run",
            {
                "harness": "codex",
                "blocked": True,
                "dry_run": True,
                "launched": False,
                "receipts_recorded": 2,
                "artifacts": [
                    {
                        "artifact_id": "codex:project:chrome-devtools:new",
                        "artifact_name": "chrome-devtools",
                        "changed": True,
                        "changed_fields": ["first_seen"],
                        "policy_action": "require-reapproval",
                        "artifact_label": "MCP server",
                        "source_scope": "project",
                        "config_path": "/workspace/.codex/config.toml",
                        "why_now": "It is new in this codex workspace, so Guard paused it for review.",
                    },
                    {
                        "artifact_id": "codex:global:chrome-devtools:old",
                        "artifact_name": "chrome-devtools",
                        "changed": True,
                        "changed_fields": ["removed"],
                        "policy_action": "require-reapproval",
                        "artifact_label": "MCP server",
                        "source_scope": "global",
                        "config_path": "/home/.codex/config.toml",
                        "why_now": (
                            "It disappeared from the global harness config, so Guard paused the change until "
                            "you confirm the removal."
                        ),
                    },
                ],
            },
            False,
        )
        output = capsys.readouterr().out

        assert "chrome-devtools" in output
        assert output.lower().count("chrome-devtools") == 2
        assert "definition replaced" not in output.lower()

    def test_guard_run_renderer_filters_unchanged_artifacts_and_counts_review_items(self, capsys):
        emit_guard_payload(
            "run",
            {
                "harness": "codex",
                "blocked": True,
                "dry_run": True,
                "launched": False,
                "receipts_recorded": 3,
                "artifacts": [
                    {
                        "artifact_id": "codex:project:stable-tool",
                        "artifact_name": "stable-tool",
                        "changed": False,
                        "changed_fields": [],
                        "policy_action": "allow",
                        "why_now": "Guard matched an existing allow rule for this exact version.",
                    },
                    {
                        "artifact_id": "codex:project:already-approved",
                        "artifact_name": "already-approved",
                        "changed": True,
                        "changed_fields": ["command"],
                        "policy_action": "allow",
                        "why_now": "Guard matched an existing allow rule for this exact definition.",
                    },
                    {
                        "artifact_id": "codex:project:review-tool",
                        "artifact_name": "review-tool",
                        "changed": True,
                        "changed_fields": ["first_seen"],
                        "policy_action": "require-reapproval",
                        "why_now": "It is new in this codex workspace, so Guard paused it for review.",
                    },
                ],
            },
            False,
        )
        output = capsys.readouterr().out

        assert "stable-tool" not in output
        assert "already-approved" in output
        assert "review-tool" in output
        assert "Needs review 1" in output

    def test_guard_run_renderer_keeps_unchanged_blockers_visible(self, capsys):
        emit_guard_payload(
            "run",
            {
                "harness": "codex",
                "blocked": True,
                "dry_run": True,
                "launched": False,
                "receipts_recorded": 1,
                "artifacts": [
                    {
                        "artifact_id": "codex:project:blocked-tool",
                        "artifact_name": "blocked-tool",
                        "changed": False,
                        "changed_fields": [],
                        "policy_action": "require-reapproval",
                        "why_now": "Guard blocked this definition because the configured policy does not trust it yet.",
                    }
                ],
            },
            False,
        )
        output = capsys.readouterr().out

        assert "blocked-tool" in output
        assert "Needs review 1" in output

    def test_guard_run_renderer_counts_each_visible_blocker_even_when_rows_coalesce(self, capsys):
        emit_guard_payload(
            "run",
            {
                "harness": "codex",
                "blocked": True,
                "dry_run": True,
                "launched": False,
                "receipts_recorded": 2,
                "artifacts": [
                    {
                        "artifact_id": "codex:project:chrome-devtools:new",
                        "artifact_name": "chrome-devtools",
                        "changed": True,
                        "changed_fields": ["first_seen"],
                        "policy_action": "require-reapproval",
                        "why_now": "It is new in this codex workspace, so Guard paused it for review.",
                    },
                    {
                        "artifact_id": "codex:project:chrome-devtools:old",
                        "artifact_name": "chrome-devtools",
                        "changed": True,
                        "changed_fields": ["removed"],
                        "policy_action": "require-reapproval",
                        "why_now": (
                            "It disappeared from the harness config, so Guard paused the change until you confirm it."
                        ),
                    },
                ],
            },
            False,
        )
        output = capsys.readouterr().out

        assert "Needs review 2" in output
        assert output.lower().count("chrome-devtools") == 1

    def test_guard_run_renderer_leads_blocked_dry_runs_with_full_review_path(self, capsys):
        emit_guard_payload(
            "run",
            {
                "harness": "codex",
                "blocked": True,
                "dry_run": True,
                "launched": False,
                "receipts_recorded": 1,
                "artifacts": [
                    {
                        "artifact_id": "codex:project:blocked-tool",
                        "artifact_name": "blocked-tool",
                        "changed": False,
                        "changed_fields": [],
                        "policy_action": "require-reapproval",
                        "why_now": "Guard blocked this definition because the configured policy does not trust it yet.",
                    }
                ],
            },
            False,
        )
        output = capsys.readouterr().out

        assert "Resolve the blocked launch" in output
        assert "hol-guard run codex" in output
        assert "Inspect only the changed config entries (optional)" in output
        assert "hol-guard diff codex" in output

    def test_guard_run_renderer_counts_only_blocking_actions_as_needing_review(self, capsys):
        emit_guard_payload(
            "run",
            {
                "harness": "codex",
                "blocked": True,
                "dry_run": True,
                "launched": False,
                "receipts_recorded": 2,
                "artifacts": [
                    {
                        "artifact_id": "codex:project:warn-only-tool",
                        "artifact_name": "warn-only-tool",
                        "changed": True,
                        "changed_fields": ["command"],
                        "policy_action": "warn",
                        "why_now": "Guard wants to highlight this change, but it does not block launch.",
                    },
                    {
                        "artifact_id": "codex:project:blocked-tool",
                        "artifact_name": "blocked-tool",
                        "changed": True,
                        "changed_fields": ["first_seen"],
                        "policy_action": "require-reapproval",
                        "why_now": "Guard blocked this definition because the configured policy does not trust it yet.",
                    },
                ],
            },
            False,
        )
        output = capsys.readouterr().out

        assert "warn-only-tool" in output
        assert "blocked-tool" in output
        assert "Needs review 1" in output

    def test_guard_run_renderer_uses_neutral_blocked_copy_for_policy_only_blockers(self, capsys):
        emit_guard_payload(
            "run",
            {
                "harness": "codex",
                "blocked": True,
                "dry_run": True,
                "launched": False,
                "receipts_recorded": 1,
                "artifacts": [
                    {
                        "artifact_id": "codex:project:blocked-tool",
                        "artifact_name": "blocked-tool",
                        "changed": False,
                        "changed_fields": [],
                        "policy_action": "require-reapproval",
                        "why_now": "Guard blocked this definition because the configured policy does not trust it yet.",
                    }
                ],
            },
            False,
        )
        output = capsys.readouterr().out

        assert "Guard found changes that need review before a real launch." not in output
        assert "Guard found artifacts that need review before a real launch." in output

    def test_guard_run_renderer_prefers_context_preserving_rerun_command(self):
        steps = guard_render_module._build_run_steps(
            {
                "harness": "codex",
                "blocked": True,
                "dry_run": True,
                "rerun_command": (
                    "hol-guard run codex --home /guard-home --workspace /workspace "
                    "--default-action warn --arg '--model gpt-5'"
                ),
            },
            blocked=True,
            dry_run=True,
        )

        assert steps[0]["command"] == (
            "hol-guard run codex --home /guard-home --workspace /workspace --default-action warn --arg '--model gpt-5'"
        )

    def test_guard_rerun_command_preserves_run_context(self):
        command = guard_commands_module._guard_rerun_command(
            argparse.Namespace(
                harness="codex",
                home="/guard-home",
                guard_home=None,
                workspace="/workspace",
                default_action="warn",
                passthrough_args=["--model gpt-5"],
            )
        )

        assert command == (
            "hol-guard run codex --home /guard-home --workspace /workspace --default-action warn --arg '--model gpt-5'"
        )

    def test_guard_rerun_command_uses_windows_safe_quoting(self, monkeypatch):
        monkeypatch.setattr(guard_commands_module.sys, "platform", "win32")
        command = guard_commands_module._guard_rerun_command(
            argparse.Namespace(
                harness="codex",
                home=r"C:\Guard Home",
                guard_home=None,
                workspace=r"C:\Workspace Root",
                default_action="warn",
                passthrough_args=["--model gpt-5"],
            )
        )

        expected = subprocess.list2cmdline(
            [
                "hol-guard",
                "run",
                "codex",
                "--home",
                r"C:\Guard Home",
                "--workspace",
                r"C:\Workspace Root",
                "--default-action",
                "warn",
                "--arg",
                "--model gpt-5",
            ]
        )

        assert command == expected

    def test_guard_diff_command_preserves_common_context(self):
        command = guard_commands_module._guard_diff_command(
            argparse.Namespace(
                harness="codex",
                home="/guard-home",
                guard_home=None,
                workspace="/workspace",
            )
        )

        assert command == "hol-guard diff codex --home /guard-home --workspace /workspace"

    def test_guard_run_renderer_uses_context_preserving_diff_command(self):
        steps = guard_render_module._build_run_steps(
            {
                "harness": "codex",
                "blocked": True,
                "dry_run": True,
                "diff_command": "hol-guard diff codex --home /guard-home --workspace /workspace",
            },
            blocked=True,
            dry_run=True,
        )

        assert steps[1]["command"] == "hol-guard diff codex --home /guard-home --workspace /workspace"

    def test_guard_run_renderer_uses_context_preserving_launch_command_for_clean_dry_runs(self):
        steps = guard_render_module._build_run_steps(
            {
                "harness": "codex",
                "dry_run": True,
                "rerun_command": (
                    "hol-guard run codex --home /guard-home --workspace /workspace "
                    "--default-action warn --arg '--model gpt-5'"
                ),
            },
            blocked=False,
            dry_run=True,
        )

        assert steps[0]["command"] == (
            "hol-guard run codex --home /guard-home --workspace /workspace --default-action warn --arg '--model gpt-5'"
        )

    def test_guard_approvals_command_preserves_common_context(self):
        command = guard_commands_module._guard_approvals_command(
            argparse.Namespace(
                harness="codex",
                home="/guard-home",
                guard_home="/guard-db",
                workspace="/workspace",
            )
        )

        assert command == "hol-guard approvals --home /guard-home --guard-home /guard-db --workspace /workspace"

    def test_guard_run_renderer_uses_context_preserving_approvals_command_for_blocked_launches(self):
        steps = guard_render_module._build_run_steps(
            {
                "harness": "codex",
                "approval_center_url": "http://127.0.0.1:4455",
                "approvals_command": "hol-guard approvals --home /guard-home --workspace /workspace",
                "review_hint": "Open the approval center and resolve the pending request.",
            },
            blocked=True,
            dry_run=False,
        )

        assert steps[0]["command"] == "hol-guard approvals --home /guard-home --workspace /workspace"

    def test_guard_run_headless_allow_persists_state_when_approval_center_is_available(
        self, tmp_path, capsys, monkeypatch
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        monkeypatch.setattr(
            guard_runner_module.subprocess,
            "run",
            lambda *args, **kwargs: type("CompletedProcess", (), {"returncode": 0})(),
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
                "--default-action",
                "allow",
            ]
        )
        output = capsys.readouterr().out
        store = GuardStore(home_dir)
        receipts = store.list_receipts(limit=10)
        snapshots = store.list_snapshots("codex")

        assert rc == 0
        assert "Launch allowed" in output
        assert len(receipts) == 2
        assert {
            "codex:global:global_tools",
            "codex:project:workspace_skill",
        } <= set(snapshots)

    def test_guard_run_headless_waits_for_local_approval_and_resumes(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 2\n")

        store = GuardStore(home_dir)
        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
        monkeypatch.setattr(
            guard_runner_module.subprocess,
            "run",
            lambda *args, **kwargs: type("CompletedProcess", (), {"returncode": 0})(),
        )

        def resolve_pending() -> None:
            for _ in range(40):
                pending = store.list_approval_requests(limit=10)
                if pending:
                    for request in pending:
                        apply_approval_resolution(
                            store=store,
                            request_id=str(request["request_id"]),
                            action="allow",
                            scope="artifact",
                            workspace=None,
                            reason="approved from test",
                        )
                    if not store.list_approval_requests(limit=10):
                        return
                threading.Event().wait(0.05)

        worker = threading.Thread(target=resolve_pending, daemon=True)
        worker.start()

        rc = main(
            [
                "guard",
                "run",
                "claude-code",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
            ]
        )
        output = capsys.readouterr().out

        assert rc == 0
        assert "Launch allowed" in output
        assert "Approval received" in output

    def test_guard_run_headless_redetects_before_persisted_resume(self, tmp_path, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 1\n")

        store = GuardStore(home_dir)
        baseline = GuardArtifact(
            artifact_id="claude-code:project:workspace-tools",
            name="workspace-tools",
            harness="claude-code",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(workspace_dir / ".mcp.json"),
            command="python",
            args=("-m", "http.server", "9100"),
            transport="stdio",
        )
        baseline_hash = artifact_hash(baseline)
        store.save_snapshot(
            "claude-code",
            baseline.artifact_id,
            {**baseline.to_dict(), "artifact_hash": baseline_hash},
            baseline_hash,
            "2026-04-10T00:00:00+00:00",
        )
        detections = [
            HarnessDetection(
                harness="claude-code",
                installed=True,
                command_available=True,
                config_paths=(str(workspace_dir / ".mcp.json"),),
                artifacts=(
                    GuardArtifact(
                        artifact_id=baseline.artifact_id,
                        name="workspace-tools",
                        harness="claude-code",
                        artifact_type="mcp_server",
                        source_scope="project",
                        config_path=str(workspace_dir / ".mcp.json"),
                        command="python",
                        args=("-m", "http.server", "9100", "--changed-1"),
                        transport="stdio",
                    ),
                ),
            ),
            HarnessDetection(
                harness="claude-code",
                installed=True,
                command_available=True,
                config_paths=(str(workspace_dir / ".mcp.json"),),
                artifacts=(
                    GuardArtifact(
                        artifact_id=baseline.artifact_id,
                        name="workspace-tools",
                        harness="claude-code",
                        artifact_type="mcp_server",
                        source_scope="project",
                        config_path=str(workspace_dir / ".mcp.json"),
                        command="python",
                        args=("-m", "http.server", "9100", "--changed-2"),
                        transport="stdio",
                    ),
                ),
            ),
        ]
        call_count = {"detect": 0}
        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
        monkeypatch.setattr(
            guard_runner_module.subprocess,
            "run",
            lambda *args, **kwargs: type("CompletedProcess", (), {"returncode": 0})(),
        )

        def fake_detect(harness: str, context):
            call_count["detect"] += 1
            index = min(call_count["detect"] - 1, len(detections) - 1)
            return detections[index]

        monkeypatch.setattr(guard_runner_module, "detect_harness", fake_detect)

        def resolve_pending() -> None:
            for _ in range(40):
                pending = store.list_approval_requests(limit=10)
                if pending:
                    apply_approval_resolution(
                        store=store,
                        request_id=str(pending[0]["request_id"]),
                        action="allow",
                        scope="artifact",
                        workspace=None,
                        reason="approved from test",
                    )
                    return
                threading.Event().wait(0.05)

        worker = threading.Thread(target=resolve_pending, daemon=True)
        worker.start()

        config = GuardConfig(guard_home=home_dir, workspace=workspace_dir, approval_wait_timeout_seconds=1)
        blocked_resolver = guard_commands_module._headless_approval_resolver(
            args=argparse.Namespace(harness="claude-code"),
            context=HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
            store=store,
            config=config,
        )
        result = guard_runner_module.guard_run(
            "claude-code",
            HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
            store,
            config,
            dry_run=False,
            passthrough_args=[],
            default_action=None,
            interactive_resolver=None,
            blocked_resolver=blocked_resolver,
        )

        assert result["blocked"] is True
        assert result["artifacts"][0]["changed_fields"] == ["args"]
        assert result["artifacts"][0]["artifact_hash"] == artifact_hash(detections[-1].artifacts[0])
        assert call_count["detect"] >= 2

    def test_guard_headless_blocked_run_persists_receipts_and_diffs(self, tmp_path, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        store = GuardStore(home_dir)
        baseline = GuardArtifact(
            artifact_id="claude-code:project:workspace-tools",
            name="workspace-tools",
            harness="claude-code",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(workspace_dir / ".mcp.json"),
            command="python",
            args=("-m", "http.server", "9100"),
            transport="stdio",
        )
        baseline_hash = artifact_hash(baseline)
        store.save_snapshot(
            "claude-code",
            baseline.artifact_id,
            {**baseline.to_dict(), "artifact_hash": baseline_hash},
            baseline_hash,
            "2026-04-10T00:00:00+00:00",
        )
        changed = GuardArtifact(
            artifact_id=baseline.artifact_id,
            name=baseline.name,
            harness=baseline.harness,
            artifact_type=baseline.artifact_type,
            source_scope=baseline.source_scope,
            config_path=baseline.config_path,
            command="python",
            args=("-m", "http.server", "9100", "--changed"),
            transport="stdio",
        )
        detection = HarnessDetection(
            harness="claude-code",
            installed=True,
            command_available=True,
            config_paths=(baseline.config_path,),
            artifacts=(changed,),
        )

        monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)

        config = GuardConfig(guard_home=home_dir, workspace=workspace_dir, approval_wait_timeout_seconds=1)
        result = guard_runner_module.guard_run(
            "claude-code",
            HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
            store,
            config,
            dry_run=False,
            passthrough_args=[],
            default_action=None,
            interactive_resolver=None,
            blocked_resolver=lambda _detection, evaluation: evaluation,
        )

        latest_diff = store.get_latest_diff("claude-code", baseline.artifact_id)
        latest_receipt = store.get_latest_receipt("claude-code", baseline.artifact_id)

        assert result["blocked"] is True
        assert latest_diff is not None
        assert latest_diff["current_hash"] == artifact_hash(changed)
        assert latest_receipt is not None
        assert latest_receipt["policy_decision"] == "require-reapproval"

    def test_guard_invalid_changed_hash_action_falls_back_to_reapproval(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        baseline = GuardArtifact(
            artifact_id="codex:project:workspace-tools",
            name="workspace-tools",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="node",
            args=("workspace.js",),
            transport="stdio",
        )
        changed = GuardArtifact(
            artifact_id=baseline.artifact_id,
            name=baseline.name,
            harness=baseline.harness,
            artifact_type=baseline.artifact_type,
            source_scope=baseline.source_scope,
            config_path=baseline.config_path,
            command="node",
            args=("workspace.js", "--changed"),
            transport="stdio",
        )
        baseline_hash = artifact_hash(baseline)
        store.save_snapshot(
            "codex",
            baseline.artifact_id,
            {**baseline.to_dict(), "artifact_hash": baseline_hash},
            baseline_hash,
            "2026-04-10T00:00:00+00:00",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(baseline.config_path,),
            artifacts=(changed,),
        )
        config = GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=None,
            changed_hash_action="require_reapproval",  # type: ignore[arg-type]
        )

        evaluation = evaluate_detection(detection, store, config, default_action="allow", persist=False)

        assert evaluation["blocked"] is True
        assert evaluation["artifacts"][0]["policy_action"] == "require-reapproval"

    def test_guard_invalid_default_action_falls_back_to_reapproval(self, tmp_path):
        config = GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=None,
            default_action="blok",  # type: ignore[arg-type]
        )

        action = decide_action(configured_action=None, default_action=None, config=config, changed=False)

        assert action == "require-reapproval"

    def test_guard_hook_invalid_policy_action_falls_back_to_reapproval(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        event = {
            "event": "PreToolUse",
            "tool_name": "workspace-tools",
            "artifact_id": "claude-code:project:workspace-tools",
            "policy_action": "require_reapproval",
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

        rc = main(
            [
                "guard",
                "hook",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--harness",
                "claude-code",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["policy_action"] == "require-reapproval"

    def test_guard_hook_blocks_sensitive_runtime_file_read_until_exactly_approved(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")

        blocked_event = {
            "event": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": ".env.local"},
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(blocked_event)))

        first_rc = main(
            [
                "guard",
                "hook",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--harness",
                "claude-code",
                "--json",
            ]
        )
        first_output = json.loads(capsys.readouterr().out)
        approval_request = first_output["approval_requests"][0]

        approval_rc = main(
            [
                "guard",
                "approvals",
                "approve",
                str(approval_request["request_id"]),
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(blocked_event)))
        second_rc = main(
            [
                "guard",
                "hook",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--harness",
                "claude-code",
                "--json",
            ]
        )
        second_output = json.loads(capsys.readouterr().out)

        different_event = {
            "event": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "~/.aws/credentials"},
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(different_event)))
        third_rc = main(
            [
                "guard",
                "hook",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--harness",
                "claude-code",
                "--json",
            ]
        )
        third_output = json.loads(capsys.readouterr().out)

        assert first_rc == 1
        assert first_output["policy_action"] == "require-reapproval"
        assert first_output["artifact_type"] == "file_read_request"
        assert "sensitive local file" in first_output["risk_summary"].lower()
        assert approval_request["recommended_scope"] == "artifact"
        assert approval_rc == 0
        assert second_rc == 0
        assert second_output["policy_action"] == "allow"
        assert third_rc == 1
        assert third_output["policy_action"] == "require-reapproval"

    def test_guard_hook_allows_non_sensitive_read_file_requests(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        safe_event = {
            "event": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "README.md"},
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(safe_event)))

        rc = main(
            [
                "guard",
                "hook",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--harness",
                "claude-code",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["policy_action"] in {"allow", "warn"}
        assert output.get("approval_requests") in (None, [])

    def test_stdio_proxy_blocks_disallowed_tools_and_redacts_headers(self):
        proxy = StdioGuardProxy(
            command=[
                sys.executable,
                "-u",
                "-c",
                "\n".join(
                    [
                        "import json, sys",
                        "for line in sys.stdin:",
                        "    message = json.loads(line)",
                        "    result = {'echo': message.get('method')}",
                        "    if message.get('method') == 'tools/call':",
                        "        result['tool'] = message.get('params', {}).get('name')",
                        "    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': result}))",
                        "    sys.stdout.flush()",
                    ]
                ),
            ],
            blocked_tools={"dangerous"},
        )

        allowed = proxy.run_session(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "safe-tool",
                        "arguments": {
                            "headers": {
                                "Authorization": "Bearer secret-token",
                                "x-api-key": "hidden",
                            }
                        },
                    },
                },
            ]
        )
        blocked = proxy.run_session(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "dangerous"},
                }
            ]
        )

        assert allowed["responses"][1]["result"]["tool"] == "safe-tool"
        assert allowed["events"][1]["redacted_params"]["arguments"]["headers"]["Authorization"] == "*****"
        assert blocked["responses"][0]["error"]["code"] == -32001
        assert blocked["events"][0]["decision"] == "block"

    def test_stdio_proxy_blocks_sensitive_file_reads_without_forwarding(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        (tmp_path / "workspace").mkdir(parents=True, exist_ok=True)
        config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace")
        proxy = StdioGuardProxy(
            command=[
                sys.executable,
                "-u",
                "-c",
                "\n".join(
                    [
                        "import json, sys",
                        "for line in sys.stdin:",
                        "    message = json.loads(line)",
                        "    result = {'tool': message.get('params', {}).get('name')}",
                        "    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': result}))",
                        "    sys.stdout.flush()",
                    ]
                ),
            ],
            cwd=tmp_path / "workspace",
            guard_store=store,
            guard_config=config,
            approval_center_url="http://127.0.0.1:4455",
            harness="codex",
        )

        allowed = proxy.run_session(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "read_file",
                        "arguments": {
                            "path": "README.md",
                            "headers": {"Authorization": "Bearer secret-token"},
                        },
                    },
                }
            ]
        )
        blocked = proxy.run_session(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "read_file",
                        "arguments": {
                            "path": ".env",
                            "headers": {"Authorization": "Bearer secret-token"},
                        },
                    },
                }
            ]
        )

        assert allowed["responses"][0]["result"]["tool"] == "read_file"
        assert allowed["events"][0]["decision"] == "forward"
        assert blocked["responses"][0]["error"]["code"] == -32001
        assert "sensitive local file" in blocked["responses"][0]["error"]["message"].lower()
        assert "http://127.0.0.1:4455" in blocked["responses"][0]["error"]["message"]
        assert blocked["responses"][0]["error"]["data"]["approvalCenterUrl"] == "http://127.0.0.1:4455"
        assert blocked["responses"][0]["error"]["data"]["reviewHint"]
        assert blocked["events"][0]["decision"] == "block"
        assert blocked["events"][0]["approval_delivery"]["destination"] == "browser"
        assert blocked["events"][0]["redacted_params"]["arguments"]["headers"]["Authorization"] == "*****"
        assert blocked["events"][0]["path_summary"].endswith("/.env")
        pending = store.list_approval_requests(limit=10)
        assert len(pending) == 1
        assert pending[0]["artifact_type"] == "file_read_request"

    def test_stdio_proxy_handles_unknown_harness_when_queueing_sensitive_read_blocks(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace_dir)
        proxy = StdioGuardProxy(
            command=[
                sys.executable,
                "-u",
                "-c",
                "\n".join(
                    [
                        "import json, sys",
                        "for line in sys.stdin:",
                        "    message = json.loads(line)",
                        "    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': {'ok': True}}))",
                        "    sys.stdout.flush()",
                    ]
                ),
            ],
            cwd=workspace_dir,
            guard_store=store,
            guard_config=config,
            approval_center_url="http://127.0.0.1:4455",
        )

        blocked = proxy.run_session(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": ".env"}},
                }
            ]
        )

        assert blocked["responses"][0]["error"]["code"] == -32001
        assert blocked["responses"][0]["error"]["data"]["approvalDelivery"]["destination"] == "browser"
        assert blocked["events"][0]["approval_delivery"]["destination"] == "browser"

    def test_remote_proxy_forwards_local_requests_and_redacts_auth_headers(self):
        server = HTTPServer(("127.0.0.1", 0), _RemoteProxyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            proxy = RemoteGuardProxy(
                base_url=f"http://127.0.0.1:{server.server_port}",
                allow_insecure_localhost=True,
            )
            response = proxy.forward(
                "/mcp",
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                headers={"Authorization": "Bearer secret-token", "x-api-key": "hidden"},
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert response["result"]["ok"] is True
        assert _RemoteProxyHandler.captured_headers["authorization"] == "Bearer secret-token"
        assert proxy.events[0]["headers"]["Authorization"] == "*****"

    def test_guard_daemon_serves_health_and_receipt_state(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.add_receipt(
            build_receipt(
                harness="codex",
                artifact_id="codex:workspace_skill",
                artifact_hash="hash-123",
                policy_decision="allow",
                capabilities_summary="mcp server • stdio • python",
                changed_capabilities=["first_seen"],
                provenance_summary="project artifact defined at .codex/config.toml",
                artifact_name="workspace_skill",
                source_scope="project",
            )
        )

        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/healthz", timeout=5) as response:
                health_payload = json.loads(response.read().decode("utf-8"))
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/receipts", timeout=5) as response:
                receipts_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert health_payload["ok"] is True
        assert health_payload["receipts"] == 1
        assert receipts_payload["items"][0]["artifact_id"] == "codex:workspace_skill"
