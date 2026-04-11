"""Runtime behavior tests for Guard hook, proxy, and daemon surfaces."""

from __future__ import annotations

import io
import json
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
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
        assert evaluation["artifacts"] == [
            {
                "artifact_id": "codex:global:global-tools",
                "artifact_name": "global-tools",
                "changed": True,
                "changed_fields": ["removed"],
                "policy_action": "require-reapproval",
                "artifact_hash": removed_hash,
                "removed": True,
            }
        ]

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
                "codex",
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

    def test_guard_run_headless_blocks_with_review_hint(self, tmp_path, capsys):
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
            ]
        )
        output = capsys.readouterr().out

        assert rc == 1
        assert "approval center" in output.lower()
        assert "Queued approvals" in output

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
