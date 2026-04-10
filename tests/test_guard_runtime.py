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
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.proxy import RemoteGuardProxy, StdioGuardProxy
from codex_plugin_scanner.guard.receipts import build_receipt
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
