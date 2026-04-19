from __future__ import annotations

import json
import sys
from io import StringIO
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.proxy import CopilotMcpGuardProxy
from codex_plugin_scanner.guard.store import GuardStore


def _child_command(marker_path: Path) -> list[str]:
    return [
        sys.executable,
        "-u",
        "-c",
        "\n".join(
            [
                "import json",
                "import sys",
                "from pathlib import Path",
                f"marker_path = Path({str(marker_path)!r})",
                "for line in sys.stdin:",
                "    message = json.loads(line)",
                "    message_id = message.get('id')",
                "    method = message.get('method')",
                "    if method is None or message_id is None:",
                "        continue",
                "    if method == 'initialize':",
                "        result = {",
                "            'protocolVersion': '2025-06-18',",
                "            'capabilities': {'tools': {}},",
                "            'serverInfo': {'name': 'fixture', 'version': '1.0.0'},",
                "        }",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': result}))",
                "        sys.stdout.flush()",
                "        continue",
                "    if method == 'tools/call':",
                "        params = message.get('params', {})",
                "        if params.get('name') == 'dangerous_delete':",
                "            marker_path.write_text(json.dumps(params), encoding='utf-8')",
                "        result = {'content': [{'type': 'text', 'text': params.get('name', 'unknown')}]}",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': result}))",
                "        sys.stdout.flush()",
                "        continue",
                "    print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': {}}))",
                "    sys.stdout.flush()",
            ]
        ),
    ]


def _context(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir(parents=True, exist_ok=True)
    workspace_dir.mkdir(parents=True, exist_ok=True)
    guard_home.mkdir(parents=True, exist_ok=True)
    return HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)


def test_copilot_guard_proxy_prompts_inline_when_client_supports_elicitation(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "dangerous-call.json"
    proxy = CopilotMcpGuardProxy(
        server_name="danger_lab",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".vscode" / "mcp.json"),
    )
    input_stream = StringIO(
        "\n".join(
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"capabilities": {"elicitation": {"form": {}}}},
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "dangerous_delete", "arguments": {"target": ".env"}},
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "guard-elicitation-1",
                        "result": {"action": "accept", "content": {"decision": "approve"}},
                    }
                ),
            ]
        )
        + "\n"
    )
    output_stream = StringIO()

    exit_code = proxy.serve(stdin=input_stream, stdout=output_stream)
    responses = [json.loads(line) for line in output_stream.getvalue().splitlines()]

    assert exit_code == 0
    assert responses[1]["id"] == "guard-elicitation-1"
    assert responses[1]["method"] == "elicitation/create"
    assert responses[2]["id"] == 2
    assert responses[2]["result"]["content"][0]["text"] == "dangerous_delete"
    assert json.loads(marker_path.read_text(encoding="utf-8"))["name"] == "dangerous_delete"
