"""Fixtures shared by the MCP tests that drive a stdio server fixture."""

from __future__ import annotations

import sys
from pathlib import Path

from codex_plugin_scanner.guard.harness_context import HarnessContext


def harness_context(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir()
    workspace_dir.mkdir()
    guard_home.mkdir()
    return HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)


def child_command(marker_path: Path) -> list[str]:
    return [
        sys.executable,
        "-u",
        "-c",
        "\n".join(
            (
                "import json",
                "import sys",
                "from pathlib import Path",
                f"marker_path = Path({str(marker_path)!r})",
                "for line in sys.stdin:",
                "    message = json.loads(line)",
                "    message_id = message.get('id')",
                "    if message_id is None:",
                "        continue",
                "    method = message.get('method')",
                "    if method == 'initialize':",
                "        result = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}}, "
                "                  'serverInfo': {'name': 'fixture', 'version': '1.0.0'}}",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': result}), flush=True)",
                "        continue",
                "    if method == 'tools/list':",
                "        tools = [",
                "            {'name': 'dangerous_delete', 'description': 'Dangerous delete', "
                "             'inputSchema': {'type': 'object', 'properties': {'target': {'type': 'string'}}}},",
                "            {'name': 'run_terminal_command', 'description': 'Run a terminal command.', "
                "             'inputSchema': {'type': 'object', 'properties': {'command': {'type': 'string'}}}},",
                "            {'name': 'safe_echo', 'description': 'Safe echo', "
                "             'inputSchema': {'type': 'object', 'properties': {}}},",
                "        ]",
                "        response = {'jsonrpc': '2.0', 'id': message_id, 'result': {'tools': tools}}",
                "        print(json.dumps(response), flush=True)",
                "        continue",
                "    if method == 'tools/call':",
                "        marker_path.write_text(json.dumps(message.get('params', {})), encoding='utf-8')",
                "        result = {'content': [{'type': 'text', 'text': 'forwarded'}]}",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': result}), flush=True)",
                "        continue",
                "    print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': {}}), flush=True)",
            )
        ),
    ]
