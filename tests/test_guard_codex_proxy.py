from __future__ import annotations

import json
import sys
from io import StringIO
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import _build_parser, _resolve_legacy_args
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_tool_calls import ToolCallDecision, build_tool_call_artifact, build_tool_call_hash
from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy
from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime_mcp_module
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
                "    if method is None:",
                "        continue",
                "    if message_id is None:",
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
                "    if method == 'tools/list':",
                "        safe_tool = {",
                "            'name': 'safe_echo',",
                "            'description': 'Safe echo',",
                "            'inputSchema': {'type': 'object', 'properties': {}},",
                "        }",
                "        dangerous_tool = {",
                "            'name': 'dangerous_delete',",
                "            'description': 'Dangerous delete',",
                "            'inputSchema': {'type': 'object', 'properties': {'target': {'type': 'string'}}},",
                "        }",
                "        result = {'tools': [safe_tool, dangerous_tool]}",
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


def _nested_request_child_command() -> list[str]:
    return [
        sys.executable,
        "-u",
        "-c",
        "\n".join(
            [
                "import json",
                "import sys",
                "for line in sys.stdin:",
                "    message = json.loads(line)",
                "    message_id = message.get('id')",
                "    method = message.get('method')",
                "    if method is None or message_id is None:",
                "        continue",
                "    if method == 'initialize':",
                "        result = {",
                "            'protocolVersion': '2025-06-18',",
                "            'capabilities': {'tools': {}, 'sampling': {}},",
                "            'serverInfo': {'name': 'fixture', 'version': '1.0.0'},",
                "        }",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': result}))",
                "        sys.stdout.flush()",
                "        continue",
                "    if method == 'tools/list':",
                "        child_request_id = 'child-sampling-1'",
                "        print(json.dumps({",
                "            'jsonrpc': '2.0',",
                "            'id': child_request_id,",
                "            'method': 'sampling/createMessage',",
                "            'params': {",
                "                'messages': [",
                "                    {'role': 'user', 'content': {'type': 'text', 'text': 'guard nested request'}}",
                "                ]",
                "            },",
                "        }))",
                "        sys.stdout.flush()",
                "        while True:",
                "            nested_line = sys.stdin.readline()",
                "            if not nested_line:",
                "                sys.exit(1)",
                "            nested_message = json.loads(nested_line)",
                "            if nested_message.get('id') == child_request_id and 'result' in nested_message:",
                "                break",
                "        result = {",
                "            'tools': [",
                "                {",
                "                    'name': 'safe_echo',",
                "                    'description': 'Safe echo',",
                "                    'inputSchema': {'type': 'object', 'properties': {}},",
                "                }",
                "            ]",
                "        }",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': result}))",
                "        sys.stdout.flush()",
                "        continue",
                "    print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': {}}))",
                "    sys.stdout.flush()",
            ]
        ),
    ]


def _nested_request_child_command_with_risky_tool(marker_path: Path) -> list[str]:
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
                "            'capabilities': {'tools': {}, 'sampling': {}},",
                "            'serverInfo': {'name': 'fixture', 'version': '1.0.0'},",
                "        }",
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message_id, 'result': result}))",
                "        sys.stdout.flush()",
                "        continue",
                "    if method == 'tools/list':",
                "        child_request_id = 'child-sampling-1'",
                "        print(json.dumps({",
                "            'jsonrpc': '2.0',",
                "            'id': child_request_id,",
                "            'method': 'sampling/createMessage',",
                "            'params': {",
                "                'messages': [",
                "                    {'role': 'user', 'content': {'type': 'text', 'text': 'guard nested request'}}",
                "                ]",
                "            },",
                "        }))",
                "        sys.stdout.flush()",
                "        while True:",
                "            nested_line = sys.stdin.readline()",
                "            if not nested_line:",
                "                sys.exit(1)",
                "            nested_message = json.loads(nested_line)",
                "            if nested_message.get('id') == child_request_id and 'result' in nested_message:",
                "                break",
                "        result = {",
                "            'tools': [",
                "                {",
                "                    'name': 'safe_echo',",
                "                    'description': 'Safe echo',",
                "                    'inputSchema': {'type': 'object', 'properties': {}},",
                "                }",
                "            ]",
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


def test_codex_guard_proxy_allows_safe_tool_calls_without_prompt(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "dangerous-call.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )

    result = proxy.run_session(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"capabilities": {"elicitation": {}}},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "safe_echo", "arguments": {}}},
        ]
    )

    assert result["responses"][2]["result"]["content"][0]["text"] == "safe_echo"
    assert marker_path.exists() is False
    assert store.count_approval_requests() == 0


def test_codex_guard_proxy_requires_inline_approval_for_risky_tool_calls(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "dangerous-call.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )

    result = proxy.run_session(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"capabilities": {"elicitation": {}}},
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "dangerous_delete", "arguments": {"target": ".env"}},
            },
        ],
        inline_approval_callback=lambda request: {"action": "accept", "content": {"decision": "approve"}},
    )

    assert result["responses"][1]["result"]["content"][0]["text"] == "dangerous_delete"
    assert json.loads(marker_path.read_text(encoding="utf-8"))["name"] == "dangerous_delete"
    assert store.count_approval_requests() == 0
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "allow"


def test_codex_guard_proxy_falls_back_to_approval_center_when_client_cannot_elicit(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "dangerous-call.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )

    result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "dangerous_delete", "arguments": {"target": ".env"}},
            },
        ]
    )
    pending = store.list_approval_requests()

    assert result["responses"][1]["error"]["code"] == -32001
    assert "retry" in result["responses"][1]["error"]["message"].lower()
    assert marker_path.exists() is False
    assert len(pending) == 1
    assert pending[0]["artifact_type"] == "tool_call"


def test_codex_guard_proxy_queues_approval_when_inline_prompt_gets_no_response(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "dangerous-call.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )

    result = proxy.run_session(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"capabilities": {"elicitation": {}}},
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "dangerous_delete", "arguments": {"target": ".env"}},
            },
        ],
        inline_approval_callback=lambda request: {"action": "cancel"},
    )
    pending = store.list_approval_requests()

    assert result["responses"][1]["error"]["code"] == -32001
    assert "approve request" in result["responses"][1]["error"]["message"].lower()
    assert marker_path.exists() is False
    assert len(pending) == 1


def test_codex_guard_proxy_parser_keeps_guard_subcommand_dispatch_intact():
    parser = _build_parser("cli.py", program_mode="combined")
    args = parser.parse_args(
        _resolve_legacy_args(
            [
                "guard",
                "codex-mcp-proxy",
                "--guard-home",
                "/tmp/guard",
                "--server-name",
                "danger_lab",
                "--config-path",
                "/tmp/config.toml",
                "--command",
                "python3",
                "--arg=/tmp/server.py",
            ],
            program_mode="combined",
        )
    )

    assert args.command == "guard"
    assert args.guard_command == "codex-mcp-proxy"
    assert args.server_command == "python3"


def test_codex_guard_proxy_does_not_emit_responses_for_notifications(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "dangerous-call.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    input_stream = StringIO(
        "\n".join(
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"capabilities": {"elicitation": {}}},
                    }
                ),
                json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            ]
        )
        + "\n"
    )
    output_stream = StringIO()

    exit_code = proxy.serve(stdin=input_stream, stdout=output_stream)
    responses = [json.loads(line) for line in output_stream.getvalue().splitlines()]

    assert exit_code == 0
    assert [response["id"] for response in responses] == [1, 2]


def test_codex_guard_proxy_ignores_client_responses_without_hanging(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "dangerous-call.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    input_stream = StringIO(
        "\n".join(
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"capabilities": {"elicitation": {}}},
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
                json.dumps({"jsonrpc": "2.0", "id": 999, "result": {"status": "unrelated"}}),
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
    assert responses[0]["id"] == 1
    assert responses[1]["id"] == "guard-elicitation-1"
    assert responses[1]["method"] == "elicitation/create"
    assert responses[2]["id"] == 2
    assert responses[2]["result"]["content"][0]["text"] == "dangerous_delete"
    assert json.loads(marker_path.read_text(encoding="utf-8"))["name"] == "dangerous_delete"


def test_codex_guard_proxy_treats_elicitation_error_as_approval_center_fallback(monkeypatch, tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "dangerous-call.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    monkeypatch.setattr(runtime_mcp_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    input_stream = StringIO(
        "\n".join(
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"capabilities": {"elicitation": {}}},
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
                        "error": {"code": 4001, "message": "client dismissed prompt"},
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
    assert responses[1]["method"] == "elicitation/create"
    assert responses[2]["id"] == 2
    assert responses[2]["error"]["code"] == -32001
    assert marker_path.exists() is False
    assert store.count_approval_requests() == 1


def test_codex_guard_proxy_rechecks_interleaved_requests_during_inline_approval(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "dangerous-call.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    input_stream = StringIO(
        "\n".join(
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"capabilities": {"elicitation": {}}},
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "dangerous_delete", "arguments": {"target": "first.txt"}},
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "dangerous_delete", "arguments": {"target": "second.txt"}},
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "guard-elicitation-2",
                        "result": {"action": "accept", "content": {"decision": "approve"}},
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
    assert responses[2]["id"] == "guard-elicitation-2"
    assert responses[2]["method"] == "elicitation/create"
    assert responses[3]["id"] == 3
    assert responses[4]["id"] == 2
    assert json.loads(marker_path.read_text(encoding="utf-8"))["arguments"]["target"] == "first.txt"


def test_codex_guard_proxy_services_nested_child_requests_without_deadlock(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_nested_request_child_command(),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    input_stream = StringIO(
        "\n".join(
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"capabilities": {"sampling": {}}},
                    }
                ),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "child-sampling-1",
                        "result": {
                            "role": "assistant",
                            "content": {"type": "text", "text": "Nested approval satisfied"},
                        },
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
    assert responses[0]["id"] == 1
    assert responses[1]["id"] == "child-sampling-1"
    assert responses[1]["method"] == "sampling/createMessage"
    assert responses[2]["id"] == 2
    assert responses[2]["result"]["tools"][0]["name"] == "safe_echo"


def test_codex_guard_proxy_guards_interleaved_requests_during_child_request_wait(monkeypatch, tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_nested_request_child_command(),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    handled_messages: list[dict[str, object]] = []

    def _fake_handle_message(
        *,
        message: dict[str, object],
        child_stdin: StringIO,
        child_stdout: StringIO,
        client_input: StringIO,
        server_output: StringIO,
        approval_callback,
    ):
        del child_stdin, child_stdout, client_input, server_output, approval_callback
        handled_messages.append(message)
        return (
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"content": [{"type": "text", "text": "guarded"}]},
            },
            {"decision": "guarded"},
        )

    monkeypatch.setattr(proxy, "_handle_message", _fake_handle_message)
    input_stream = StringIO(
        "\n".join(
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "dangerous_delete", "arguments": {"target": "nested.txt"}},
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "child-sampling-1",
                        "result": {
                            "role": "assistant",
                            "content": {"type": "text", "text": "Nested approval satisfied"},
                        },
                    }
                ),
            ]
        )
        + "\n"
    )
    output_stream = StringIO()
    child_stdin = StringIO()
    child_stdout = StringIO()

    proxy._proxy_child_request(
        payload={"jsonrpc": "2.0", "id": "child-sampling-1", "method": "sampling/createMessage", "params": {}},
        child_stdin=child_stdin,
        child_stdout=child_stdout,
        client_input=input_stream,
        server_output=output_stream,
    )
    responses = [json.loads(line) for line in output_stream.getvalue().splitlines()]
    child_messages = [json.loads(line) for line in child_stdin.getvalue().splitlines()]

    assert responses[0]["id"] == "child-sampling-1"
    assert responses[0]["method"] == "sampling/createMessage"
    assert responses[1]["id"] == 3
    assert responses[1]["result"]["content"][0]["text"] == "guarded"
    assert handled_messages == [
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "dangerous_delete", "arguments": {"target": "nested.txt"}},
        }
    ]
    assert child_messages == [
        {
            "jsonrpc": "2.0",
            "id": "child-sampling-1",
            "result": {
                "role": "assistant",
                "content": {"type": "text", "text": "Nested approval satisfied"},
            },
        }
    ]


def test_codex_guard_proxy_buffers_out_of_order_child_responses(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_nested_request_child_command(),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    child_stdin = StringIO()
    child_stdout = StringIO(
        "\n".join(
            [
                json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": "second"}]}}),
                json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "first"}]}}),
            ]
        )
        + "\n"
    )
    server_output = StringIO()

    first_response = proxy._forward_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "safe_echo", "arguments": {}}},
        child_stdin,
        child_stdout,
        client_input=None,
        server_output=server_output,
    )
    second_response = proxy._forward_message(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "safe_echo", "arguments": {}}},
        child_stdin,
        child_stdout,
        client_input=None,
        server_output=server_output,
    )

    assert first_response["id"] == 1
    assert second_response["id"] == 2
    assert server_output.getvalue() == ""


def test_codex_guard_proxy_rechecks_buffer_after_nested_child_request(monkeypatch, tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_nested_request_child_command(),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    child_stdin = StringIO()

    def _fake_proxy_child_request(**kwargs):
        del kwargs
        proxy._buffer_child_response(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"content": [{"type": "text", "text": "outer"}]},
            }
        )

    monkeypatch.setattr(proxy, "_proxy_child_request", _fake_proxy_child_request)
    response = proxy._forward_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        child_stdin,
        StringIO('{"jsonrpc":"2.0","id":"child-sampling-1","method":"sampling/createMessage","params":{}}\n'),
        client_input=StringIO(),
        server_output=StringIO(),
    )

    assert response["id"] == 1
    assert response["result"]["content"][0]["text"] == "outer"


def test_codex_guard_proxy_rechecks_buffered_client_reply_for_child_request(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_nested_request_child_command(),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    child_stdin = StringIO()
    server_output = StringIO()
    buffered_reply = {
        "jsonrpc": "2.0",
        "id": "child-sampling-1",
        "result": {
            "role": "assistant",
            "content": {"type": "text", "text": "Nested approval satisfied"},
        },
    }

    proxy._buffer_client_response(buffered_reply)
    proxy._proxy_child_request(
        payload={"jsonrpc": "2.0", "id": "child-sampling-1", "method": "sampling/createMessage", "params": {}},
        child_stdin=child_stdin,
        child_stdout=StringIO(),
        client_input=StringIO(),
        server_output=server_output,
    )

    assert json.loads(server_output.getvalue().splitlines()[0])["id"] == "child-sampling-1"
    assert [json.loads(line) for line in child_stdin.getvalue().splitlines()] == [buffered_reply]


def test_codex_guard_proxy_buffers_non_matching_child_request_replies(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_nested_request_child_command(),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    inner_child_stdin = StringIO()
    inner_server_output = StringIO()
    outer_reply = {
        "jsonrpc": "2.0",
        "id": "child-sampling-outer",
        "result": {
            "role": "assistant",
            "content": {"type": "text", "text": "Outer reply"},
        },
    }
    inner_reply = {
        "jsonrpc": "2.0",
        "id": "child-sampling-inner",
        "result": {
            "role": "assistant",
            "content": {"type": "text", "text": "Inner reply"},
        },
    }

    proxy._proxy_child_request(
        payload={"jsonrpc": "2.0", "id": "child-sampling-inner", "method": "sampling/createMessage", "params": {}},
        child_stdin=inner_child_stdin,
        child_stdout=StringIO(),
        client_input=StringIO("\n".join([json.dumps(outer_reply), json.dumps(inner_reply)]) + "\n"),
        server_output=inner_server_output,
    )

    outer_child_stdin = StringIO()
    outer_server_output = StringIO()
    proxy._proxy_child_request(
        payload={"jsonrpc": "2.0", "id": "child-sampling-outer", "method": "sampling/createMessage", "params": {}},
        child_stdin=outer_child_stdin,
        child_stdout=StringIO(),
        client_input=StringIO(),
        server_output=outer_server_output,
    )

    assert [json.loads(line) for line in inner_child_stdin.getvalue().splitlines()] == [inner_reply]
    assert [json.loads(line) for line in outer_child_stdin.getvalue().splitlines()] == [outer_reply]


def test_tool_call_hash_changes_when_server_identity_changes():
    artifact_a = build_tool_call_artifact(
        harness="codex",
        server_name="danger_lab",
        tool_name="dangerous_delete",
        source_scope="project",
        config_path="/workspace-a/.codex/config.toml",
        transport="stdio",
        server_fingerprint={"command": ["python3", "server-a.py"], "transport": "stdio"},
    )
    artifact_b = build_tool_call_artifact(
        harness="codex",
        server_name="danger_lab",
        tool_name="dangerous_delete",
        source_scope="project",
        config_path="/workspace-b/.codex/config.toml",
        transport="stdio",
        server_fingerprint={"command": ["python3", "server-b.py"], "transport": "stdio"},
    )

    assert build_tool_call_hash(artifact_a, {"target": "canary.txt"}) != build_tool_call_hash(
        artifact_b,
        {"target": "canary.txt"},
    )


def test_codex_guard_proxy_buffers_other_inline_approval_responses(tmp_path):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_child_command(tmp_path / "dangerous-call.json"),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    input_stream = StringIO(
        "\n".join(
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "guard-elicitation-1",
                        "result": {"action": "accept", "content": {"decision": "approve"}},
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "guard-elicitation-2",
                        "result": {"action": "accept", "content": {"decision": "approve"}},
                    }
                ),
            ]
        )
        + "\n"
    )

    nested_result = proxy._request_inline_approval(
        {"jsonrpc": "2.0", "id": "guard-elicitation-2", "method": "elicitation/create", "params": {}},
        input_stream=input_stream,
        output_stream=StringIO(),
        child_stdin=StringIO(),
        child_stdout=StringIO(),
    )
    outer_result = proxy._request_inline_approval(
        {"jsonrpc": "2.0", "id": "guard-elicitation-1", "method": "elicitation/create", "params": {}},
        input_stream=input_stream,
        output_stream=StringIO(),
        child_stdin=StringIO(),
        child_stdout=StringIO(),
    )

    assert nested_result == {"action": "accept", "content": {"decision": "approve"}}
    assert outer_result == {"action": "accept", "content": {"decision": "approve"}}


@pytest.mark.parametrize("action", ["warn", "review"])
def test_codex_guard_proxy_treats_non_blocking_policy_actions_as_pass_through(monkeypatch, tmp_path, action):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    marker_path = tmp_path / "dangerous-call.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace_skill",
        command=_child_command(marker_path),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    monkeypatch.setattr(
        runtime_mcp_module,
        "evaluate_tool_call",
        lambda **_: ToolCallDecision(
            action=action,
            source="policy",
            signals=("tool name implies destructive file or system changes",),
            summary="Policy override matched this tool call.",
        ),
    )

    result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "dangerous_delete", "arguments": {"target": ".env"}},
            },
        ]
    )

    assert result["responses"][1]["result"]["content"][0]["text"] == "dangerous_delete"
    assert json.loads(marker_path.read_text(encoding="utf-8"))["name"] == "dangerous_delete"
    assert store.count_approval_requests() == 0
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "allow"
