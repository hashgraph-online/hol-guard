from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime import local_mcp_stdio as stdio_module
from codex_plugin_scanner.guard.runtime.local_cli_commands import OTHER_COMMAND_ID, slug_local_cli_command_id
from codex_plugin_scanner.guard.runtime.local_mcp_probe import (
    is_package_mcp_launcher,
    is_strict_package_mcp_launcher,
    looks_like_mcp_launch,
    mcp_launch_tokens,
    probe_stdio_mcp_server,
)
from codex_plugin_scanner.guard.runtime.local_mcp_stdio import (
    MCP_PACKAGE_PROBE_TIMEOUT_SECONDS,
    MCP_PROBE_OUTPUT_LIMIT,
    probe_env,
)
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity


def test_package_launcher_detection() -> None:
    assert is_package_mcp_launcher(("npx", "-y", "@modelcontextprotocol/server-github"))
    assert is_package_mcp_launcher(("uvx", "mcp-server-git"))
    assert is_strict_package_mcp_launcher(("npx", "-y", "@modelcontextprotocol/server-github"))
    assert not is_strict_package_mcp_launcher(("pnpm", "dlx", "my-custom-cli"))
    assert not is_package_mcp_launcher(("npx",))
    assert not is_package_mcp_launcher(("npx", "--yes"))
    assert not is_package_mcp_launcher(("git", "status"))


def test_looks_like_mcp_launch_for_named_servers(tmp_path: Path) -> None:
    tokens = mcp_launch_tokens("./github-mcp", cwd=tmp_path, home_dir=tmp_path)
    assert tokens == ("./github-mcp",)
    assert looks_like_mcp_launch(tokens, command_text="./github-mcp", cwd=tmp_path, home_dir=tmp_path) is False
    assert looks_like_mcp_launch(
        ("npx", "-y", "@modelcontextprotocol/server-github"),
        command_text="npx -y @modelcontextprotocol/server-github",
        cwd=tmp_path,
        home_dir=tmp_path,
    )


def test_probe_identity_matches_runtime_builder(tmp_path: Path) -> None:
    command = "npx -y @modelcontextprotocol/server-github"
    expected = build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", "@modelcontextprotocol/server-github"),
        transport="stdio",
    )

    def runner(_argv: list[str]) -> list[dict[str, object]]:
        return [{"name": "read_file", "description": "Read a file"}]

    probed = probe_stdio_mcp_server(command, cwd=tmp_path, home_dir=tmp_path, runner=runner)
    assert probed is not None
    assert probed.server_identity.identity_hash == expected.identity_hash
    assert probed.identity.cli_id == f"local-cli.mcp-{expected.identity_hash[:8]}"
    assert probed.identity.identity_hash == expected.identity_hash
    assert probed.status == "ok"
    ids = [tool.command_id for tool in probed.tools]
    assert slug_local_cli_command_id("read_file") in ids
    assert slug_local_cli_command_id("read.file") != slug_local_cli_command_id("read-file")
    assert slug_local_cli_command_id("READ_FILE") != slug_local_cli_command_id("read_file")
    assert OTHER_COMMAND_ID in ids


def test_probe_returns_none_when_runner_fails(tmp_path: Path) -> None:
    def runner(_argv: list[str]) -> None:
        return None

    probed = probe_stdio_mcp_server(
        "npx -y @modelcontextprotocol/server-github",
        cwd=tmp_path,
        home_dir=tmp_path,
        runner=runner,
    )
    assert probed is None


def test_live_stdio_probe_lists_tools(tmp_path: Path) -> None:
    server = tmp_path / "fake-mcp-server.py"
    server.write_text(
        """
import json
import sys

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "0"},
            },
        }), flush=True)
    elif method == "tools/list":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "tools": [
                    {"name": "read_file", "description": "Read a file"},
                    {"name": "write_file", "description": "Write a file"},
                ]
            },
        }), flush=True)
""",
        encoding="utf-8",
    )
    probed = probe_stdio_mcp_server(
        f"python3 {server}",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert probed is not None
    assert probed.status == "ok"
    names = [tool.name for tool in probed.tools]
    assert "read_file" in names
    assert "write_file" in names
    assert "Other tools" in names


def test_live_stdio_probe_reads_content_length(tmp_path: Path) -> None:
    server = tmp_path / "fake-mcp-framed.py"
    server.write_text(
        """
import json
import sys

def send(payload):
    body = json.dumps(payload)
    sys.stdout.write(f"Content-Length: {len(body.encode('utf-8'))}\\r\\n\\r\\n{body}")
    sys.stdout.flush()

buffer = ""
while True:
    chunk = sys.stdin.read(1)
    if chunk == "":
        break
    buffer += chunk
    if "\\n" not in buffer:
        continue
    line, buffer = buffer.split("\\n", 1)
    if not line.strip():
        continue
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        send({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "framed"}},
        })
    elif method == "tools/list":
        send({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"tools": [{"name": "ping", "description": "Ping"}]},
        })
        break
""",
        encoding="utf-8",
    )
    probed = probe_stdio_mcp_server(f"python3 {server}", cwd=tmp_path, home_dir=tmp_path)
    assert probed is not None
    assert any(tool.name == "ping" for tool in probed.tools)


def _large_tools(count: int = 40, description_size: int = 2000) -> list[dict[str, object]]:
    return [
        {
            "name": f"tool_{index}",
            "description": "x" * description_size,
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
        }
        for index in range(count)
    ]


def _write_framed_server(path: Path, *, tools: list[dict[str, object]], roots_first: bool = False) -> None:
    path.write_text(
        f"""
import json
import sys

TOOLS = {json.dumps(tools)}
ROOTS_FIRST = {roots_first!r}

def send(payload):
    body = json.dumps(payload)
    sys.stdout.write(f"Content-Length: {{len(body.encode('utf-8'))}}\\r\\n\\r\\n{{body}}")
    sys.stdout.flush()

buffer = ""
while True:
    chunk = sys.stdin.read(1)
    if chunk == "":
        break
    buffer += chunk
    if "\\n" not in buffer:
        continue
    line, buffer = buffer.split("\\n", 1)
    if not line.strip():
        continue
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        if ROOTS_FIRST:
            send({{"jsonrpc": "2.0", "id": 99, "method": "roots/list", "params": {{}}}})
        send({{
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {{"protocolVersion": "2024-11-05", "capabilities": {{}}, "serverInfo": {{"name": "fat"}}}},
        }})
    elif method == "tools/list":
        send({{
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {{"tools": TOOLS}},
        }})
        break
""",
        encoding="utf-8",
    )


def test_live_stdio_probe_lists_tools_from_large_payload(tmp_path: Path) -> None:
    tools = _large_tools()
    payload = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": tools}})
    assert len(payload) > 64_000
    assert len(payload) < MCP_PROBE_OUTPUT_LIMIT
    server = tmp_path / "fat-mcp.py"
    _write_framed_server(server, tools=tools)
    probed = probe_stdio_mcp_server(f"python3 {server}", cwd=tmp_path, home_dir=tmp_path)
    assert probed is not None
    assert probed.status == "ok"
    names = [tool.name for tool in probed.tools]
    assert "tool_0" in names
    assert "tool_39" in names
    assert "Other tools" in names


def test_legacy_output_limit_drops_large_tools_list(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(stdio_module, "MCP_PROBE_OUTPUT_LIMIT", 64_000)
    server = tmp_path / "fat-mcp.py"
    _write_framed_server(server, tools=_large_tools())
    probed = probe_stdio_mcp_server(f"python3 {server}", cwd=tmp_path, home_dir=tmp_path, timeout=2.0)
    assert probed is None


def test_live_stdio_probe_answers_roots_list(tmp_path: Path) -> None:
    server = tmp_path / "roots-mcp.py"
    _write_framed_server(server, tools=[{"name": "list_pages", "description": "List pages"}], roots_first=True)
    probed = probe_stdio_mcp_server(f"python3 {server}", cwd=tmp_path, home_dir=tmp_path)
    assert probed is not None
    assert any(tool.name == "list_pages" for tool in probed.tools)


def test_live_stdio_probe_skips_stdout_noise(tmp_path: Path) -> None:
    server = tmp_path / "noisy-mcp.py"
    server.write_text(
        """
import json
import sys
print("need to install the following packages:", flush=True)
print("chrome-devtools-mcp", flush=True)
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "noisy"}},
        }), flush=True)
    elif method == "tools/list":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"tools": [{"name": "click", "description": "Click"}]},
        }), flush=True)
        break
""",
        encoding="utf-8",
    )
    probed = probe_stdio_mcp_server(f"python3 {server}", cwd=tmp_path, home_dir=tmp_path)
    assert probed is not None
    assert any(tool.name == "click" for tool in probed.tools)


def test_live_stdio_probe_empty_tools(tmp_path: Path) -> None:
    server = tmp_path / "empty-mcp.py"
    server.write_text(
        """
import json
import sys
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "empty"}},
        }), flush=True)
    elif method == "tools/list":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"tools": []},
        }), flush=True)
        break
""",
        encoding="utf-8",
    )
    probed = probe_stdio_mcp_server(f"python3 {server}", cwd=tmp_path, home_dir=tmp_path)
    assert probed is not None
    assert probed.status == "empty"
    assert [tool.name for tool in probed.tools] == ["Other tools"]


def test_probe_timeout_returns_none(tmp_path: Path) -> None:
    server = tmp_path / "slow-mcp.py"
    server.write_text("import time\ntime.sleep(8)\n", encoding="utf-8")
    probed = probe_stdio_mcp_server(f"python3 {server}", cwd=tmp_path, home_dir=tmp_path, timeout=0.2)
    assert probed is None


def test_package_launcher_uses_longer_probe_timeout(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, float] = {}

    def fake_run(_argv: list[str], *, timeout: float) -> list[dict[str, object]]:
        captured["timeout"] = timeout
        return [{"name": "list_pages", "description": "List pages"}]

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.local_mcp_probe.run_mcp_tools_list",
        fake_run,
    )
    probed = probe_stdio_mcp_server(
        "npx -y chrome-devtools-mcp@latest",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert captured["timeout"] == MCP_PACKAGE_PROBE_TIMEOUT_SECONDS
    assert probed is not None
    assert any(tool.name == "list_pages" for tool in probed.tools)


def test_probe_env_reuses_npm_cache(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    npm = home / ".npm"
    npm.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("npm_config_cache", raising=False)
    monkeypatch.delenv("NPM_CONFIG_CACHE", raising=False)
    isolated = tmp_path / "probe-tmp"
    isolated.mkdir()
    env = probe_env(str(isolated))
    assert env["HOME"] == str(isolated)
    assert env["npm_config_cache"] == str(npm)
    assert env["NPM_CONFIG_CACHE"] == str(npm)
    assert "npm_config_yes" not in env
    assert "NPM_CONFIG_YES" not in env


def test_probe_env_resolves_relative_npm_cache(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rel-cache").mkdir()
    monkeypatch.setenv("NPM_CONFIG_CACHE", "rel-cache")
    monkeypatch.delenv("npm_config_cache", raising=False)
    env = probe_env(str(tmp_path / "probe-tmp"))
    resolved = str((tmp_path / "rel-cache").resolve())
    assert env["npm_config_cache"] == resolved
    assert env["NPM_CONFIG_CACHE"] == resolved
    assert Path(env["npm_config_cache"]).is_absolute()


def test_incomplete_pagination_does_not_persist_partial_tools(tmp_path: Path) -> None:
    server = tmp_path / "paged-mcp.py"
    server.write_text(
        """
import json
import sys
import time

page = 0
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "paged"}},
        }), flush=True)
    elif method == "tools/list":
        page += 1
        if page > 1:
            time.sleep(2)
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "tools": [{"name": f"tool_{page}", "description": "paged"}],
                "nextCursor": "more" if page == 1 else None,
            },
        }), flush=True)
""",
        encoding="utf-8",
    )
    probed = probe_stdio_mcp_server(f"python3 {server}", cwd=tmp_path, home_dir=tmp_path, timeout=0.4)
    assert probed is None


def test_live_stdio_probe_reads_utf8_tool_names(tmp_path: Path) -> None:
    server = tmp_path / "utf8-mcp.py"
    server.write_text(
        """
import json
import sys

def send(payload):
    body = (json.dumps(payload, ensure_ascii=False) + "\\n").encode("utf-8")
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        send({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "utf8"}},
        })
    elif method == "tools/list":
        send({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"tools": [{"name": "open_page", "description": "caf\\u00e9 naive"}]},
        })
        break
""",
        encoding="utf-8",
    )
    probed = probe_stdio_mcp_server(f"python3 {server}", cwd=tmp_path, home_dir=tmp_path)
    assert probed is not None
    assert any(tool.name == "open_page" and tool.description == "café naive" for tool in probed.tools)


def test_live_stdio_probe_reads_tools_after_server_exits(tmp_path: Path) -> None:
    server = tmp_path / "exit-mcp.py"
    server.write_text(
        """
import json
import sys
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "exit"}},
        }), flush=True)
    elif method == "tools/list":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"tools": [{"name": "list_pages", "description": "List"}]},
        }), flush=True)
        break
""",
        encoding="utf-8",
    )
    probed = probe_stdio_mcp_server(f"python3 {server}", cwd=tmp_path, home_dir=tmp_path)
    assert probed is not None
    assert any(tool.name == "list_pages" for tool in probed.tools)
