from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.local_cli_commands import OTHER_COMMAND_ID, slug_local_cli_command_id
from codex_plugin_scanner.guard.runtime.local_mcp_probe import (
    is_package_mcp_launcher,
    is_strict_package_mcp_launcher,
    looks_like_mcp_launch,
    mcp_launch_tokens,
    probe_stdio_mcp_server,
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
    assert looks_like_mcp_launch(
        tokens, command_text="./github-mcp", cwd=tmp_path, home_dir=tmp_path
    ) is False
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
