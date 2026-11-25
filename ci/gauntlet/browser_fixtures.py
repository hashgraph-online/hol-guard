"""Synthetic browser fixtures for the Gauntlet: two stand-in browser drivers and a browser binary.

Every name here is invented for the Gauntlet, except the reference driver's server name and tool
list, which must match a real driver so Guard classifies the stand-in the way it classifies that
driver. ``browser_driver_server.py`` serves the recorded tool list over stdio with scripted pages
instead of a browser, and journals every executed call to ``output/browser-calls.jsonl``.

- ``playwright``: the reference driver stand-in, with the tool list recorded in
  ``tests/fixtures/browser_drivers/playwright/tools.json``.
- ``sitehand``: a driver no profile matches, with two routine tools.
- ``chromium``: a stand-in on ``PATH`` that records its argv and exits, for launch-layer cases.
"""

from __future__ import annotations

import json
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
SERVER_SOURCE = Path(__file__).with_name("browser_driver_server.py")
TOOLS_ROOT = REPO / "tests" / "fixtures" / "browser_drivers"

REFERENCE_DRIVER = "playwright"
UNPROFILED_DRIVER = "sitehand"
UNPROFILED_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "open_url",
        "description": "Open a web address in the browser.",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    },
    {
        "name": "read_page",
        "description": "Return the text outline of the open page.",
        "inputSchema": {"type": "object", "properties": {}},
    },
)
BROWSER_BINARY = "chromium"
CALL_JOURNAL = "browser-calls.jsonl"
LAUNCH_JOURNAL = "browser-launches.jsonl"
PAGE_NAMES = ("shop-basket", "shop-login", "docs-article", "partner-landing", "local-dev")

CHROMIUM_STANDIN = """#!/usr/bin/env python3
# chromium: synthetic browser stand-in for Guard Gauntlet fixtures. Records argv, opens nothing.
import json
import sys

with open({journal!r}, "a", encoding="utf-8") as handle:
    handle.write(json.dumps({{"argv": sys.argv[1:]}}) + "\\n")
"""


@dataclass(frozen=True)
class BrowserFixture:
    """Where the browser stand-ins landed inside one fixture HOME."""

    server: Path
    reference_tools: Path
    unprofiled_tools: Path
    browser_binary: Path
    call_journal: Path
    launch_journal: Path
    mcp_configs: tuple[Path, ...]
    path_prefix: str


def _write(path: Path, text: str, *, executable: bool = False) -> Path:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | (stat.S_IXUSR if executable else 0))
    return path


def recorded_tools(driver: str = REFERENCE_DRIVER) -> list[dict[str, Any]]:
    """The recorded tool list of a reference driver."""
    document = json.loads((TOOLS_ROOT / driver / "tools.json").read_text(encoding="utf-8"))
    return list(document["tools"])


def install_server(home: Path) -> tuple[Path, Path, Path]:
    """Copy the stand-in server and both tool lists under ``~/.local/lib/browser-fixture``."""
    root = home / ".local" / "lib" / "browser-fixture"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    server = root / "server.py"
    shutil.copyfile(SERVER_SOURCE, server)
    server.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    reference = _write(root / f"{REFERENCE_DRIVER}.tools.json", json.dumps({"tools": recorded_tools()}, indent=2))
    unprofiled = _write(
        root / f"{UNPROFILED_DRIVER}.tools.json", json.dumps({"tools": list(UNPROFILED_TOOLS)}, indent=2)
    )
    return server, reference, unprofiled


def install_browser_binary(home: Path, journal: Path) -> Path:
    """Install the recording ``chromium`` stand-in in ``~/.local/bin``."""
    return _write(
        home / ".local" / "bin" / BROWSER_BINARY, CHROMIUM_STANDIN.format(journal=str(journal)), executable=True
    )


def mcp_servers(
    server: Path, reference_tools: Path, unprofiled_tools: Path, journal: Path
) -> dict[str, dict[str, Any]]:
    """Both stand-ins in the common ``mcpServers`` shape. They share one call journal."""

    def entry(tools: Path, name: str) -> dict[str, Any]:
        return {"command": "python3", "args": [str(server), str(tools), str(journal), name]}

    return {
        REFERENCE_DRIVER: entry(reference_tools, REFERENCE_DRIVER),
        UNPROFILED_DRIVER: entry(unprofiled_tools, UNPROFILED_DRIVER),
    }


def _codex_toml(servers: dict[str, dict[str, Any]]) -> str:
    blocks = []
    for name, server in servers.items():
        args = ", ".join(json.dumps(arg) for arg in server["args"])
        blocks.append(f'[mcp_servers.{name}]\ncommand = "{server["command"]}"\nargs = [{args}]\n')
    return "\n".join(blocks)


def _without_codex_servers(text: str, servers: dict[str, dict[str, Any]]) -> str:
    """Drop the tables for servers about to be rewritten, so repeated staging never declares one twice.

    Removes ``[mcp_servers.<name>]`` and its subtables such as ``[mcp_servers.<name>.env]``, up to
    the next table header. Everything else is kept as written.
    """
    owned = tuple(f"[mcp_servers.{name}" for name in servers)
    kept: list[str] = []
    skipping = False
    for line in text.splitlines():
        header = line.strip()
        if header.startswith("["):
            skipping = any(
                header.startswith(prefix) and header[len(prefix) : len(prefix) + 1] in ("]", ".") for prefix in owned
            )
        if not skipping:
            kept.append(line)
    body = "\n".join(kept).rstrip()
    return body + "\n\n" if body else ""


def write_mcp_configs(home: Path, harness: str, servers: dict[str, dict[str, Any]]) -> tuple[Path, ...]:
    """Register the stand-ins in the harness's user-level MCP config, merging with any existing one.

    As for connector fixtures, Claude Code also gets a launch file for ``--mcp-config`` because it
    runs with ``--strict-mcp-config``. The launch file carries the merged server list, so servers a
    case staged earlier stay reachable.
    """
    if harness == "claude-code":
        path = home / ".claude.json"
        existing = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        existing["mcpServers"] = {**existing.get("mcpServers", {}), **servers}
        launch = home / ".claude" / "gauntlet-browser-mcp.json"
        return (
            _write(launch, json.dumps({"mcpServers": existing["mcpServers"]}, indent=2) + "\n"),
            _write(path, json.dumps(existing, indent=2) + "\n"),
        )
    if harness == "codex":
        path = home / ".codex" / "config.toml"
        prefix = _without_codex_servers(path.read_text(encoding="utf-8"), servers) if path.is_file() else ""
        return (_write(path, prefix + _codex_toml(servers)),)
    if harness == "cursor":
        path = home / ".cursor" / "mcp.json"
        existing = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        existing["mcpServers"] = {**existing.get("mcpServers", {}), **servers}
        return (_write(path, json.dumps(existing, indent=2) + "\n"),)
    raise ValueError("browser fixtures support claude-code, codex and cursor")


def stage_browser_fixture(home: Path, output: Path, harness: str) -> BrowserFixture:
    """Install both driver stand-ins and the browser binary for one case."""
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    call_journal = output / CALL_JOURNAL
    launch_journal = output / LAUNCH_JOURNAL
    server, reference, unprofiled = install_server(home)
    binary = install_browser_binary(home, launch_journal)
    servers = mcp_servers(server, reference, unprofiled, call_journal)
    return BrowserFixture(
        server=server,
        reference_tools=reference,
        unprofiled_tools=unprofiled,
        browser_binary=binary,
        call_journal=call_journal,
        launch_journal=launch_journal,
        mcp_configs=write_mcp_configs(home, harness, servers),
        path_prefix=str(binary.parent),
    )


def read_journal(path: Path) -> list[dict[str, Any]]:
    """Journal entries in call order. A missing journal means no call ran."""
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def executed_calls(path: Path, *, server: str | None = None, tool: str | None = None) -> list[dict[str, Any]]:
    """Journal entries that ran, optionally narrowed to one server or tool."""
    return [
        entry
        for entry in read_journal(path)
        if (server is None or entry.get("server") == server) and (tool is None or entry.get("tool") == tool)
    ]
