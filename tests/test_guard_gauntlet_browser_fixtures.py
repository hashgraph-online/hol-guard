"""Browser Gauntlet fixtures: the stand-in driver's page model, journal and staging."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import tomllib

from ci.gauntlet import browser_driver_server as server
from ci.gauntlet.browser_fixtures import (
    BROWSER_BINARY,
    PAGE_NAMES,
    REFERENCE_DRIVER,
    UNPROFILED_DRIVER,
    UNPROFILED_TOOLS,
    executed_calls,
    read_journal,
    recorded_tools,
    stage_browser_fixture,
)


def _state(tmp_path: Path, tools=None, name: str = REFERENCE_DRIVER) -> server.BrowserState:
    return server.BrowserState(tools or recorded_tools(), tmp_path / "calls.jsonl", name)


def test_every_named_page_exists_with_the_required_parts() -> None:
    assert set(server.PAGES) == set(PAGE_NAMES)
    elements = [item for page in server.PAGES.values() for item in page["elements"]]
    assert any(item.get("password") for item in elements)
    assert any(item.get("file") for item in elements)
    assert any("download" in item for item in elements)
    assert any(item.get("form") for item in elements)
    origins = {server.origin_of(page["url"]) for page in server.PAGES.values()}
    outbound = {server.origin_of(item["href"]) for item in elements if "href" in item}
    assert outbound - origins, "at least one link leaves the fixture pages"
    assert server.origin_of(server.PAGES["local-dev"]["url"]) == "http://127.0.0.1:5173"


def test_page_names_and_hosts_are_synthetic() -> None:
    for page in server.PAGES.values():
        host = server.origin_of(page["url"]).split("://", 1)[1].split(":", 1)[0]
        assert host.endswith(".example.test") or host == "127.0.0.1", host


@pytest.mark.parametrize(
    ("url", "page"),
    [
        ("https://shop.example.test/basket", "shop-basket"),
        ("https://shop.example.test/basket/", "shop-basket"),
        ("https://shop.example.test/basket?coupon=1#top", "shop-basket"),
        ("http://127.0.0.1:5173/items/sample", "local-dev"),
        ("https://unknown.example.test/", None),
    ],
)
def test_page_for_url(url: str, page: str | None) -> None:
    assert server.page_for_url(url) == page


def test_navigate_click_type_and_back(tmp_path: Path) -> None:
    state = _state(tmp_path)
    text, error = state.call("browser_navigate", {"url": "https://shop.example.test/basket"})
    assert not error and "ref=e4" in text
    text, error = state.call("browser_click", {"element": "Sign in", "ref": "e4"})
    assert not error and state.page == "shop-login"
    text, error = state.call("browser_type", {"element": "Password", "ref": "e2", "text": "fixture-pass"})
    assert not error and state.typed == {"e2": len("fixture-pass")}
    state.call("browser_navigate_back", {})
    assert state.page == "shop-basket"


def test_download_upload_and_errors(tmp_path: Path) -> None:
    state = _state(tmp_path)
    state.call("browser_navigate", {"url": "https://shop.example.test/basket"})
    text, _ = state.call("browser_click", {"element": "Download receipt", "ref": "e5"})
    assert state.downloads == ["receipt.pdf"] and "receipt.pdf" in text
    state.call("browser_navigate", {"url": "https://docs.example.test/guide/getting-started"})
    state.call("browser_file_upload", {"paths": ["/somewhere/notes/app.log"]})
    assert state.uploads == ["app.log"]
    assert state.call("browser_click", {"element": "x", "ref": "e99"})[1] is True
    assert state.call("browser_navigate", {"url": "https://unlisted.example.test/"})[1] is True
    assert state.call("not_a_tool", {})[1] is True


def test_journal_records_calls_without_argument_values(tmp_path: Path) -> None:
    state = _state(tmp_path)
    for message in (
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "browser_navigate", "arguments": {"url": "https://shop.example.test/login"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "browser_type",
                "arguments": {"element": "Password", "ref": "e2", "text": "typed-value"},
            },
        },
    ):
        server.handle(state, message)
    entries = read_journal(tmp_path / "calls.jsonl")
    assert [entry["tool"] for entry in entries] == ["browser_navigate", "browser_type"]
    assert entries[1]["page"] == "shop-login"
    assert entries[1]["origin"] == "https://shop.example.test"
    assert entries[1]["argument_keys"] == ["element", "ref", "text"]
    assert "typed-value" not in (tmp_path / "calls.jsonl").read_text(encoding="utf-8")
    assert executed_calls(tmp_path / "calls.jsonl", tool="browser_type") == [entries[1]]


def test_handle_answers_unknown_methods_and_lists_tools(tmp_path: Path) -> None:
    state = _state(tmp_path)
    listed = server.handle(state, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert [tool["name"] for tool in listed["result"]["tools"]] == [tool["name"] for tool in recorded_tools()]
    missing = server.handle(state, {"jsonrpc": "2.0", "id": 2, "method": "resources/list"})
    assert missing["error"]["code"] == -32601
    assert server.handle(state, {"jsonrpc": "2.0", "method": "ping"}) is None


def test_unprofiled_driver_routine_tools(tmp_path: Path) -> None:
    state = _state(tmp_path, list(UNPROFILED_TOOLS), UNPROFILED_DRIVER)
    assert state.call("open_url", {"url": "https://docs.example.test/guide/getting-started"})[1] is False
    text, error = state.call("read_page", {})
    assert not error and "Getting started" in text
    assert state.call("browser_click", {"ref": "e1"})[1] is True


def test_recorded_tool_list_is_well_formed() -> None:
    tools = recorded_tools()
    names = [tool["name"] for tool in tools]
    assert len(names) == len(set(names))
    assert {"browser_navigate", "browser_click", "browser_type", "browser_evaluate", "browser_file_upload"} <= set(
        names
    )
    assert all(tool["inputSchema"]["type"] == "object" for tool in tools)


def test_server_runs_over_stdio(tmp_path: Path) -> None:
    tools = tmp_path / "tools.json"
    tools.write_text(json.dumps({"tools": recorded_tools()}), encoding="utf-8")
    journal = tmp_path / "calls.jsonl"
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "browser_navigate", "arguments": {"url": "http://127.0.0.1:5173/"}},
        },
    ]
    completed = subprocess.run(
        [sys.executable, str(Path(server.__file__)), str(tools), str(journal), REFERENCE_DRIVER],
        input="\n".join(json.dumps(line) for line in lines) + "\nnot json\n",
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    replies = [json.loads(line) for line in completed.stdout.splitlines()]
    assert replies[0]["result"]["serverInfo"]["name"] == REFERENCE_DRIVER
    assert replies[1]["result"]["isError"] is False
    assert read_journal(journal)[0]["page"] == "local-dev"


@pytest.mark.parametrize("harness", ["claude-code", "codex", "cursor"])
def test_stage_registers_both_drivers(tmp_path: Path, harness: str) -> None:
    home = tmp_path / "home"
    fixture = stage_browser_fixture(home, tmp_path / "output", harness)
    assert fixture.server.is_file() and fixture.browser_binary.is_file()
    config = fixture.mcp_configs[0]
    if harness == "codex":
        servers = tomllib.loads(config.read_text(encoding="utf-8"))["mcp_servers"]
    else:
        servers = json.loads(config.read_text(encoding="utf-8"))["mcpServers"]
    assert set(servers) == {REFERENCE_DRIVER, UNPROFILED_DRIVER}
    assert servers[REFERENCE_DRIVER]["args"][-1] == REFERENCE_DRIVER
    assert servers[UNPROFILED_DRIVER]["args"][2] == str(fixture.call_journal)


def test_stage_merges_existing_claude_config(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {"echo-mcp": {"command": "node"}}, "x": 1}))
    fixture = stage_browser_fixture(home, tmp_path / "output", "claude-code")
    merged = json.loads(fixture.mcp_configs[1].read_text(encoding="utf-8"))
    assert merged["x"] == 1 and {"echo-mcp", REFERENCE_DRIVER, UNPROFILED_DRIVER} <= set(merged["mcpServers"])


def test_stage_rejects_unknown_harness(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        stage_browser_fixture(tmp_path / "home", tmp_path / "output", "unknown")


def test_browser_binary_records_argv_and_exits(tmp_path: Path) -> None:
    fixture = stage_browser_fixture(tmp_path / "home", tmp_path / "output", "cursor")
    assert fixture.browser_binary.name == BROWSER_BINARY
    subprocess.run(
        [sys.executable, str(fixture.browser_binary), "--remote-debugging-port=9222", "--headless"],
        check=True,
        timeout=30,
    )
    assert read_journal(fixture.launch_journal) == [{"argv": ["--remote-debugging-port=9222", "--headless"]}]
