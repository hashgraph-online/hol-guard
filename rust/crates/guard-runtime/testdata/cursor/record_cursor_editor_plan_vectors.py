#!/usr/bin/env python3
"""Record `cursor_editor_plan` replay vectors from the ORIGINAL Python install.

Run against a checkout whose `CursorHarnessAdapter._install_editor` still merges
the managed origins and picks the Guard proxies to refresh in Python (the base
of the commit that introduced the native `cursor_editor_plan` kind), never from
Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output cursor_editor_plan_vectors.json>

Each case runs the original install in a scratch home with detection, hook
install and proxy rendering stubbed out, then records the request the native
kind takes (only each entry's launch fields) and the state origins, refreshed entry indices and notes Python
wrote. An install that raised is recorded as a refusal.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

Row = tuple[str, str, str]

PROXY_ENTRIES: list[tuple[str, object]] = [
    ("plain-text", "not an object"),
    ("plain-list", ["hol-guard", "cursor-mcp-proxy"]),
    ("plain-null", None),
    ("no-command", {"args": ["cursor-mcp-proxy"]}),
    ("numeric-command", {"command": 7, "args": ["-m", "codex_plugin_scanner.cli", "guard", "mcp-proxy"]}),
    ("launcher-direct", {"command": "hol-guard", "args": ["cursor-mcp-proxy", "--server-name", "a"]}),
    ("launcher-guard", {"command": "/usr/local/bin/hol-guard", "args": ["guard", "cursor-mcp-proxy"]}),
    (
        "launcher-module",
        {"command": "C:\\Tools\\HOL-GUARD.EXE", "args": ["-m", "codex_plugin_scanner.cli", "guard", "codex-mcp-proxy"]},
    ),
    ("launcher-current-cmd", {"command": "current-hol-guard.cmd", "args": ["hermes-mcp-proxy"]}),
    ("launcher-trailing-dot", {"command": "bin/hol-guard/.", "args": ["mcp-proxy"]}),
    ("launcher-double-suffix", {"command": "hol-guard.bat.exe", "args": ["mcp-proxy"]}),
    (
        "launcher-relay-module",
        {
            "command": "hol-guard",
            "args": ["mcp-relay", "/usr/bin/python3", "-m", "codex_plugin_scanner.cli", "guard", "cursor-mcp-proxy"],
        },
    ),
    ("launcher-relay-bare", {"command": "hol-guard", "args": ["mcp-relay", "/usr/bin/python3", "cursor-mcp-proxy"]}),
    ("launcher-relay-short", {"command": "hol-guard", "args": ["mcp-relay", "cursor-mcp-proxy"]}),
    ("launcher-unknown", {"command": "hol-guard", "args": ["other-proxy", "cursor-mcp-proxy"]}),
    ("launcher-no-args", {"command": "hol-guard"}),
    ("launcher-mixed-args", {"command": "hol-guard", "args": [3, None, "cursor-mcp-proxy"]}),
    ("launcher-text-args", {"command": "hol-guard", "args": "mcp-proxy"}),
    ("launcher-object-args", {"command": "hol-guard", "args": {"cursor-mcp-proxy": 1, "guard": 2}}),
    ("python-module", {"command": "python3", "args": ["-m", "codex_plugin_scanner.cli", "guard", "mcp-proxy"]}),
    (
        "runtime-relay",
        {
            "command": "/opt/guard/hol-guard-runtime",
            "args": ["mcp-relay", "/usr/bin/python3", "-m", "codex_plugin_scanner.cli", "guard", "cursor-mcp-proxy"],
        },
    ),
    ("python-scrambled", {"command": "py", "args": ["copilot-mcp-proxy", "guard", "x", "codex_plugin_scanner.cli"]}),
    ("python-no-guard", {"command": "python3", "args": ["codex_plugin_scanner.cli", "cursor-mcp-proxy"]}),
    ("node-server", {"command": "node", "args": ["guard", "server.js"], "env": {"A": "1"}}),
    ("empty-command", {"command": "", "args": ["codex_plugin_scanner.cli", "guard", "opencode-mcp-proxy"]}),
]

# (name, previous state, observed rows, managed rows, mcp.json payload, workspace)
CASES: list[tuple[str, object, list[Row], list[Row], object, bool]] = [
    ("empty", None, [], [], None, False),
    ("empty-workspace", None, [], [], {}, True),
    ("state-without-origins", {"workspace_dir": "/w"}, [], [], {"other": 1}, False),
    ("origins-not-object", {"managed_origins": [["a", "b"]]}, [("a", "project", "p/.cursor/mcp.json")], [], {}, False),
    (
        "origins-merge-order",
        {"managed_origins": {"b": ["project", "old-b"], "a": 5, "z": None}},
        [("a", "project", "pa"), ("c", "project", "pc"), ("g", "global", "home/.cursor/mcp.json")],
        [("b", "global", "home/.cursor/mcp.json"), ("d", "project", "pd"), ("missing", "global", "pm")],
        {"mcpServers": {}},
        True,
    ),
    (
        "observed-and-managed-same-name",
        {"managed_origins": {"x": ["project", "old"]}},
        [("x", "project", "observed")],
        [("x", "project", "managed"), ("y", "project", "py")],
        {},
        False,
    ),
    (
        "managed-global-after-observed-project",
        {},
        [("x", "project", "observed")],
        [("x", "global", "home/.cursor/mcp.json")],
        {},
        False,
    ),
    ("servers-not-object", None, [], [], {"mcpServers": ["hol-guard"]}, False),
    ("servers-proxies", None, [], [], {"mcpServers": dict(PROXY_ENTRIES)}, False),
    (
        "servers-and-origins",
        {"managed_origins": {"q": ["project", "pq"]}},
        [("q", "global", "g")],
        [("launcher-direct", "project", "pl")],
        {"mcpServers": dict(PROXY_ENTRIES[4:9])},
        True,
    ),
    ("args-null-raises", None, [], [], {"mcpServers": {"bad": {"command": "hol-guard", "args": None}}}, False),
    ("args-number-raises", None, [], [], {"mcpServers": {"ok": {}, "bad": {"command": "x", "args": 5}}}, False),
]


def _server(row: Row) -> SimpleNamespace:
    name, scope, config_path = row
    return SimpleNamespace(name=name, source_scope=scope, config_path=config_path)


def _launch(config: object) -> dict[str, object] | None:
    """The `command` and `args` of an `mcpServers` entry, the only fields sent."""
    if not isinstance(config, dict):
        return None
    return {key: value for key, value in config.items() if key in ("command", "args")}


def _record(adapter_module, case: tuple[str, object, list[Row], list[Row], object, bool]) -> dict[str, object]:
    name, previous_state, observed, managed, payload, workspace = case
    adapter_class = adapter_module.CursorHarnessAdapter
    refreshed: list[object] = []

    def refresh(config: dict[str, object]) -> dict[str, object]:
        refreshed.append(config)
        return {"refreshed": True}

    adapter = adapter_class()
    adapter.detect = lambda context: None
    adapter._proxy_server_entry = lambda context, server: {"managed": server.name}
    adapter._refresh_guard_proxy_entry = refresh
    adapter_module.managed_stdio_servers = lambda detection: tuple(_server(row) for row in managed)
    adapter_module.observable_stdio_servers_with_proxy = lambda detection: tuple(_server(row) for row in observed)
    adapter_module.skipped_stdio_server_names = lambda detection: ()
    adapter_module.install_cursor_hooks = lambda context: {}

    servers = payload.get("mcpServers") if isinstance(payload, dict) else None
    configs: list[object] = []
    launches = None
    if isinstance(servers, dict):
        configs = list(servers.values())
        launches = [_launch(config) for config in configs]
    previous_origins = None
    if isinstance(previous_state, dict) and isinstance(previous_state.get("managed_origins"), dict):
        previous_origins = [[key, value] for key, value in previous_state["managed_origins"].items()]
    request = {
        "previous_origins": previous_origins,
        "observed": [list(row) for row in observed],
        "managed": [list(row) for row in managed],
        "servers": launches,
        "workspace": workspace,
    }
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        workspace_dir = None
        if workspace:
            workspace_dir = root / "workspace"
            workspace_dir.mkdir()
        context = adapter_module.HarnessContext(
            home_dir=root / "home", workspace_dir=workspace_dir, guard_home=root / "guard"
        )
        target = adapter._target_editor_config_path(context)
        state_path = adapter._state_path(target, context)
        if payload is not None:
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(payload), encoding="utf-8")
        if previous_state is not None:
            state_path.parent.mkdir(parents=True)
            state_path.write_text(json.dumps(previous_state), encoding="utf-8")
        try:
            manifest = adapter._install_editor(context)
        except TypeError:
            return {"name": name, "request": request, "expect": {"refused": True}}
        state = json.loads(state_path.read_text(encoding="utf-8"))
    refresh_indices: list[int] = []
    cursor = 0
    for config in refreshed:
        while configs[cursor] != config:
            cursor += 1
        refresh_indices.append(cursor)
        cursor += 1
    expect = {
        "origins": [[key, value] for key, value in state["managed_origins"].items()],
        "refresh": refresh_indices,
        "notes": manifest["notes"],
    }
    return {"name": name, "request": request, "expect": expect}


def main() -> None:
    from codex_plugin_scanner.guard.adapters import cursor as adapter_module

    if not hasattr(adapter_module.CursorHarnessAdapter, "_strict_json_object"):
        sys.exit("refusing to record: the original Python Cursor editor install is gone")
    cases = [_record(adapter_module, case) for case in CASES]
    document = {"schema": "guard-cursor-editor-plan-vectors.v1", "cases": cases}
    Path(sys.argv[1]).write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
