#!/usr/bin/env python3
"""Record `copilot_mcp_plan` replay vectors from the ORIGINAL Python install.

Run against a checkout whose `CopilotHarnessAdapter._render_install` still picks
the MCP payload key, the Guard proxies to refresh and the managed servers to add
in Python (the base of the commit that introduced the native `copilot_mcp_plan`
kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output copilot_mcp_plan_vectors.json>

Each case runs the original install in a scratch root with detection, the hook
plan, the shim and every write stubbed out, then records the request the native
kind takes and what Python did to each MCP target: the key it wrote, the servers
object it started from, the entries it refreshed (with the Python proxy argv it
relaunched), the managed servers it added and the fields it gave them. `<ROOT>`
stands for the scratch root.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

Row = tuple[str, str, str]
MODULE = ["-m", "codex_plugin_scanner.cli", "guard"]

ENTRIES: list[tuple[str, object]] = [
    ("plain-text", "not an object"),
    ("plain-null", None),
    ("plain-list", ["hol-guard", "copilot-mcp-proxy"]),
    ("no-command", {"args": ["copilot-mcp-proxy"]}),
    ("numeric-command", {"command": 7, "args": [*MODULE, "mcp-proxy"]}),
    ("launcher-direct", {"command": "hol-guard", "args": ["copilot-mcp-proxy", "--server-name", "a"]}),
    ("launcher-guard", {"command": "/usr/local/bin/hol-guard", "args": ["guard", "copilot-mcp-proxy"]}),
    ("launcher-module", {"command": "C:\\Tools\\HOL-GUARD.EXE", "args": [*MODULE, "codex-mcp-proxy", "-x"]}),
    ("launcher-current-cmd", {"command": "current-hol-guard.cmd", "args": ["hermes-mcp-proxy"]}),
    ("launcher-trailing-dot", {"command": "bin/hol-guard/.", "args": ["mcp-proxy"]}),
    ("launcher-double-suffix", {"command": "hol-guard.bat.exe", "args": ["mcp-proxy"]}),
    (
        "launcher-relay",
        {"command": "hol-guard", "args": ["mcp-relay", "/usr/bin/python3", *MODULE, "copilot-mcp-proxy"]},
    ),
    ("launcher-relay-mcp-proxy", {"command": "hol-guard", "args": ["mcp-relay", "/usr/bin/py", *MODULE, "mcp-proxy"]}),
    ("launcher-relay-bare", {"command": "hol-guard", "args": ["mcp-relay", "/usr/bin/python3", "copilot-mcp-proxy"]}),
    ("launcher-relay-short", {"command": "hol-guard", "args": ["mcp-relay", "copilot-mcp-proxy"]}),
    ("launcher-unknown", {"command": "hol-guard", "args": ["other-proxy", "copilot-mcp-proxy"]}),
    ("launcher-no-args", {"command": "hol-guard"}),
    ("launcher-mixed-args", {"command": "hol-guard", "args": [3, None, "copilot-mcp-proxy", {"a": 1}]}),
    ("launcher-text-args", {"command": "hol-guard", "args": "mcp-proxy"}),
    ("launcher-object-args", {"command": "hol-guard", "args": {"copilot-mcp-proxy": 1}}),
    ("launcher-null-args", {"command": "hol-guard", "args": None, "env": {"A": "1"}}),
    ("list-command", {"command": ["/old/python", *MODULE, "copilot-mcp-proxy", "--server-name", "lab"]}),
    (
        "list-command-and-args",
        {"command": ["/old/python", "-m"], "args": ["codex_plugin_scanner.cli", "guard", "copilot-mcp-proxy"]},
    ),
    ("list-command-launcher", {"command": ["hol-guard", "copilot-mcp-proxy"], "args": ["--x"]}),
    ("list-command-mixed", {"command": [1, "hol-guard", None, "guard"], "args": ["mcp-proxy"]}),
    ("list-command-empty", {"command": [], "args": [*MODULE, "copilot-mcp-proxy"]}),
    ("list-command-no-strings", {"command": [1, None], "args": [*MODULE, "copilot-mcp-proxy"]}),
    ("object-command", {"command": {"hol-guard": 1}, "args": ["copilot-mcp-proxy"]}),
    ("python-module", {"command": "python3", "args": [*MODULE, "mcp-proxy"], "environment": {"B": "2"}}),
    (
        "python-relay",
        {"command": "/opt/guard/runtime", "args": ["mcp-relay", "/usr/bin/python3", *MODULE, "cursor-mcp-proxy"]},
    ),
    ("python-relay-short", {"command": "/opt/guard/runtime", "args": ["mcp-relay", *MODULE, "copilot-mcp-proxy"]}),
    ("python-scrambled", {"command": "py", "args": ["copilot-mcp-proxy", "guard", "x", "codex_plugin_scanner.cli"]}),
    ("python-no-guard", {"command": "python3", "args": ["codex_plugin_scanner.cli", "copilot-mcp-proxy"]}),
    ("node-server", {"command": "node", "args": ["guard", "server.js"], "env": {"A": "1"}}),
    ("empty-command", {"command": "", "args": ["codex_plugin_scanner.cli", "guard", "opencode-mcp-proxy"]}),
    ("unicode-é-名", {"command": "hol-guard", "args": ["copilot-mcp-proxy", "--server-name", "é"]}),
]
PROXIES = dict(ENTRIES)
USER = {"user": {"command": "node", "args": ["server.js"]}, "shared": {"command": "npx", "args": ["shared"]}}

# (name, workspace, {target label: payload or None}, managed rows). A row's
# path names a target label or a template filled with `{ROOT}`.
CASES: list[tuple[str, bool, dict[str, object], list[Row]]] = [
    ("global-absent", False, {"HOME": None}, []),
    ("global-empty", False, {"HOME": {}}, []),
    ("global-proxies", False, {"HOME": {"mcpServers": PROXIES}}, []),
    ("global-servers-key", False, {"HOME": {"servers": PROXIES, "other": 1}}, []),
    ("global-both-keys", False, {"HOME": {"servers": USER, "mcpServers": {"m": {"command": "x"}}}}, []),
    ("global-both-preferred-not-object", False, {"HOME": {"mcpServers": [1], "servers": USER}}, []),
    ("global-neither-object", False, {"HOME": {"mcpServers": None, "servers": "x"}}, []),
    ("global-mcp-servers-null", False, {"HOME": {"mcpServers": None}}, [("g", "global", "elsewhere")]),
    (
        "global-managed",
        False,
        {"HOME": {"mcpServers": USER}},
        [("user", "global", "{ROOT}/home/.copilot/mcp-config.json"), ("new", "global", "x"), ("p", "project", "HOME")],
    ),
    (
        "global-managed-project-elsewhere",
        False,
        {"HOME": {"mcpServers": {}}},
        [("p", "project", "{ROOT}/work/.mcp.json"), ("q", "project", "{ROOT}/home//.copilot/./mcp-config.json")],
    ),
    ("workspace-absent", True, {"WS": None, "VS": None}, []),
    (
        "workspace-keys-by-name",
        True,
        {"WS": {"servers": {}, "mcpServers": {}}, "VS": {"servers": {}, "mcpServers": {}}},
        [],
    ),
    ("workspace-single-keys", True, {"WS": {"servers": PROXIES}, "VS": {"mcpServers": PROXIES}}, []),
    (
        "workspace-fallback",
        True,
        {"WS": {"mcpServers": "text", "servers": USER}, "VS": {"servers": [], "mcpServers": USER}},
        [("user", "global", "g")],
    ),
    (
        "workspace-managed",
        True,
        {"WS": {"mcpServers": USER}, "VS": {"servers": {"shared": {"command": "npx"}}}},
        [
            ("shared", "global", "{ROOT}/home/.copilot/mcp-config.json"),
            ("user", "global", "g"),
            ("user", "project", "WS"),
            ("ws-only", "project", "WS"),
            ("vs-only", "project", "VS"),
            ("vs-dotted", "project", "{ROOT}/work/.vscode/./mcp.json"),
            ("vs-slash", "project", "{ROOT}/work/.vscode/mcp.json/"),
            ("other-project", "project", "{ROOT}/elsewhere/.mcp.json"),
            ("relative", "project", ".mcp.json"),
            ("odd-scope", "user", "WS"),
            ("new", "global", "g"),
            ("new", "project", "VS"),
            ("ws-only", "global", "g"),
        ],
    ),
    (
        "workspace-shadow-non-object",
        True,
        {"WS": {"mcpServers": {"text": "x", "nul": None, "obj": {}}}, "VS": None},
        [("text", "global", "g"), ("nul", "global", "g"), ("obj", "global", "g"), ("obj", "project", "WS")],
    ),
    (
        "workspace-proxies-and-managed",
        True,
        {"WS": {"mcpServers": PROXIES}, "VS": {"servers": dict(ENTRIES[5:12])}},
        [("launcher-direct", "global", "g"), ("launcher-guard", "project", "VS"), ("unicode-é-名", "global", "g")],
    ),
]


def _paths(root: Path) -> dict[str, Path]:
    return {
        "HOME": root / "home" / ".copilot" / "mcp-config.json",
        "WS": root / "work" / ".mcp.json",
        "VS": root / "work" / ".vscode" / "mcp.json",
    }


def _key(path: str | Path, root: Path) -> str:
    """The path key the shim sends, with the scratch root replaced."""
    return os.path.normcase(str(Path(path))).replace(str(root), "<ROOT>")


def _slot(payload: dict[str, object], key: str) -> object:
    if key not in payload:
        return None
    servers = payload[key]
    if not isinstance(servers, dict):
        return False
    return [
        [name, {k: v for k, v in config.items() if k in ("command", "args")} if isinstance(config, dict) else None]
        for name, config in servers.items()
    ]


def _record(module, case: tuple[str, bool, dict[str, object], list[Row]]) -> dict[str, object]:
    name, workspace, payloads, rows = case
    adapter_class = module.CopilotHarnessAdapter
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        paths = _paths(root)
        (root / "work").mkdir()
        context = module.HarnessContext(
            home_dir=root / "home", workspace_dir=root / "work" if workspace else None, guard_home=root / "guard"
        )
        managed = tuple(
            SimpleNamespace(name=n, source_scope=s, config_path=str(paths.get(p) or p.replace("{ROOT}", str(root))))
            for n, s, p in rows
        )
        targets = adapter_class._target_mcp_paths(context)
        assert [paths[label] for label in payloads] == list(targets), name
        sources = {paths[label]: copy.deepcopy(payload or {}) for label, payload in payloads.items()}
        request = {
            "workspace": workspace,
            "managed": [[s.name, s.source_scope, _key(s.config_path, root)] for s in managed],
            "targets": [
                {"path": _key(t, root), "name": t.name, **{k: _slot(sources[t], k) for k in ("mcpServers", "servers")}}
                for t in targets
            ],
        }
        plans: list[dict[str, object]] = []
        configs: list[object] = []
        refresh_args: list[list[str]] = []
        original_servers_payload = module._mcp_servers_payload
        original_refresh = module._refresh_guard_proxy_entry

        def servers_payload(target_path: Path, payload: dict[str, object]) -> object:
            found = original_servers_payload(target_path, payload)
            source = next((k for k in ("mcpServers", "servers") if found is not None and payload.get(k) is found), None)
            configs[:] = list(found.values()) if isinstance(found, dict) else []
            plans.append({"key": None, "source": source, "refresh": [], "add": [], "fields": None})
            return found

        def refresh(config: dict[str, object], *, launcher_env: dict[str, str]) -> dict[str, object]:
            index = next(i for i, value in enumerate(configs) if value is config)
            refreshed = original_refresh(config, launcher_env=launcher_env)
            plans[-1]["refresh"].append([index, refresh_args.pop()])
            return refreshed

        def proxy_entry(*, proxy_command: str, context: object, server: object) -> dict[str, object]:
            assert proxy_command == "copilot-mcp-proxy"
            if server is not None:
                plans[-1]["add"].append(next(i for i, value in enumerate(managed) if value is server))
            return {"command": "PROXY", "args": []}

        def commit(context: object, *, target_path: Path, target_payload: str, **_: object) -> None:
            written = json.loads(target_payload)
            keys = [k for k in ("mcpServers", "servers") if k in written]
            assert len(keys) == 1, name
            plans[-1]["key"] = keys[0]
            fields = adapter_class()._proxy_server_entry(context, None, target_path)
            plans[-1]["fields"] = [[k, v] for k, v in fields.items() if k not in ("command", "args")]

        plan = SimpleNamespace(install=lambda entry: None, bash="b", powershell="p", payload={})
        module._mcp_servers_payload = servers_payload
        module._refresh_guard_proxy_entry = refresh
        module.proxy_launcher_entry = proxy_entry
        module.mcp_proxy_launch = lambda python, args: refresh_args.append(list(args)) or ("PY", list(args))
        module.guard_cli_launcher = lambda: "PY"
        module.merge_guard_launcher_env = lambda env=None: {}
        module.commit_copilot_target_and_state = commit
        module._copilot_json_payload = lambda path: sources[path]
        module.managed_stdio_servers = lambda detection: managed
        module.skipped_stdio_server_names = lambda detection: ()
        module.plan_copilot_hooks = lambda home, config, ws: (plan, plan if ws is not None else None)
        module._hook_command_parts = lambda context, **_: ("hook",)
        module.install_guard_shim = lambda harness, context: {}
        module.write_text_at_authorized_path = lambda path, text: None
        module._json_payload = lambda path: {}
        adapter = adapter_class()
        adapter.detect = lambda context, config_contents=None: None
        manifest = adapter._render_install(context)
        module._mcp_servers_payload = original_servers_payload
        module._refresh_guard_proxy_entry = original_refresh
    return {"name": name, "request": request, "expect": {"targets": plans, "notes": manifest["notes"]}}


def main() -> None:
    from codex_plugin_scanner.guard.adapters import copilot as module

    if not hasattr(module, "_mcp_servers_payload"):
        sys.exit("refusing to record: the original Python Copilot MCP install plan is gone")
    cases = [_record(module, case) for case in CASES]
    document = {"schema": "guard-copilot-mcp-plan-vectors.v1", "cases": cases}
    Path(sys.argv[1]).write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
