#!/usr/bin/env python3
"""Record `opencode_install_plan` replay vectors from the ORIGINAL Python helpers.

Run against a checkout that still plans the OpenCode install config in Python
(the base of the commit that introduced the native `opencode_install_plan`
runner-authority kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output install_plan_vectors.json>

Each case pins one `plan` request and what `_install_locked` derived from it:
the managed and skipped servers, the root config's `permission` and `mcp`
values and the runtime overlay. Guard's proxy argv, the launcher environment
and the source config read are stubbed with fixed values the replay test
rebuilds. Every object is stored as `{"o": [[key, value], ...]}` so the replay
can check key order, which serde_json would otherwise drop.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.adapters import opencode as old
from codex_plugin_scanner.guard.adapters.mcp_servers import ManagedMcpServer, proxy_process_env

if not hasattr(old, "_persisted_mcp_with_guard_companions"):
    sys.exit("refusing to record: the original Python install planner is gone")

WORKSPACE = "nonexistent-guard/work"
GLOBAL_CONFIG = "nonexistent-guard/config/opencode/opencode.json"
PROJECT_CONFIG = "nonexistent-guard/work/opencode.json"
PREFIX = "hol-guard::"

_SOURCES: dict[tuple[str, str], dict[str, object] | None] = {}
_LAUNCHER_ENV: dict[str, str] = {}


def _proxy_cli_args(
    *, proxy_command: str, guard_home: str, server: ManagedMcpServer, home: str | None, workspace: str | None
) -> list[str]:
    del guard_home, home
    return [proxy_command, server.name, workspace or ""]


def _launcher_env(env: dict[str, str]) -> dict[str, str]:
    return {**_LAUNCHER_ENV, **env}


def _install_stubs() -> None:
    old.proxy_cli_args = _proxy_cli_args  # type: ignore[assignment]
    old.guard_cli_command = lambda _context, args: ["guard-cli", *args]  # type: ignore[assignment]
    old.mcp_proxy_command = lambda command: ["relay", *command]  # type: ignore[assignment]
    old.merge_guard_launcher_env = _launcher_env  # type: ignore[assignment]
    old._source_mcp_server_config = lambda server: _SOURCES.get((server.config_path, server.name))  # type: ignore[assignment]


def server(
    name: str,
    *,
    scope: str = "global",
    command: str = "node",
    args: tuple[str, ...] = (),
    env: dict[str, str] | None = None,
    enabled: bool = True,
    config: str = GLOBAL_CONFIG,
) -> ManagedMcpServer:
    return ManagedMcpServer(
        harness="opencode",
        name=name,
        source_scope=scope,
        config_path=config,
        command=command,
        args=args,
        transport="stdio",
        env=dict(env or {}),
        enabled=enabled,
    )


def ordered(value: object) -> object:
    """Every object as `{"o": [[key, value], ...]}`, recursively."""

    if isinstance(value, dict):
        return {"o": [[key, ordered(item)] for key, item in value.items()]}
    if isinstance(value, (list, tuple)):
        return [ordered(item) for item in value]
    return value


def record(name: str, case: dict[str, object]) -> dict[str, object]:
    servers: list[ManagedMcpServer] = list(case.get("servers", []))  # type: ignore[arg-type]
    workspace = bool(case.get("workspace", False))
    skipped: list[str] = list(case.get("skipped", []))  # type: ignore[arg-type]
    artifacts: list[str] = list(case.get("artifacts", []))  # type: ignore[arg-type]
    workspace_servers: set[str] = set(case.get("workspace_servers", []))  # type: ignore[arg-type]
    sources: dict[tuple[str, str], dict[str, object] | None] = dict(case.get("sources", {}))  # type: ignore[arg-type]
    _SOURCES.clear()
    _SOURCES.update(sources)
    _LAUNCHER_ENV.clear()
    _LAUNCHER_ENV.update(case.get("launcher_env", {}))  # type: ignore[arg-type]
    permission = case.get("permission")
    mcp = case.get("mcp")
    context = SimpleNamespace(
        home_dir=Path("nonexistent-guard/home"),
        guard_home=Path("nonexistent-guard/guard-home"),
        workspace_dir=Path(WORKSPACE) if workspace else None,
    )
    # `_install_locked`'s inline server selection, verbatim.
    managed_servers = tuple(server for server in servers if not server.name.startswith(PREFIX))
    prefix_artifacts = {artifact for artifact in artifacts if artifact.startswith(PREFIX)}
    skipped_servers = tuple(dict.fromkeys((*skipped, *sorted(prefix_artifacts))))
    adapter = old.OpenCodeHarnessAdapter()
    expect = {
        "managed": [index for index, item in enumerate(servers) if item in managed_servers],
        "skipped": list(skipped_servers),
        "permission": adapter._managed_permission_payload(
            permission,
            context=context,  # type: ignore[arg-type]
            servers=managed_servers,
            existing_workspace_server_names=workspace_servers,
        ),
        "mcp": old._persisted_mcp_with_guard_companions(
            mcp,
            context=context,  # type: ignore[arg-type]
            servers=managed_servers,
            existing_workspace_server_names=workspace_servers,
        ),
        "overlay": old.runtime_overlay(
            permission_rules=adapter._proxy_permission_rules(context, managed_servers, workspace_servers),  # type: ignore[arg-type]
            mcp_servers=adapter._proxy_mcp_overrides(context, managed_servers, workspace_servers),  # type: ignore[arg-type]
        ),
    }
    request = {
        "op": "plan",
        "workspace": workspace,
        "servers": [
            {
                "name": item.name,
                "source_scope": item.source_scope,
                "command": item.command,
                "args": list(item.args),
                "env": dict(item.env),
                "enabled": item.enabled,
                "proxy_environment": _launcher_env(proxy_process_env(item.env)),
                "source": sources.get((item.config_path, item.name)),
            }
            for item in servers
        ],
        "skipped": skipped,
        "artifacts": artifacts,
        "workspace_servers": sorted(workspace_servers),
        "permission": permission,
        "mcp": mcp,
        "mcp_keys": list(mcp) if isinstance(mcp, dict) else [],
    }
    return {"name": name, "request": ordered(request), "expect": ordered(expect)}


LEGACY_PROXY = [
    "/usr/bin/python3",
    "-m",
    "codex_plugin_scanner.cli",
    "guard",
    "opencode-mcp-proxy",
    "--server-name",
    "files",
    "--command",
    "npx",
    "--arg=-y",
    "--arg=@scope/files=1",
    "--arg=",
]


def cases() -> list[tuple[str, dict[str, object]]]:
    files = server("files", command="npx", args=("-y", "@scope/files"), env={"TOKEN": "t", "PYTHONPATH": "x/y"})
    return [
        ("empty", {}),
        ("permission-string", {"permission": "ask"}),
        ("permission-list", {"permission": ["allow"], "mcp": []}),
        (
            "permission-bash-string-keeps-key-order",
            {"permission": {"z": "deny", "bash": "ask", "*": "allow", "a": {"y": 1, "b": 2}}},
        ),
        (
            "permission-bash-object-merges-over-defaults",
            {"permission": {"bash": {"z *": "ask", "rm -rf *": "allow", "*": "deny", "a *": {"k": 1}}, "edit": "ask"}},
        ),
        ("permission-wildcard-without-bash", {"permission": {"edit": "deny", "*": "ask"}}),
        ("permission-wildcard-not-text", {"permission": {"*": {"x": 1}, "bash": ["no"]}}),
        ("permission-bash-null-wildcard-text", {"permission": {"bash": None, "*": "deny"}}),
        (
            "mcp-user-entries-keep-order",
            {
                "mcp": {
                    "zeta": {"type": "remote", "url": "https://example.invalid/mcp", "enabled": True},
                    "alpha": {"command": ["node", "a.js"], "z": 1, "a": 2},
                    "not-an-object": "x",
                    "hol-guard::kept": {"command": ["anything"], "b": 1, "a": 2},
                    "list": [1, 2],
                }
            },
        ),
        (
            "mcp-legacy-proxy-wrappers-restore",
            {
                "mcp": {
                    "first": {"enabled": False, "command": LEGACY_PROXY, "environment": {"Z": "1", "A": "2"}},
                    "second": {
                        "type": {"odd": True},
                        "command": ["x", "opencode-mcp-proxy", "--command", "a", "--command", "b", "--arg=1", 7],
                        "environment": "not-an-object",
                        "enabled": None,
                    },
                    "dangling": {"command": ["hol-guard", "opencode-mcp-proxy", "--command"]},
                    "string-command": {"command": "opencode-mcp-proxy --command x"},
                }
            },
        ),
        (
            "mcp-guard-proxy-commands-drop",
            {
                "mcp": {
                    "launcher": {"command": ["/opt/HOL-Guard.EXE", "guard", "cursor-mcp-proxy", "--x"]},
                    "windows": {"command": "C:\\tools\\current-hol-guard.cmd", "args": ["codex-mcp-proxy"]},
                    "module": {"command": ["python", "-m", "codex_plugin_scanner.cli", "guard", "mcp-proxy"]},
                    "relay": {
                        "command": [
                            "hol-guard",
                            "mcp-relay",
                            "/usr/bin/python3",
                            "-m",
                            "codex_plugin_scanner.cli",
                            "guard",
                            "hermes-mcp-proxy",
                        ]
                    },
                    "relay-not-proxy": {"command": ["hol-guard", "mcp-relay", "py", "mcp-proxy"]},
                    "launcher-no-proxy": {"command": ["hol-guard", "run", "mcp-proxy"]},
                    "dotted": {"command": ["/opt/hol-guard/.", "mcp-proxy"]},
                    "trailing": {"command": "/opt/hol-guard/", "args": ["guard", "copilot-mcp-proxy", 3]},
                    "module-missing-guard": {"command": ["python", "-m", "codex_plugin_scanner.cli", "mcp-proxy"]},
                    "empty-command": {"command": [1, 2]},
                    "user": {"command": ["node", "server.js"]},
                }
            },
        ),
        (
            "global-server-gets-native-and-companion",
            {
                "servers": [files],
                "sources": {(GLOBAL_CONFIG, "files"): {"timeout": 5, "command": ["old"], "enabled": True, "env": {}}},
                "mcp": {"other": {"command": ["node"]}},
                "permission": {"files_*": "deny", "edit": "ask"},
            },
        ),
        (
            "existing-native-and-companion-update-in-place",
            {
                "servers": [server("files", env={"B": "2", "A": "1"}), server("db", command="uvx", args=("db",))],
                "sources": {(GLOBAL_CONFIG, "db"): {"type": "custom", "z": 1}},
                "mcp": {
                    "hol-guard::files": {"command": ["stale"]},
                    "zz": {"command": ["node"]},
                    "files": {"z": 1, "enabled": True, "command": ["node"], "a": 2},
                },
            },
        ),
        (
            "workspace-scopes-and-shadowing",
            {
                "workspace": True,
                "servers": [
                    server("proj", scope="project", config=PROJECT_CONFIG),
                    server("shadow-global"),
                    server("shadow-custom", scope="custom"),
                    server("shadow-custom-off", scope="custom", enabled=False),
                    server("free", scope="custom"),
                ],
                "workspace_servers": ["shadow-global", "shadow-custom", "shadow-custom-off", "proj", "unrelated"],
                "mcp": {"proj": {"command": ["node"]}},
            },
        ),
        (
            "no-workspace-ignores-workspace-names",
            {
                "servers": [server("shadow-global"), server("proj", scope="project")],
                "workspace_servers": ["shadow-global", "proj"],
            },
        ),
        (
            "disabled-servers",
            {
                "workspace": True,
                "servers": [server("off", enabled=False), server("off-project", scope="project", enabled=False)],
                "permission": {"off_*": "allow"},
            },
        ),
        (
            "companion-prefixed-servers-and-artifacts",
            {
                "servers": [server("hol-guard::files"), server("files"), server("hol-guard::")],
                "skipped": ["remote", "hol-guard::b", "remote"],
                "artifacts": ["hol-guard::b", "hol-guard::a", "plain", "hol-guard::a"],
            },
        ),
        ("empty-command-skips-native", {"servers": [server("blank", command="")]}),
        (
            "duplicate-server-names",
            {
                "workspace": True,
                "servers": [
                    server("dup", command="a", config=GLOBAL_CONFIG),
                    server("dup", scope="project", command="b", config=PROJECT_CONFIG),
                ],
                "sources": {(GLOBAL_CONFIG, "dup"): {"note": "global"}, (PROJECT_CONFIG, "dup"): {"note": "project"}},
            },
        ),
        (
            "launcher-environment-without-server-env",
            {
                "servers": [server("env", env={"PYTHONHOME": "x/y", " ": "blank", " PAD ": "kept"})],
                "launcher_env": {"PYTHONPATH": "nonexistent-guard/src"},
            },
        ),
        (
            "unicode-names",
            {
                "servers": [server("dätä ✓", args=("--flag", "ünï"))],
                "mcp": {"ü": {"command": ["node"]}, "a": {"command": ["node"]}},
                "permission": {"ü": "ask", "*": "allow"},
            },
        ),
        ("mcp-not-an-object", {"servers": [server("files")], "mcp": "nope", "permission": 3}),
    ]


def main(output: Path) -> None:
    _install_stubs()
    recorded = [record(name, case) for name, case in cases()]
    document = {"schema": "guard-opencode-install-plan-vectors.v1", "cases": recorded}
    output.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
