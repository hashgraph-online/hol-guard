"""The Python-launcher entry of a Guard MCP proxy, for tests that pin it.

The runtime's ``harness_adapter`` ops build this entry, selecting the native
relay when the caller's runtime advertises it. A test that renders a Codex
config segment needs the entry a Python-launched proxy writes, so it asks for
the proxy argv from the runtime and adds the stable launcher and its env.
"""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.launcher import merge_guard_launcher_env
from codex_plugin_scanner.guard.mcp_server_client import ManagedMcpServer, proxy_cli_args, proxy_process_env
from codex_plugin_scanner.guard.stable_guard_cli import guard_cli_launcher


def python_proxy_launcher_entry(
    *,
    proxy_command: str,
    context: HarnessContext,
    server: ManagedMcpServer,
) -> dict[str, object]:
    """The ``command``/``args``/``env`` mapping that launches ``proxy_command`` through Python."""

    args = proxy_cli_args(
        proxy_command=proxy_command,
        guard_home=str(context.guard_home),
        server=server,
        home=str(context.home_dir) if context.home_dir.resolve() != Path.home().resolve() else None,
        workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
    )
    entry: dict[str, object] = {"command": guard_cli_launcher(), "args": args}
    env = merge_guard_launcher_env(proxy_process_env(getattr(server, "env", {})))
    if env:
        entry["env"] = env
    return entry
