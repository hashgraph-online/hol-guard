"""Start a Guard MCP proxy command through the native relay.

The native runtime's ``mcp-relay`` subcommand owns the Guard MCP proxy. A
harness configuration written while the runtime could not relay still names
the Python ``*-mcp-proxy`` command, so that command now rebuilds the
module-form proxy argv and hands it to the relay. Without a runtime that
advertises the relay, the command refuses and names the repair instead of
forwarding tool calls unchecked.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from ..native_hook_bridge import native_hook_bridge_executable

RELAY_FEATURE = "mcp-stdio-relay-v1"
RELAY_COMMAND = "mcp-relay"
MODULE_PREFIX = ("-m", "codex_plugin_scanner.cli", "guard")
UNAVAILABLE = (
    "HOL Guard cannot start this MCP server because its native runtime is missing or "
    "cannot relay MCP sessions. Run `hol-guard repair`, then restart the session."
)


def relay_argv(
    proxy: str,
    args: argparse.Namespace,
    *,
    guard_home: Path,
    server_command: str,
    server_args: list[str],
    server_id: str | None,
    server_env_keys: tuple[str, ...],
) -> list[str]:
    """The module-form proxy argv the native relay parses."""

    argv = [*MODULE_PREFIX, proxy, f"--guard-home={guard_home}"]
    for flag, value in (
        ("--home", getattr(args, "home", None)),
        ("--workspace", getattr(args, "workspace", None)),
        ("--server-name", getattr(args, "server_name", None)),
        ("--server-id", server_id),
        ("--source-scope", getattr(args, "source_scope", None)),
        ("--config-path", getattr(args, "config_path", None)),
        ("--transport", getattr(args, "transport", None)),
        ("--command", server_command),
    ):
        if value:
            argv.append(f"{flag}={value}")
    argv.extend(f"--arg={value}" for value in server_args)
    argv.extend(f"--server-env-key={key}" for key in server_env_keys)
    return argv


def run_relay(argv: list[str], *, guard_home: Path) -> int:
    """Replace this process with the native relay, or refuse with the repair."""

    runtime = native_hook_bridge_executable(RELAY_FEATURE, guard_home=guard_home)
    if runtime is None:
        print(UNAVAILABLE, file=sys.stderr)
        return 1
    launch = [str(runtime), RELAY_COMMAND, sys.executable, *argv]
    sys.stdout.flush()
    sys.stderr.flush()
    if os.name == "nt":
        return subprocess.call(launch)
    os.execv(launch[0], launch)
    return 1


def relay_proxy_command(proxy: str, args: argparse.Namespace, *, guard_home: Path) -> int:
    """Run a ``*-mcp-proxy`` command whose server is on its own argv."""

    argv = relay_argv(
        proxy,
        args,
        guard_home=guard_home,
        server_command=args.server_command,
        server_args=list(args.server_args),
        server_id=getattr(args, "server_id", None),
        server_env_keys=tuple(args.server_env_keys),
    )
    return run_relay(argv, guard_home=guard_home)


__all__ = ["relay_argv", "relay_proxy_command", "run_relay"]
