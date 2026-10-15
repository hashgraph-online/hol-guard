"""Launcher selection for Guard-managed MCP stdio proxies: native relay or Python.

The native runtime's ``mcp-relay`` subcommand replaces the Python MCP proxy for
the Codex, Copilot, Cursor and OpenCode proxies. It receives the exact Python
proxy argv after its subcommand, so one generated argv serves both launchers and
upstream recovery reads it unchanged. The relay asks the resident for every
``tools/call`` decision and blocks any call the resident does not decide, so
selecting it never widens what a call may do.

Installers select the relay when the validated runtime advertises
``mcp-stdio-relay-v1`` (Unix runtimes); otherwise they keep launching the
Python proxy. A session whose calls the resident cannot decide is handed to the
Python proxy by the relay at startup. ``HOL_GUARD_MCP_RELAY=python`` keeps the
Python proxy, like the hook bridge overrides. ``HOL_GUARD_MCP_RELAY=native``
selects the relay from any validated runtime that serves the resident's relay
decision, including one that does not advertise the relay. Calls the resident
defers are still refused.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from pathlib import Path

NATIVE_MCP_RELAY_COMMAND = "mcp-relay"
NATIVE_MCP_RELAY_FEATURE = "mcp-stdio-relay-v1"
NATIVE_MCP_RELAY_DECIDE_FEATURE = "mcp-relay-decide-v1"
MCP_RELAY_SELECTION_ENV = "HOL_GUARD_MCP_RELAY"
# The proxies the native relay parses; other Guard proxies stay on Python.
RELAY_PROXY_COMMANDS = frozenset({"codex-mcp-proxy", "copilot-mcp-proxy", "cursor-mcp-proxy", "opencode-mcp-proxy"})
_PYTHON_PROXY_PREFIX = ("-m", "codex_plugin_scanner.cli", "guard")


def native_mcp_relay() -> Path | None:
    """The validated native runtime that should launch MCP proxies, or None."""

    selection = os.environ.get(MCP_RELAY_SELECTION_ENV)
    if selection == "python" or os.name == "nt" or getattr(sys, "frozen", False):
        return None
    if selection == "native":
        return _validated_runtime(NATIVE_MCP_RELAY_DECIDE_FEATURE)
    return _validated_runtime(NATIVE_MCP_RELAY_FEATURE)


def _validated_runtime(feature: str) -> Path | None:
    from .native_hook_bridge import native_hook_bridge_executable

    return native_hook_bridge_executable(feature)


def _relays(python_args: Sequence[str]) -> bool:
    values = tuple(python_args)
    return len(values) > 3 and values[:3] == _PYTHON_PROXY_PREFIX and values[3] in RELAY_PROXY_COMMANDS


def mcp_proxy_launch(python: str, python_args: Sequence[str]) -> tuple[str, list[str]]:
    """``(command, args)`` launching a Python proxy argv, through the relay when selected."""

    if not _relays(python_args):
        return python, list(python_args)
    relay = native_mcp_relay()
    if relay is None:
        return python, list(python_args)
    return str(relay), [NATIVE_MCP_RELAY_COMMAND, python, *python_args]


def mcp_proxy_command(command: Sequence[str]) -> list[str]:
    """The single-list form of :func:`mcp_proxy_launch` (``[python, *args]``)."""

    values = list(command)
    if not values:
        return values
    executable, args = mcp_proxy_launch(values[0], values[1:])
    return [executable, *args]


def python_proxy_launch(command: str | None, args: Sequence[str]) -> tuple[str | None, tuple[str, ...]]:
    """Unwrap a native relay launch to the Python proxy ``(command, args)`` it carries."""

    values = tuple(args)
    if len(values) > 1 and values[0] == NATIVE_MCP_RELAY_COMMAND and _relays(values[2:]):
        return values[1], values[2:]
    return command, values


__all__ = [
    "MCP_RELAY_SELECTION_ENV",
    "NATIVE_MCP_RELAY_COMMAND",
    "NATIVE_MCP_RELAY_DECIDE_FEATURE",
    "NATIVE_MCP_RELAY_FEATURE",
    "RELAY_PROXY_COMMANDS",
    "mcp_proxy_command",
    "mcp_proxy_launch",
    "native_mcp_relay",
    "python_proxy_launch",
]
