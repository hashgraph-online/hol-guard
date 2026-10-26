"""Launcher selection for Guard-managed MCP stdio proxies: native relay or Python.

The native runtime's ``mcp-relay`` subcommand replaces the Python MCP proxy for
the Codex, Copilot, Cursor, Hermes and OpenCode proxies. It receives the exact Python
proxy argv after its subcommand, so one generated argv serves both launchers and
upstream recovery reads it unchanged. The relay asks the resident for every
``tools/call`` decision and blocks any call the resident does not decide, so
selecting it never widens what a call may do.

Installers select the relay when the validated runtime advertises
``mcp-stdio-relay-v1``; otherwise they keep launching the
Python proxy. A frozen build launches the verified runtime copy under the
proxy's ``--guard-home``, as its hooks do, because its bundled runtime can
live in a per-launch extraction directory. A session whose calls the resident cannot decide is handed to the
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
NATIVE_MCP_RELAY_DECIDE_FEATURE = "mcp-relay-decide-v2"
MCP_RELAY_SELECTION_ENV = "HOL_GUARD_MCP_RELAY"
# The proxies the native relay parses; other Guard proxies stay on Python.
RELAY_PROXY_COMMANDS = frozenset(
    {"codex-mcp-proxy", "copilot-mcp-proxy", "cursor-mcp-proxy", "hermes-mcp-proxy", "opencode-mcp-proxy"}
)
_PYTHON_PROXY_PREFIX = ("-m", "codex_plugin_scanner.cli", "guard")


def native_mcp_relay(guard_home: Path | None = None) -> Path | None:
    """The validated native runtime that should launch MCP proxies, or None.

    A frozen build needs ``guard_home`` to name its durable runtime copy.
    """

    selection = os.environ.get(MCP_RELAY_SELECTION_ENV)
    if selection == "python":
        return None
    feature = NATIVE_MCP_RELAY_DECIDE_FEATURE if selection == "native" else NATIVE_MCP_RELAY_FEATURE
    from .native_hook_bridge import native_hook_bridge_executable

    return native_hook_bridge_executable(feature, guard_home=guard_home)


def _relays(python_args: Sequence[str]) -> bool:
    values = tuple(python_args)
    return len(values) > 3 and values[:3] == _PYTHON_PROXY_PREFIX and values[3] in RELAY_PROXY_COMMANDS


def mcp_proxy_launch(python: str, python_args: Sequence[str]) -> tuple[str, list[str]]:
    """``(command, args)`` launching a Python proxy argv, through the relay when selected."""

    relayed = _relay_argv(python_args)
    if relayed is None:
        return python, list(python_args)
    relay = native_mcp_relay(_guard_home(relayed))
    if relay is None:
        return python, list(python_args)
    return str(relay), [NATIVE_MCP_RELAY_COMMAND, python, *relayed]


def _relay_argv(python_args: Sequence[str]) -> tuple[str, ...] | None:
    """The module-form proxy argv the relay parses, or None when it does not relay.

    A frozen build's CLI argv names the proxy command directly, as OpenCode
    writes it; the relay gets it back in module form, which the frozen
    launcher also runs.
    """

    values = tuple(python_args)
    if _relays(values):
        return values
    if getattr(sys, "frozen", False) and values and values[0] in RELAY_PROXY_COMMANDS:
        return (*_PYTHON_PROXY_PREFIX, *values)
    return None


def _guard_home(python_args: Sequence[str]) -> Path | None:
    """The proxy argv's ``--guard-home``, read as the relay parses it.

    Tokens after the proxy command are ``--flag value`` or ``--flag=value``
    pairs, and a repeated flag keeps its last value.
    """

    guard_home: str | None = None
    rest = iter(tuple(python_args)[len(_PYTHON_PROXY_PREFIX) + 1 :])
    for token in rest:
        flag, separator, inline = token.partition("=")
        value = inline if separator else next(rest, None)
        if flag == "--guard-home" and value:
            guard_home = value
    return Path(guard_home) if guard_home else None


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
