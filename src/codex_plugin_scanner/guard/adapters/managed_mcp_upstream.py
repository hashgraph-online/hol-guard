"""The generated argv grammar of a Guard MCP proxy launch."""

from __future__ import annotations

_NATIVE_RELAY_COMMAND = "mcp-relay"
PROXY_LAUNCHER_ENV_KEYS = frozenset(
    {
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONBREAKPOINT",
        "__PYVENV_LAUNCHER__",
        # Native-authority bindings are persisted by the launcher from the
        # installer's ambient env; server env must never inject them.
        "HOL_GUARD_NATIVE",
        "HOL_GUARD_NATIVE_BINARY",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
        "HOL_GUARD_TEST_MODE",
    }
)


def proxy_argument_tail(args: tuple[str, ...], commands: frozenset[str]) -> tuple[str, tuple[str, ...]] | None:
    if len(args) > 2 and args[0] == _NATIVE_RELAY_COMMAND:
        # ``<runtime> mcp-relay <python> <proxy argv>`` carries the generated module argv unchanged.
        relayed = args[2:]
        if len(relayed) >= 4 and relayed[:3] == ("-m", "codex_plugin_scanner.cli", "guard") and relayed[3] in commands:
            return relayed[3], relayed[4:]
        return None
    if args and args[0] in commands:
        return args[0], args[1:]
    if len(args) >= 2 and args[0] == "guard" and args[1] in commands:
        return args[1], args[2:]
    if len(args) >= 4 and args[:3] == ("-m", "codex_plugin_scanner.cli", "guard") and args[3] in commands:
        return args[3], args[4:]
    return None
