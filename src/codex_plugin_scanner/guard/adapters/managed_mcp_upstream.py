"""Environment keys a Guard MCP proxy launch never takes from server config."""

from __future__ import annotations

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
