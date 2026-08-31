"""Helpers for scrubbing Guard-internal secrets from subprocess environments."""

from __future__ import annotations

import os

# Env vars that carry Guard-internal tokens. These must never be inherited
# by user-configured MCP server subprocesses, which are attacker-controlled.
_GUARD_TOKEN_ENV_VARS: tuple[str, ...] = ("HERMES_GUARD_TOKEN",)

# MCP servers still need ordinary process/runtime context to launch reliably.
# Credentials and product-specific configuration must come from the server's
# explicit ``env`` block, making that grant visible and reviewable.
_INHERITED_RUNTIME_ENV_VARS: frozenset[str] = frozenset(
    {
        "COLORTERM",
        "COMSPEC",
        "FORCE_COLOR",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "NO_COLOR",
        "PATH",
        "PATHEXT",
        "SHELL",
        "SYSTEMROOT",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "USER",
        "WINDIR",
    }
)


def _build_scrubbed_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build a subprocess env dict with Guard-internal tokens scrubbed.

    The proxy launches user-configured MCP server commands.  Those commands are
    part of the repository's documented attacker-controlled surface, so any
    Guard-internal token present in ``os.environ`` (inherited from the parent
    Hermes process) must be stripped before the env reaches the child.
    """
    env = {key: value for key, value in os.environ.items() if key in _INHERITED_RUNTIME_ENV_VARS}
    if extra:
        # Filter extra to prevent re-injecting scrubbed tokens via caller-provided env.
        env.update({k: v for k, v in extra.items() if k not in _GUARD_TOKEN_ENV_VARS})
    return env
