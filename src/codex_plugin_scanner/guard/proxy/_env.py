"""Mechanical adapter for native MCP child-environment selection."""

from __future__ import annotations

import os

from ..native_context import context_mcp_launch_environment

# Guard-side bearer credentials that must never reach a child MCP server.
# The native `mcp_launch_environment` op drops these from both the inherited
# ambient environment and any caller-supplied `extra`; keep the tuple here so
# callers/tests can enumerate the protected set without re-deriving it.
_GUARD_TOKEN_ENV_VARS: tuple[str, ...] = ("HERMES_GUARD_TOKEN",)


def _build_scrubbed_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    return context_mcp_launch_environment(os.environ, extra or {})
