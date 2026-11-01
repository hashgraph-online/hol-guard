"""Detect Guard approval mutation attempts from agent-controlled shells."""

from __future__ import annotations

import os
from collections.abc import Mapping

SELF_APPROVAL_REASON = (
    "Guard blocks AI agents from approving or weakening Guard approval state from inside a protected shell. "
    "Review the original request in the local approval center or native harness prompt."
)

_AGENT_ENV_MARKERS = frozenset(
    {
        "HOL_GUARD_HOOK_ARGV",
        "HOL_GUARD_MANAGED_CURSOR_HOOK",
        "HOL_GUARD_CURSOR_APPROVAL_BINDING",
        "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF",
        "CURSOR_SESSION_ID",
        "CURSOR_TRACE_ID",
        "CURSOR_TRANSCRIPT_PATH",
        "CLAUDECODE",
        "OPENCODE_CONFIG_CONTENT",
        "CODEX_SANDBOX",
    }
)


def approval_resolution_invoked_from_agent(env: Mapping[str, str] | None = None) -> bool:
    """Detect known AI harness hook contexts for approval CLI mutation defense-in-depth."""

    source = env if env is not None else os.environ
    return any(str(source.get(key) or "").strip() for key in _AGENT_ENV_MARKERS)


__all__ = [
    "SELF_APPROVAL_REASON",
    "approval_resolution_invoked_from_agent",
]
