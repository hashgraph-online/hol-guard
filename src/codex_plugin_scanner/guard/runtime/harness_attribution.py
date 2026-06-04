"""Resolve which harness initiated a runtime hook invocation."""

from __future__ import annotations

import os
from collections.abc import Mapping

_CURSOR_ENV_MARKERS = frozenset(
    {
        "CURSOR_VERSION",
        "CURSOR_PROJECT_DIR",
        "CURSOR_TRACE_ID",
        "CURSOR_SESSION_ID",
        "CURSOR_TRANSCRIPT_PATH",
    }
)


def cursor_runtime_detected(env: Mapping[str, str] | None = None) -> bool:
    """Return True when hook subprocess env indicates Cursor IDE/agent."""

    source = os.environ if env is None else env
    return any(
        isinstance(source.get(key), str) and source[key].strip() for key in _CURSOR_ENV_MARKERS
    )


def resolve_runtime_hook_harness(
    requested_harness: str,
    *,
    env: Mapping[str, str] | None = None,
) -> str:
    """Re-attribute Claude-compatible hooks to Cursor when they run inside Cursor."""

    normalized = requested_harness.strip().lower().replace("_", "-")
    if normalized in {"claude", "claude-code"} and cursor_runtime_detected(env):
        return "cursor"
    return requested_harness


def cursor_hook_query_extras(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Query parameters for the Claude daemon hook bridge when invoked from Cursor."""

    source = os.environ if env is None else env
    if not cursor_runtime_detected(source):
        return {}
    extras: dict[str, str] = {"runtime-harness": "cursor"}
    project_dir = source.get("CURSOR_PROJECT_DIR")
    if isinstance(project_dir, str) and project_dir.strip():
        extras["workspace"] = project_dir.strip()
    return extras


__all__ = [
    "cursor_hook_query_extras",
    "cursor_runtime_detected",
    "resolve_runtime_hook_harness",
]
