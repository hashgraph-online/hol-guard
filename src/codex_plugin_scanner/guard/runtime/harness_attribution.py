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

# Presence-only, non-secret runtime markers. Each family is injected by the
# harness runtime into the environment of commands it executes, so a Guard
# process that inherits one of them was spawned from that harness. They are
# read as an attribution signal only; policy scoping never keys off them.
_CLAUDE_CODE_ENV_MARKERS = frozenset({"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"})
_CODEX_ENV_MARKERS = frozenset({"CODEX_SANDBOX"})


def _zcode_env_markers() -> frozenset[str]:
    from ..adapters.zcode_config import ZCODE_ENV_HINTS

    return frozenset(ZCODE_ENV_HINTS)


def _zcode_bundle_identifier() -> str:
    from ..adapters.zcode_config import ZCODE_BUNDLE_IDENTIFIER

    return ZCODE_BUNDLE_IDENTIFIER


def _env_marker_present(env: Mapping[str, str], markers: frozenset[str]) -> bool:
    return any(isinstance(env.get(key), str) and env[key].strip() for key in markers)


def resolve_environment_harness(env: Mapping[str, str] | None = None) -> str | None:
    """Return the harness slug whose runtime markers appear in ``env``, if any.

    Guard commands spawned from an AI harness (package shims, protect, local
    supply-chain scans) inherit that harness's runtime environment even though
    no harness hook fired for them. This resolves the invoking harness from
    presence-only env markers so those requests can be attributed to the app
    that ran them instead of the synthetic Guard CLI surface. Marker families
    are disjoint in practice; the fixed order below is the deterministic
    tie-breaker when more than one matches.
    """

    source = os.environ if env is None else env
    if _env_marker_present(source, _zcode_env_markers()):
        return "zcode"
    bundle = source.get("__CFBundleIdentifier")
    if isinstance(bundle, str) and bundle.strip() == _zcode_bundle_identifier():
        return "zcode"
    if _env_marker_present(source, _CLAUDE_CODE_ENV_MARKERS):
        return "claude-code"
    if _env_marker_present(source, _CURSOR_ENV_MARKERS):
        return "cursor"
    if _env_marker_present(source, _CODEX_ENV_MARKERS):
        return "codex"
    return None


def cursor_runtime_detected(env: Mapping[str, str] | None = None) -> bool:
    """Return True when hook subprocess env indicates Cursor IDE/agent."""

    source = os.environ if env is None else env
    return any(isinstance(source.get(key), str) and source[key].strip() for key in _CURSOR_ENV_MARKERS)


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
    "resolve_environment_harness",
    "resolve_runtime_hook_harness",
]
