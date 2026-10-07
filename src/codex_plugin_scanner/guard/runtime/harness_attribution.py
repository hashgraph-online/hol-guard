"""Resolve which harness initiated a runtime hook invocation."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping
from pathlib import PurePath

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
_CODEX_ENV_MARKERS = frozenset({"CODEX_SANDBOX", "CODEX_THREAD_ID"})
_GROK_ENV_MARKERS = frozenset({"GROK_AGENT", "GROK_SESSION_ID"})
_OPENCODE_ENV_MARKERS = frozenset({"OPENCODE_CONFIG_CONTENT"})
_DEVIN_ENV_MARKERS = frozenset({"DEVIN_PROJECT_DIR"})
ORIGIN_HARNESS_ENV = "HOL_GUARD_ORIGIN_HARNESS"
_ORIGIN_HARNESS_VALUES = frozenset(
    {
        "claude-code",
        "codex",
        "copilot",
        "cursor",
        "gemini",
        "grok",
        "omp",
        "opencode",
        "pi",
        "zcode",
        "devin",
    }
)

_PROCESS_HARNESSES = {
    "codex": "codex",
    "claude": "claude-code",
    "cursor": "cursor",
    "cursor-agent": "cursor",
    "zcode": "zcode",
    "zcode-cli": "zcode",
    "grok": "grok",
    "pi": "pi",
    "omp": "omp",
    "opencode": "opencode",
    "devin": "devin",
}
_APP_PATH_MARKERS = (
    ("/codex.app/", "codex"),
    ("/cursor.app/", "cursor"),
    ("/grok.app/", "grok"),
    ("/claude.app/", "claude-code"),
    ("/opencode.app/", "opencode"),
    ("/zcode.app/", "zcode"),
    ("/devin.app/", "devin"),
)


def resolve_parent_process_harness() -> str | None:
    """Best-effort display attribution when a harness supplies no env marker.

    Inspect executable names only, never arguments or process environments.
    Bound traversal and elapsed time; failures leave the origin unknown. This
    signal must never be used as an authorization or policy selector.
    """
    if os.name == "nt":
        return None
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "pid=,ppid=,comm="],
            capture_output=True,
            text=True,
            check=False,
            timeout=0.5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    parents: dict[int, tuple[int, str]] = {}
    for row in result.stdout.splitlines():
        try:
            process, parent, executable = row.strip().split(maxsplit=2)
            parents[int(process)] = (int(parent), executable)
        except ValueError:
            continue
    pid = os.getppid()
    seen: set[int] = set()
    for _ in range(8):
        if pid <= 1 or pid in seen or pid not in parents:
            break
        seen.add(pid)
        pid, executable = parents[pid]
        harness = _harness_from_executable(executable)
        if harness:
            return harness
    return None


def _harness_from_executable(path: str) -> str | None:
    name = PurePath(path).name.lower()
    if name.endswith(".exe"):
        name = name[:-4]
    mapped = _PROCESS_HARNESSES.get(name)
    if mapped:
        return mapped
    posix = path.replace("\\", "/").lower()
    for marker, harness in _APP_PATH_MARKERS:
        if marker in posix:
            return harness
    return None


def origin_harness_env(harness: str) -> dict[str, str]:
    """Stamp a known harness onto a Guard-spawned child for display attribution."""

    slug = harness.strip().lower().replace("_", "-")
    if slug not in _ORIGIN_HARNESS_VALUES:
        return {}
    return {ORIGIN_HARNESS_ENV: slug}


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
    origin = source.get(ORIGIN_HARNESS_ENV)
    if isinstance(origin, str):
        slug = origin.strip().lower().replace("_", "-")
        if slug in _ORIGIN_HARNESS_VALUES:
            return slug
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
    if _env_marker_present(source, _GROK_ENV_MARKERS):
        return "grok"
    if _env_marker_present(source, _OPENCODE_ENV_MARKERS):
        return "opencode"
    if _env_marker_present(source, _DEVIN_ENV_MARKERS):
        return "devin"
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
    "ORIGIN_HARNESS_ENV",
    "cursor_hook_query_extras",
    "cursor_runtime_detected",
    "origin_harness_env",
    "resolve_environment_harness",
    "resolve_parent_process_harness",
    "resolve_runtime_hook_harness",
]
