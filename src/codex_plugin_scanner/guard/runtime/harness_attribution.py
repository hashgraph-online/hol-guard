"""Ask the native runtime which harness initiated a Guard process.

The native ``harness_attribution`` kind owns the runtime markers, the
environment families, the process-name table and the bounded parent walk. This
module only reads this process's environment and parent id, passes them in and
returns the answer. The result is display and request identity, never an
authorization or a policy selector.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

_KIND = "harness_attribution"


def _ask(op: str, **fields: object) -> dict[str, Any]:
    from ..native_runner_authority import native_runner_authority

    return native_runner_authority(_KIND, {"op": op, **fields})


def _harness(answer: dict[str, Any]) -> str | None:
    harness = answer.get("harness")
    return harness if isinstance(harness, str) else None


def _environment(env: Mapping[str, str] | None) -> dict[str, str]:
    """The marker variables of this process, or of the mapping a caller names."""
    if env is not None:
        return {key: value for key, value in env.items() if isinstance(value, str)}
    from ..native_harness_client import request_environment

    return request_environment()


def resolve_parent_process_harness() -> str | None:
    """The nearest harness among this process's parents, or ``None``."""
    return _harness(_ask("parent", ppid=os.getppid()))


def resolve_environment_harness(env: Mapping[str, str] | None = None) -> str | None:
    """The harness whose runtime markers appear in ``env`` (this process's by default)."""
    return _harness(_ask("environment", env=_environment(env)))


def resolve_runtime_hook_harness(
    requested_harness: str,
    *,
    env: Mapping[str, str] | None = None,
) -> str:
    """The harness a hook runs as.

    Claude-compatible hooks inside Cursor are Cursor's, but Claude Code's own
    markers win, so a Claude session started from a Cursor terminal stays Claude.
    """
    from ..native_runner_authority import NativeRunnerAuthorityError

    try:
        harness = _ask("runtime_hook", requested=requested_harness, env=_environment(env)).get("harness")
    except NativeRunnerAuthorityError:
        # With no runtime to attribute the hook, the harness that was asked for
        # stands: the hook still has to reach its fail-closed answer, and an
        # error here would leave the harness with no answer at all.
        return requested_harness
    return harness if isinstance(harness, str) else requested_harness


def origin_harness_env(harness: str) -> dict[str, str]:
    """The variable that stamps a known harness onto a Guard-spawned child."""
    stamp = _ask("origin_env", harness=harness).get("env")
    if not isinstance(stamp, dict):
        return {}
    return {str(key): str(value) for key, value in stamp.items()}


__all__ = [
    "origin_harness_env",
    "resolve_environment_harness",
    "resolve_parent_process_harness",
    "resolve_runtime_hook_harness",
]
