"""Execution-owned containment for exact local TypeScript checks.

The resident owns containment, enforcement and the verdict; this module only
parses the launch intent the resident needs as evidence.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from . import native_execution as _native_execution
from .contained_runner_result import ContainedRunnerResult
from .runtime.contained_execution_common import (
    canonical_existing_directory as _canonical_directory,
)
from .runtime.package_intent_parser import parse_package_intent

ContainedTypeScriptResult = ContainedRunnerResult


def try_execute_contained_typescript(
    manager: str,
    argv: tuple[str, ...],
    *,
    workspace: Path,
    guard_home: Path,
    shim_directory: Path,
    environment: dict[str, str],
    timeout_seconds: float = 120.0,
) -> ContainedTypeScriptResult | None:
    """Run one exact compiler check under enforcement or return to Guard review."""

    if manager.strip().lower() != "npx":
        return None
    canonical_workspace = _canonical_directory(workspace)
    intent = parse_package_intent(
        shlex.join(("npx", *argv)),
        workspace=canonical_workspace,
        guard_home=guard_home,
    )
    if intent is None or len(intent.local_executions) != 1:
        return None
    return _native_execution.contained_typescript_execute_native(
        canonical_workspace,
        "npx",
        argv,
        guard_home=guard_home,
        shim_directory=shim_directory,
        environment=environment,
        evidence=intent.local_executions[0].to_dict(),
        timeout_seconds=timeout_seconds,
    )


__all__ = ("ContainedTypeScriptResult", "try_execute_contained_typescript")
