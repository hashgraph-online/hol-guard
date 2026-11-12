"""Execution-owned containment for exact local TypeScript checks.

The resident owns the whole launch: it parses the package intent from the
shim's manager and argv, runs the single local compiler check under
enforcement and returns the verdict.
"""

from __future__ import annotations

from pathlib import Path

from . import native_execution as _native_execution
from .contained_runner_result import ContainedRunnerResult

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

    return _native_execution.contained_typescript_execute_native(
        workspace,
        manager,
        argv,
        guard_home=guard_home,
        shim_directory=shim_directory,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )


__all__ = ("ContainedTypeScriptResult", "try_execute_contained_typescript")
