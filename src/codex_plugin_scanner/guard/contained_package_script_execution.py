"""Execution-owned containment for exact local Bun package scripts.

The resident rebuilds the script evidence from the workspace, owns containment
and enforcement, and decides the verdict.
"""

from __future__ import annotations

from pathlib import Path

from . import native_execution as _native_execution
from .contained_runner_result import ContainedRunnerResult

ContainedPackageScriptResult = ContainedRunnerResult


def try_execute_contained_package_script(
    manager: str,
    argv: tuple[str, ...],
    *,
    workspace: Path,
    guard_home: Path,
    shim_directory: Path,
    environment: dict[str, str],
    timeout_seconds: float = 120.0,
) -> ContainedPackageScriptResult | None:
    """Run one exact result-only Bun script, or fail back to Guard review."""

    if manager.strip().lower() != "bun":
        return None
    return _native_execution.contained_package_script_execute_native(
        workspace,
        "bun",
        argv,
        guard_home=guard_home,
        shim_directory=shim_directory,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )


__all__ = ("ContainedPackageScriptResult", "try_execute_contained_package_script")
