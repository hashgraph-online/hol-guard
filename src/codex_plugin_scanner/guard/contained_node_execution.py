"""Execution-owned containment for exact local test and lint commands.

The resident owns the whole launch: it parses the package intent from the
shim's manager and argv, applies the manager and workspace limits, runs the
single local execution under enforcement and returns the verdict. An allowed
Vitest handoff from Guard's installed package shims that cannot be contained
stops with ``SystemExit`` instead of falling through uncontained, including
when the resident gives no verdict at all.
"""

from __future__ import annotations

from pathlib import Path

from . import native_execution as _native_execution
from .contained_runner_result import ContainedRunnerResult

ContainedNodeResult = ContainedRunnerResult

_VITEST_REFUSAL = "HOL Guard refused uncontained Vitest execution: the resident returned no verdict"


def _package_shim_handoff_active(shim_directory: Path) -> bool:
    """Return whether this call came from Guard's installed package-shim boundary."""

    try:
        canonical = shim_directory.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    return canonical.name == "bin" and canonical.parent.name == "package-shims"


def _names_vitest(token: str) -> bool:
    """``vitest`` or a versioned ``vitest@<spec>`` package token.

    The resident owns the exact rule, over the package name it parsed out of
    the launch (``vitest_refusal`` in ``guard-command``). This reading is
    deliberately broader: it runs only where no verdict came back, so no
    parse exists to read, and a launch that merely mentions Vitest is stopped
    rather than handed to review uncontained.
    """

    return token == "vitest" or token.startswith("vitest@")


def try_execute_contained_node_command(
    manager: str,
    argv: tuple[str, ...],
    *,
    workspace: Path,
    guard_home: Path,
    shim_directory: Path,
    environment: dict[str, str],
    timeout_seconds: float = 120.0,
) -> ContainedNodeResult | None:
    """Run one exact local test or lint command, or return to Guard review."""

    try:
        return _native_execution.contained_node_execute_native(
            workspace,
            manager,
            argv,
            guard_home=guard_home,
            shim_directory=shim_directory,
            environment=environment,
            timeout_seconds=timeout_seconds,
            require_verdict=True,
        )
    except _native_execution.ContainedVerdictUnavailableError:
        # Without a verdict the resident cannot have parsed this launch, so
        # the shim stops anything that names Vitest rather than letting
        # review run it uncontained. A well-formed reply that returns the
        # launch to review still does.
        if _package_shim_handoff_active(shim_directory) and any(_names_vitest(token) for token in argv):
            raise SystemExit(_VITEST_REFUSAL) from None
        return None


__all__ = ("ContainedNodeResult", "try_execute_contained_node_command")
