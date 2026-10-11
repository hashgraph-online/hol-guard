"""Execution-owned containment for exact local test and lint commands."""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path

from . import native_execution as _native_execution
from .runtime.contained_execution_common import canonical_existing_directory as _canonical_directory
from .runtime.effect_decision import EffectDecision, PositiveProof
from .runtime.package_intent_parser import parse_package_intent


@dataclass(frozen=True, slots=True)
class ContainedNodeResult:
    exit_code: int
    stdout: str
    stderr: str
    proof: PositiveProof
    decision: EffectDecision
    operation_id: str


def _package_shim_handoff_active(shim_directory: Path) -> bool:
    """Return whether this call came from Guard's installed package-shim boundary."""

    try:
        canonical = shim_directory.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    return canonical.name == "bin" and canonical.parent.name == "package-shims"


def _fail_closed_vitest_handoff(shim_directory: Path, runner: str | None, reason: str) -> None:
    """Stop an allowed native Vitest handoff instead of falling through uncontained."""

    if runner == "vitest" and _package_shim_handoff_active(shim_directory):
        raise SystemExit(f"HOL Guard refused uncontained Vitest execution: {reason}")


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

    normalized_manager = manager.strip().lower()
    if normalized_manager not in {"npx", "bunx"}:
        return None
    try:
        canonical_workspace = _canonical_directory(workspace)
        # The OS backends expose system runtime roots read-only. A project
        # beneath one of those roots would bypass omission via an absolute path.
        system_roots = ("/System", "/usr", "/bin", "/lib", "/lib64", "/sbin")
        if any(canonical_workspace.is_relative_to(Path(root).resolve(strict=False)) for root in system_roots):
            return None
    except ValueError:
        return None
    intent = parse_package_intent(
        shlex.join((normalized_manager, *argv)),
        workspace=canonical_workspace,
        guard_home=guard_home,
    )
    if intent is None or len(intent.local_executions) != 1:
        return None
    execution = intent.local_executions[0]
    native_result = _native_execution.contained_node_execute_native(
        workspace,
        normalized_manager,
        argv,
        guard_home=guard_home,
        evidence=execution.to_dict(),
    )
    if native_result is None:
        # The resident owns the decision; an absent answer is never replaced by Python.
        _fail_closed_vitest_handoff(shim_directory, execution.package_name, "native containment was unavailable")
    return native_result
