"""Execution-owned containment for exact local TypeScript checks."""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path

from . import native_execution as _native_execution
from .runtime.contained_execution_common import canonical_existing_directory as _canonical_directory
from .runtime.effect_decision import EffectDecision, PositiveProof
from .runtime.package_intent_parser import parse_package_intent


@dataclass(frozen=True, slots=True)
class ContainedTypeScriptResult:
    exit_code: int
    stdout: str
    stderr: str
    proof: PositiveProof
    decision: EffectDecision
    operation_id: str = "typecheck"


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
    local_execution = intent.local_executions[0]
    return _native_execution.contained_typescript_execute_native(
        workspace,
        manager.strip().lower(),
        argv,
        guard_home=guard_home,
        evidence=local_execution.to_dict(),
    )


__all__ = ("ContainedTypeScriptResult", "try_execute_contained_typescript")
