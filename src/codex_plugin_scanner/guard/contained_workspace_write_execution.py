"""Guard-owned containment and atomic promotion for one workspace output."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from . import native_execution as _native_execution
from .runtime.contained_execution_common import (
    canonical_existing_directory as _canonical_directory,
)
from .runtime.contained_execution_common import (
    clean_containment_environment as _clean_environment,
)
from .runtime.effect_decision import EffectDecision, PositiveProof

ContainedWriteOperation = Literal["patch-check", "patch-apply", "format-write", "copy-generated"]


@dataclass(frozen=True, slots=True)
class ContainedWorkspaceWriteResult:
    exit_code: int
    stdout: str
    stderr: str
    proof: PositiveProof
    decision: EffectDecision
    operation_id: ContainedWriteOperation
    output_digest: str | None


def try_execute_contained_workspace_write(
    operation: ContainedWriteOperation,
    *,
    workspace: Path,
    guard_home: Path,
    source: str,
    target: str | None = None,
    environment: dict[str, str] | None = None,
    timeout_seconds: float = 120.0,
) -> ContainedWorkspaceWriteResult | None:
    """Execute one exact operation and promote at most one declared output."""

    try:
        canonical_workspace = _canonical_directory(workspace)
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    return _native_execution.contained_workspace_write_execute_native(
        canonical_workspace,
        guard_home=guard_home,
        operation=operation,
        source=source,
        target=target,
        environment=dict(_clean_environment(environment or dict(os.environ))),
        timeout_seconds=timeout_seconds,
    )


__all__ = ("ContainedWorkspaceWriteResult", "try_execute_contained_workspace_write")
