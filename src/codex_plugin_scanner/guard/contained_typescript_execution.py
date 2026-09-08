"""Execution-owned containment for exact local TypeScript checks."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from .containment_execution_support import (
    contained_process_effect_decision as _contained_decision,
)
from .containment_execution_support import (
    containment_positive_proof as _proof_from_result,
)
from .containment_execution_support import (
    load_current_containment_health as _load_current_containment_health,
)
from .runtime.contained_execution_common import (
    canonical_existing_directory as _canonical_directory,
)
from .runtime.contained_execution_common import (
    clean_containment_environment as _clean_environment,
)
from .runtime.contained_execution_common import (
    containment_binding_digest as _binding_digest,
)
from .runtime.containment_contract import ContainmentPolicy, ContainmentRequest
from .runtime.containment_executor import execute_contained, file_sha256
from .runtime.effect_decision import EffectDecision, PositiveProof
from .runtime.package_intent_parser import parse_package_intent
from .runtime.typescript_snapshot_inputs import typescript_snapshot_inputs


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
        _shell_join(("npx", *argv)),
        workspace=canonical_workspace,
    )
    if intent is None or len(intent.local_executions) != 1:
        return None
    local_execution = intent.local_executions[0]
    evidence = local_execution.typescript_launch
    if evidence is None or evidence.status != "complete" or evidence.direct_silent_verification:
        return None
    executable = local_execution.local_executable
    if executable is None or executable.resolved_path is None or executable.content_hash is None:
        return None
    compiler = Path(executable.resolved_path)
    package_root = compiler.parent.parent
    if package_root.name != "typescript" or package_root.parent.name != "node_modules":
        return None
    compiler_args = _compiler_args(argv)
    if compiler_args is None:
        return None
    try:
        tree_digest, package_inputs, closure_digest, closure_inputs = typescript_snapshot_inputs(
            canonical_workspace,
            package_root,
            evidence.source_files,
        )
        compiler_digest = file_sha256(str(compiler))
        node_path = _resolve_node(environment.get("PATH", ""), shim_directory)
        node_digest = file_sha256(node_path)
    except (OSError, ValueError):
        return None
    launch_digest = _binding_digest(
        {
            "typescript_evidence": evidence.binding_digest,
            "tree_digest": tree_digest,
            "closure_digest": closure_digest,
            "compiler_digest": compiler_digest,
            "node_digest": node_digest,
            "compiler_args": list(compiler_args),
        }
    )
    request = ContainmentRequest(
        argv=(node_path, "node_modules/typescript/bin/tsc", *compiler_args),
        cwd=str(canonical_workspace),
        environment=_clean_environment(environment),
        policy=ContainmentPolicy(str(canonical_workspace), ()),
        inputs=(*package_inputs, *closure_inputs),
        launch_digest=launch_digest,
        executable_digest=node_digest,
        operation_id="typecheck",
    )
    try:
        health, runtime_fingerprint = _load_current_containment_health(guard_home)
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    result = execute_contained(request, timeout_seconds=timeout_seconds)
    if not result.enforced or result.exit_code != 0:
        return None
    try:
        proof = _proof_from_result(result, request, health, runtime_fingerprint)
    except ValueError:
        return None
    decision = _contained_decision(
        proof,
        operation_id="typecheck",
        producer_ref="containment:typescript-v1",
        reason_code="routine-typecheck-contained",
    )
    if decision.disposition.value != "silent-contained":
        return None
    return ContainedTypeScriptResult(result.exit_code, result.stdout, result.stderr, proof, decision)


def _compiler_args(argv: tuple[str, ...]) -> tuple[str, ...] | None:
    try:
        index = argv.index("tsc")
    except ValueError:
        return None
    return argv[index + 1 :]


def _resolve_node(path_value: str, shim_directory: Path) -> str:
    shim = str(shim_directory.resolve(strict=True))
    filtered = os.pathsep.join(
        entry for entry in path_value.split(os.pathsep) if entry and str(Path(entry).resolve(strict=False)) != shim
    )
    candidate = shutil.which("node", path=filtered)
    if candidate is None:
        raise ValueError("node executable unavailable")
    path = Path(candidate)
    canonical = path.resolve(strict=True)
    shim_path = Path(shim)
    if (
        canonical == shim_path
        or canonical.is_relative_to(shim_path)
        or not canonical.is_file()
        or not os.access(canonical, os.X_OK)
    ):
        raise ValueError("node executable is not path-pinned")
    return str(canonical)


def _shell_join(tokens: tuple[str, ...]) -> str:
    import shlex

    return shlex.join(tokens)


__all__ = ("ContainedTypeScriptResult", "try_execute_contained_typescript")
