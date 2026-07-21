"""Execution-owned containment for exact local test and lint commands."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .runtime.containment_contract import ContainmentPolicy, ContainmentRequest
from .runtime.containment_executor import ContainmentExecutionResult, execute_contained, file_sha256
from .runtime.containment_health import ContainmentHealthEvidence, contained_positive_proof
from .runtime.effect_contract import (
    ContainmentRequirement,
    DecisionBasis,
    EffectAssessment,
    EffectBlastRadius,
    EffectConfidence,
    EffectEvidenceSource,
    EffectKind,
    EffectReversibility,
    EffectTargetScope,
    ProofRequirement,
    ProofRoute,
)
from .runtime.effect_decision import (
    DecisionFactor,
    DecisionFactorSource,
    EffectDecision,
    EffectDecisionRequest,
    FinalDisposition,
    PositiveProof,
    evaluate_effect_decision,
)
from .runtime.local_node_runner_evidence import build_local_node_runner_evidence
from .runtime.package_intent_parser import parse_package_intent
from .runtime.workspace_snapshot_inputs import complete_workspace_snapshot, reject_external_node_modules


@dataclass(frozen=True, slots=True)
class ContainedNodeResult:
    exit_code: int
    stdout: str
    stderr: str
    proof: PositiveProof
    decision: EffectDecision
    operation_id: str


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
    if normalized_manager != "npx":
        return None
    try:
        canonical_workspace = _canonical_directory(workspace)
    except ValueError:
        return None
    intent = parse_package_intent(
        shlex.join((normalized_manager, *argv)),
        workspace=canonical_workspace,
    )
    if intent is None or len(intent.local_executions) != 1:
        return None
    execution = intent.local_executions[0]
    evidence = build_local_node_runner_evidence(
        normalized_manager,
        argv,
        execution,
        workspace=canonical_workspace,
    )
    if evidence is None or evidence.status != "complete" or evidence.direct_silent_verification:
        return None
    if evidence.executable_path is None or evidence.executable_hash is None:
        return None
    executable = Path(evidence.executable_path)
    try:
        executable_relative = executable.relative_to(canonical_workspace).as_posix()
        reject_external_node_modules(canonical_workspace)
        workspace_digest, inputs = complete_workspace_snapshot(canonical_workspace)
        executable_digest = file_sha256(str(executable))
        node_path = _resolve_node(environment.get("PATH", ""), shim_directory)
        node_digest = file_sha256(node_path)
    except (OSError, ValueError):
        return None
    if f"sha256:{executable_digest}" != evidence.executable_hash:
        return None
    snapshot_digests = {item.snapshot_path: f"sha256:{item.content_digest}" for item in inputs}
    expected_snapshot_digests = {
        "package.json": evidence.root_manifest_hash,
        "package-lock.json": evidence.lockfile_hash,
        f"node_modules/{evidence.runner}/package.json": evidence.package_manifest_hash,
        executable_relative: evidence.executable_hash,
    }
    if any(snapshot_digests.get(path) != digest for path, digest in expected_snapshot_digests.items()):
        return None
    launch_digest = _binding_digest(
        {
            "runner_evidence": evidence.binding_digest,
            "workspace_digest": workspace_digest,
            "executable_digest": executable_digest,
            "node_digest": node_digest,
            "runner_args": list(evidence.runner_args),
        }
    )
    request = ContainmentRequest(
        argv=(node_path, executable_relative, *evidence.runner_args),
        cwd=str(canonical_workspace),
        environment=_clean_environment(environment),
        policy=ContainmentPolicy(str(canonical_workspace), ()),
        inputs=inputs,
        launch_digest=launch_digest,
        executable_digest=node_digest,
        operation_id=evidence.operation_id,
    )
    try:
        health, runtime_fingerprint = _load_current_containment_health(guard_home)
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    result = execute_contained(request, timeout_seconds=timeout_seconds)
    if not result.enforced or result.exit_code is None:
        return None
    try:
        proof = _proof_from_result(result, request, health, runtime_fingerprint)
    except ValueError:
        return None
    decision = _contained_decision(proof, operation_id=evidence.operation_id)
    if decision.disposition is not FinalDisposition.SILENT_CONTAINED:
        return None
    return ContainedNodeResult(
        result.exit_code,
        result.stdout,
        result.stderr,
        proof,
        decision,
        evidence.operation_id,
    )


def _proof_from_result(
    result: ContainmentExecutionResult,
    request: ContainmentRequest,
    health: ContainmentHealthEvidence,
    runtime_fingerprint: str,
) -> PositiveProof:
    return contained_positive_proof(
        result.attestation,
        request,
        health,
        requirements=(
            ProofRequirement.OPERATION_AND_TARGETS,
            ProofRequirement.WORKSPACE_IDENTITY,
            ProofRequirement.WORKING_DIRECTORY_IDENTITY,
            ProofRequirement.EXECUTABLE_IDENTITY,
            ProofRequirement.LAUNCH_CHAIN,
            ProofRequirement.PARSER_CONFIDENCE,
            ProofRequirement.EXPECTED_EFFECTS,
        ),
        now=datetime.now(timezone.utc),
        runtime_fingerprint=runtime_fingerprint,
    )


def _load_current_containment_health(guard_home: Path) -> tuple[ContainmentHealthEvidence, str]:
    from .daemon.client import load_guard_surface_daemon_client
    from .daemon.manager import current_guard_daemon_runtime_fingerprint

    client = load_guard_surface_daemon_client(guard_home.resolve(strict=True))
    evidence = ContainmentHealthEvidence.from_mapping(client.containment_health())
    runtime_fingerprint = current_guard_daemon_runtime_fingerprint()
    errors = evidence.compatibility_errors(
        now=datetime.now(timezone.utc),
        runtime_fingerprint=runtime_fingerprint,
    )
    if errors:
        raise RuntimeError(f"containment health incompatible: {errors[0]}")
    return evidence, runtime_fingerprint


def _contained_decision(proof: PositiveProof, *, operation_id: str) -> EffectDecision:
    requirements = frozenset(
        {
            ProofRequirement.OPERATION_AND_TARGETS,
            ProofRequirement.WORKSPACE_IDENTITY,
            ProofRequirement.WORKING_DIRECTORY_IDENTITY,
            ProofRequirement.EXECUTABLE_IDENTITY,
            ProofRequirement.LAUNCH_CHAIN,
            ProofRequirement.PARSER_CONFIDENCE,
            ProofRequirement.EXPECTED_EFFECTS,
            ProofRequirement.CONTAINMENT_IDENTITY,
        }
    )
    assessment = EffectAssessment(
        kind=EffectKind.PROCESS_EXECUTION,
        target_scope=EffectTargetScope.WORKSPACE,
        reversibility=EffectReversibility.TRIVIALLY_RECOVERABLE,
        blast_radius=EffectBlastRadius.WORKSPACE,
        evidence_source=EffectEvidenceSource.CONTAINMENT,
        confidence=EffectConfidence.STRONG,
        containment=ContainmentRequirement.REQUIRED,
        proof_requirements=requirements,
    )
    return evaluate_effect_decision(
        EffectDecisionRequest(
            factors=(
                DecisionFactor(
                    source=DecisionFactorSource.EFFECT,
                    reason_code=f"routine-{operation_id}-contained",
                    basis=DecisionBasis("allow", ProofRoute.CONTAINED),
                    operation_ref=f"operation:{operation_id}",
                    producer_ref="containment:local-node-v1",
                    evidence_digest=proof.binding_digest,
                    assessment=assessment,
                    proof=proof,
                ),
            )
        )
    )


def _resolve_node(path_value: str, shim_directory: Path) -> str:
    shim = str(shim_directory.resolve(strict=True))
    filtered = os.pathsep.join(
        entry for entry in path_value.split(os.pathsep) if entry and str(Path(entry).resolve(strict=False)) != shim
    )
    candidate = shutil.which("node", path=filtered)
    if candidate is None:
        raise ValueError("node executable unavailable")
    canonical = Path(candidate).resolve(strict=True)
    shim_path = Path(shim)
    if (
        canonical == shim_path
        or canonical.is_relative_to(shim_path)
        or not canonical.is_file()
        or not os.access(canonical, os.X_OK)
    ):
        raise ValueError("node executable is not path-pinned")
    return str(canonical)


def _clean_environment(environment: dict[str, str]) -> tuple[tuple[str, str], ...]:
    allowed: dict[str, str] = {}
    for key in ("LANG", "LC_ALL", "LC_CTYPE", "NO_COLOR", "TERM"):
        value = environment.get(key)
        if value:
            allowed[key] = value
    return tuple(sorted(allowed.items()))


def _canonical_directory(path: Path) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("workspace must be an existing canonical directory")
    canonical = path.resolve(strict=True)
    if canonical != Path(os.path.normpath(str(path))):
        raise ValueError("workspace cannot contain aliases")
    return canonical


def _binding_digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(len(encoded).to_bytes(8, "big") + encoded).hexdigest()


__all__ = ("ContainedNodeResult", "try_execute_contained_node_command")
