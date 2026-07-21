"""Execution-owned containment for exact local Bun package scripts."""

from __future__ import annotations

import hashlib
import json
import os
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
from .runtime.local_package_script_evidence import build_local_package_script_evidence
from .runtime.workspace_snapshot_inputs import complete_workspace_snapshot, reject_external_node_modules


@dataclass(frozen=True, slots=True)
class ContainedPackageScriptResult:
    exit_code: int
    stdout: str
    stderr: str
    proof: PositiveProof
    decision: EffectDecision
    operation_id: str


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
    try:
        canonical_workspace = _canonical_directory(workspace)
        evidence = build_local_package_script_evidence("bun", argv, workspace=canonical_workspace)
    except (OSError, ValueError):
        return None
    if evidence is None or evidence.status != "complete" or evidence.direct_silent_verification:
        return None
    if evidence.executable_path is None or evidence.executable_hash is None:
        return None
    runner = Path(evidence.executable_path)
    try:
        runner_relative = runner.relative_to(canonical_workspace).as_posix()
        reject_external_node_modules(canonical_workspace)
        workspace_digest, inputs = complete_workspace_snapshot(canonical_workspace)
        runner_digest = file_sha256(str(runner))
        bun_path = _resolve_bun(environment.get("PATH", ""), shim_directory)
        bun_digest = file_sha256(bun_path)
    except (OSError, ValueError):
        return None
    if f"sha256:{runner_digest}" != evidence.executable_hash:
        return None
    snapshot_digests = {item.snapshot_path: f"sha256:{item.content_digest}" for item in inputs}
    expected = {
        "package.json": evidence.root_manifest_hash,
        "package-lock.json": evidence.lockfile_hash,
        f"node_modules/{_runner_package(evidence.runner)}/package.json": evidence.package_manifest_hash,
        runner_relative: evidence.executable_hash,
    }
    if any(snapshot_digests.get(path) != digest for path, digest in expected.items()):
        return None
    launch_digest = _binding_digest(
        {
            "script_evidence": evidence.binding_digest,
            "workspace_digest": workspace_digest,
            "runner_digest": runner_digest,
            "bun_digest": bun_digest,
            "runner_args": list(evidence.runner_args),
        }
    )
    request = ContainmentRequest(
        argv=(bun_path, runner_relative, *evidence.runner_args),
        cwd=str(canonical_workspace),
        environment=_clean_environment(environment),
        policy=ContainmentPolicy(str(canonical_workspace), ()),
        inputs=inputs,
        launch_digest=launch_digest,
        executable_digest=bun_digest,
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
    return ContainedPackageScriptResult(
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
                    producer_ref="containment:bun-package-script-v1",
                    evidence_digest=proof.binding_digest,
                    assessment=assessment,
                    proof=proof,
                ),
            )
        )
    )


def _resolve_bun(path_value: str, shim_directory: Path) -> str:
    shim = str(shim_directory.resolve(strict=True))
    filtered = os.pathsep.join(
        entry for entry in path_value.split(os.pathsep) if entry and str(Path(entry).resolve(strict=False)) != shim
    )
    candidate = shutil.which("bun", path=filtered)
    if candidate is None:
        raise ValueError("Bun executable unavailable")
    canonical = Path(candidate).resolve(strict=True)
    if canonical == Path(shim) or canonical.is_relative_to(Path(shim)):
        raise ValueError("Bun executable resolves inside the shim directory")
    if not canonical.is_file() or not os.access(canonical, os.X_OK):
        raise ValueError("Bun executable is not path-pinned")
    return str(canonical)


def _runner_package(runner: str) -> str:
    return "typescript" if runner == "tsc" else runner


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


__all__ = ("ContainedPackageScriptResult", "try_execute_contained_package_script")
