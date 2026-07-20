"""Guard-owned containment and atomic promotion for one workspace output."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, cast

from .runtime.containment_contract import ContainmentAttestation, ContainmentPolicy, ContainmentRequest
from .runtime.containment_executor import execute_contained, file_sha256
from .runtime.containment_health import ContainmentHealthEvidence, contained_positive_proof
from .runtime.containment_outputs import ContainmentCapturedOutput
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
from .runtime.secret_sensitivity import classify_secret_path
from .runtime.workspace_snapshot_inputs import complete_workspace_snapshot

ContainedWriteOperation = Literal["patch-check", "patch-apply", "format-write", "copy-generated"]
_PROTECTED_PARTS = frozenset({".git", ".guard", ".ssh", "guard-home"})


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
        invocation = _invocation(operation, source, target, canonical_workspace, environment or dict(os.environ))
        executable, argv, source_path, target_path = invocation
        workspace_digest, inputs = complete_workspace_snapshot(canonical_workspace)
        executable_digest = file_sha256(executable)
        launch_digest = _binding_digest(
            {
                "operation": operation,
                "argv": list(argv),
                "executable": executable_digest,
                "workspace": workspace_digest,
                "source": source_path,
                "target": target_path,
            }
        )
        allowed_writes = (str((canonical_workspace / target_path).parent),) if target_path is not None else ()
        request = ContainmentRequest(
            argv=(executable, *argv),
            cwd=str(canonical_workspace),
            environment=_clean_environment(environment or dict(os.environ)),
            policy=ContainmentPolicy(str(canonical_workspace), allowed_writes),
            inputs=inputs,
            launch_digest=launch_digest,
            executable_digest=executable_digest,
            operation_id=operation,
            declared_outputs=(target_path,) if target_path is not None else (),
        )
        health, runtime_fingerprint = _load_current_containment_health(guard_home)
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    execution = execute_contained(request, timeout_seconds=timeout_seconds)
    if not execution.enforced or execution.exit_code is None:
        return None
    if execution.exit_code != 0:
        return _result_without_promotion(
            operation,
            request,
            execution.exit_code,
            execution.stdout,
            execution.stderr,
            execution.attestation,
            health,
            runtime_fingerprint,
            workspace_digest,
        )
    output: ContainmentCapturedOutput | None = None
    if target_path is not None:
        if len(execution.outputs) != 1 or execution.outputs[0].snapshot_path != target_path:
            return None
        output = execution.outputs[0]
    try:
        proof = _proof_from_execution(
            request,
            execution.attestation,
            health,
            runtime_fingerprint,
            workspace_digest=workspace_digest,
            output=output,
        )
        decision = _contained_decision(proof, operation=operation)
    except ValueError:
        return None
    if decision.disposition is not FinalDisposition.SILENT_CONTAINED:
        return None
    if output is not None and target_path is not None:
        try:
            current_digest, _current_inputs = complete_workspace_snapshot(canonical_workspace)
            if current_digest != workspace_digest:
                return None
            expected_digest = next(
                (item.content_digest for item in inputs if item.snapshot_path == target_path),
                None,
            )
            _promote_output(canonical_workspace, target_path, output.content, expected_digest=expected_digest)
        except (OSError, RuntimeError, ValueError):
            return None
    return ContainedWorkspaceWriteResult(
        execution.exit_code,
        execution.stdout,
        execution.stderr,
        proof,
        decision,
        operation,
        output.content_digest if output is not None else None,
    )


def _result_without_promotion(
    operation: ContainedWriteOperation,
    request: ContainmentRequest,
    exit_code: int,
    stdout: str,
    stderr: str,
    attestation: ContainmentAttestation,
    health: ContainmentHealthEvidence,
    runtime_fingerprint: str,
    workspace_digest: str,
) -> ContainedWorkspaceWriteResult | None:
    if operation != "patch-check":
        return None
    try:
        base = _proof_from_execution(
            request,
            attestation,
            health,
            runtime_fingerprint,
            workspace_digest=workspace_digest,
            output=None,
        )
        decision = _contained_decision(base, operation=operation)
    except ValueError:
        return None
    return ContainedWorkspaceWriteResult(exit_code, stdout, stderr, base, decision, operation, None)


def _proof_from_execution(
    request: ContainmentRequest,
    attestation: ContainmentAttestation,
    health: ContainmentHealthEvidence,
    runtime_fingerprint: str,
    *,
    workspace_digest: str,
    output: ContainmentCapturedOutput | None,
) -> PositiveProof:
    health_bound = contained_positive_proof(
        attestation,
        request,
        health,
        requirements=_requirements(),
        now=datetime.now(timezone.utc),
        runtime_fingerprint=runtime_fingerprint,
    )
    return PositiveProof(
        route=ProofRoute.CONTAINED,
        binding_digest=_binding_digest(
            {
                "base": health_bound.binding_digest,
                "workspace": workspace_digest,
                "output_path": output.snapshot_path if output is not None else None,
                "output_digest": output.content_digest if output is not None else None,
            }
        ),
        satisfied_requirements=health_bound.satisfied_requirements,
        enforced=True,
    )


def _requirements() -> tuple[ProofRequirement, ...]:
    return (
        ProofRequirement.OPERATION_AND_TARGETS,
        ProofRequirement.WORKSPACE_IDENTITY,
        ProofRequirement.WORKING_DIRECTORY_IDENTITY,
        ProofRequirement.EXECUTABLE_IDENTITY,
        ProofRequirement.LAUNCH_CHAIN,
        ProofRequirement.SHELL_DATA_FLOW,
        ProofRequirement.PARSER_CONFIDENCE,
        ProofRequirement.EXPECTED_EFFECTS,
    )


def _contained_decision(proof: PositiveProof, *, operation: ContainedWriteOperation) -> EffectDecision:
    assessment = EffectAssessment(
        kind=EffectKind.PROCESS_EXECUTION if operation == "patch-check" else EffectKind.WORKSPACE_WRITE,
        target_scope=EffectTargetScope.WORKSPACE,
        reversibility=EffectReversibility.REVERSIBLE,
        blast_radius=EffectBlastRadius.SINGLE_RESOURCE,
        evidence_source=EffectEvidenceSource.CONTAINMENT,
        confidence=EffectConfidence.STRONG,
        containment=ContainmentRequirement.REQUIRED,
        proof_requirements=frozenset({*_requirements(), ProofRequirement.CONTAINMENT_IDENTITY}),
    )
    return evaluate_effect_decision(
        EffectDecisionRequest(
            factors=(
                DecisionFactor(
                    source=DecisionFactorSource.EFFECT,
                    reason_code=f"contained-{operation}",
                    basis=DecisionBasis("allow", ProofRoute.CONTAINED),
                    operation_ref=f"operation:{operation}",
                    producer_ref="containment:workspace-write-v1",
                    evidence_digest=proof.binding_digest,
                    assessment=assessment,
                    proof=proof,
                ),
            )
        )
    )


def _invocation(
    operation: ContainedWriteOperation,
    source: str,
    target: str | None,
    workspace: Path,
    environment: dict[str, str],
) -> tuple[str, tuple[str, ...], str, str | None]:
    source_path = _safe_relative(source, workspace, must_exist=True)
    if operation == "patch-check":
        if target is not None or not source_path.endswith(".patch"):
            raise ValueError("patch-check requires exactly one patch input")
        return _resolve_executable("git", environment), ("apply", "--check", source_path), source_path, None
    if target is None:
        raise ValueError("write operations require one exact output")
    target_path = _safe_relative(target, workspace, must_exist=False)
    if operation == "patch-apply":
        if not source_path.endswith(".patch"):
            raise ValueError("patch-apply requires a patch input")
        return _resolve_executable("git", environment), ("apply", source_path), source_path, target_path
    if operation == "format-write":
        if source_path != target_path or not source_path.endswith(".py"):
            raise ValueError("format-write requires one in-place Python target")
        return _resolve_executable("ruff", environment), ("format", source_path), source_path, target_path
    if operation == "copy-generated":
        return _resolve_executable("cp", environment), (source_path, target_path), source_path, target_path


def _safe_relative(value: str, workspace: Path, *, must_exist: bool) -> str:
    path = Path(value)
    if not value or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("workspace paths must be canonical relative paths")
    portable = path.as_posix()
    if portable != value.replace("\\", "/") or classify_secret_path(portable, cwd=workspace) is not None:
        raise ValueError("workspace path is aliased or secret-bearing")
    if any(part.lower() in _PROTECTED_PARTS or part.lower().startswith(".env") for part in path.parts):
        raise ValueError("workspace path is protected")
    candidate = workspace / path
    parent = candidate.parent.resolve(strict=True)
    if parent.is_symlink() or not parent.is_relative_to(workspace):
        raise ValueError("workspace path escapes through its parent")
    if must_exist:
        metadata = candidate.stat(follow_symlinks=False)
        if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("workspace input must be a singly linked regular file")
        if candidate.resolve(strict=True) != candidate:
            raise ValueError("workspace input cannot contain aliases")
    elif candidate.is_symlink() or (candidate.exists() and not candidate.is_file()):
        raise ValueError("workspace output must be absent or a regular file")
    return portable


def _promote_output(workspace: Path, target: str, content: bytes, *, expected_digest: str | None) -> None:
    raw_nofollow = cast(object, getattr(os, "O_NOFOLLOW", None))
    raw_directory = cast(object, getattr(os, "O_DIRECTORY", None))
    if type(raw_nofollow) is not int or type(raw_directory) is not int or os.open not in os.supports_dir_fd:
        raise RuntimeError("secure descriptor-relative output promotion is unavailable")
    common = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | raw_nofollow
    relative = Path(target)
    descriptors: list[int] = []
    temporary_name = f".guard-output-{secrets.token_hex(16)}"
    temporary_created = False
    try:
        current = os.open(workspace, common | raw_directory)
        descriptors.append(current)
        for part in relative.parts[:-1]:
            current = os.open(part, common | raw_directory, dir_fd=current)
            descriptors.append(current)
        name = relative.parts[-1]
        expected_state = _target_state(current, name)
        if (expected_state[0] if expected_state is not None else None) != expected_digest:
            raise ValueError("workspace output changed before atomic promotion")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | raw_nofollow
        temporary = os.open(temporary_name, flags, 0o600, dir_fd=current)
        temporary_created = True
        try:
            os.fchmod(temporary, expected_state[1] if expected_state is not None else 0o600)
            offset = 0
            while offset < len(content):
                offset += os.write(temporary, content[offset:])
            os.fsync(temporary)
        finally:
            os.close(temporary)
        if _target_state(current, name) != expected_state:
            raise ValueError("workspace output changed during atomic promotion")
        os.replace(temporary_name, name, src_dir_fd=current, dst_dir_fd=current)
        temporary_created = False
        with suppress(OSError):
            os.fsync(current)
    finally:
        if temporary_created and descriptors:
            with suppress(OSError):
                os.unlink(temporary_name, dir_fd=descriptors[-1])
        for descriptor in reversed(descriptors):
            with suppress(OSError):
                os.close(descriptor)


def _target_state(directory: int, name: str) -> tuple[str, int] | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("workspace output target must be a singly linked regular file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest(), stat.S_IMODE(metadata.st_mode)
    finally:
        os.close(descriptor)


def _resolve_executable(name: str, environment: dict[str, str]) -> str:
    candidate = shutil.which(name, path=environment.get("PATH", ""))
    if candidate is None:
        raise ValueError(f"{name} executable unavailable")
    canonical = Path(candidate).resolve(strict=True)
    if not canonical.is_file() or not os.access(canonical, os.X_OK):
        raise ValueError(f"{name} executable is not path-pinned")
    return str(canonical)


def _load_current_containment_health(guard_home: Path) -> tuple[ContainmentHealthEvidence, str]:
    from .daemon.client import load_guard_surface_daemon_client
    from .daemon.manager import current_guard_daemon_runtime_fingerprint

    client = load_guard_surface_daemon_client(guard_home.resolve(strict=True))
    evidence = ContainmentHealthEvidence.from_mapping(client.containment_health())
    runtime_fingerprint = current_guard_daemon_runtime_fingerprint()
    errors = evidence.compatibility_errors(now=datetime.now(timezone.utc), runtime_fingerprint=runtime_fingerprint)
    if errors:
        raise RuntimeError(f"containment health incompatible: {errors[0]}")
    return evidence, runtime_fingerprint


def _canonical_directory(path: Path) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("workspace must be an existing canonical directory")
    canonical = path.resolve(strict=True)
    if canonical != Path(os.path.normpath(str(path))):
        raise ValueError("workspace cannot contain aliases")
    return canonical


def _clean_environment(environment: dict[str, str]) -> tuple[tuple[str, str], ...]:
    keys = ("LANG", "LC_ALL", "LC_CTYPE", "NO_COLOR", "TERM")
    return tuple(sorted((key, value) for key in keys if (value := environment.get(key))))


def _binding_digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(len(encoded).to_bytes(8, "big") + encoded).hexdigest()


__all__ = ("ContainedWorkspaceWriteResult", "try_execute_contained_workspace_write")
