"""Conservative candidates for Guard-owned contained workspace writes."""

from __future__ import annotations

from pathlib import Path
from typing import Final

from .command_model import CanonicalCommand, CommandSegment
from .effect_contract import (
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
)
from .effect_decision import DecisionFactor, DecisionFactorSource

WORKSPACE_WRITE_CANDIDATE_VERSION: Final = "guard.workspace-write-candidate.v1"


def workspace_write_candidate_factors(command: CanonicalCommand) -> tuple[DecisionFactor, ...]:
    """Retain review/block until Guard executes and promotes an exact output."""

    if _symlink_write_through(command):
        return (
            DecisionFactor(
                source=DecisionFactorSource.EFFECT,
                reason_code="workspace-symlink-write-blocked",
                basis=DecisionBasis("block", None),
                operation_ref="operation:workspace-symlink-write",
                producer_ref="policy:workspace-write-candidate-v1",
                assessment=EffectAssessment(
                    kind=EffectKind.EXTERNAL_FILESYSTEM_WRITE,
                    target_scope=EffectTargetScope.EXTERNAL_LOCAL,
                    reversibility=EffectReversibility.RECOVERABLE_WITH_REVIEW,
                    blast_radius=EffectBlastRadius.MULTIPLE_RESOURCES,
                    evidence_source=EffectEvidenceSource.PARSER,
                    confidence=EffectConfidence.STRONG,
                    containment=ContainmentRequirement.NOT_ELIGIBLE,
                    proof_requirements=frozenset(
                        {
                            ProofRequirement.OPERATION_AND_TARGETS,
                            ProofRequirement.WORKSPACE_IDENTITY,
                        }
                    ),
                ),
            ),
        )
    operation = workspace_write_candidate_operation(command)
    if operation is None:
        return ()
    kind = EffectKind.PROCESS_EXECUTION if operation == "patch-check" else EffectKind.WORKSPACE_WRITE
    return (
        DecisionFactor(
            source=DecisionFactorSource.EFFECT,
            reason_code="contained-workspace-write-proof-required",
            basis=DecisionBasis("review", None),
            operation_ref=f"operation:{operation}",
            producer_ref="policy:workspace-write-candidate-v1",
            assessment=EffectAssessment(
                kind=kind,
                target_scope=EffectTargetScope.WORKSPACE,
                reversibility=EffectReversibility.REVERSIBLE,
                blast_radius=EffectBlastRadius.WORKSPACE,
                evidence_source=EffectEvidenceSource.PARSER,
                confidence=EffectConfidence.STRONG,
                containment=ContainmentRequirement.REQUIRED,
                proof_requirements=frozenset(
                    {
                        ProofRequirement.OPERATION_AND_TARGETS,
                        ProofRequirement.WORKSPACE_IDENTITY,
                        ProofRequirement.EXECUTABLE_IDENTITY,
                        ProofRequirement.SHELL_DATA_FLOW,
                        ProofRequirement.EXPECTED_EFFECTS,
                        ProofRequirement.CONTAINMENT_IDENTITY,
                    }
                ),
            ),
        ),
    )


def workspace_write_candidate_operation(command: CanonicalCommand) -> str | None:
    """Return an operation only for the frozen simple workspace-write grammar."""

    if not _plain_command(command) or not command.segments:
        return None
    if len(command.segments) == 1:
        operation = command.segments[0]
    elif len(command.segments) == 2:
        directory, operation = command.segments
        if _name(directory) != "cd" or len(directory.arguments) != 1 or not _plain_value(directory.arguments[0]):
            return None
    else:
        return None
    name = _name(operation)
    args = operation.arguments
    if name == "git" and len(args) == 3 and args[:2] == ("apply", "--check") and _plain_value(args[2]):
        return "patch-check"
    if name == "git" and len(args) == 2 and args[0] == "apply" and _plain_value(args[1]):
        return "patch-apply"
    if name == "ruff" and len(args) == 2 and args[0] == "format" and _plain_value(args[1]):
        return "format-write"
    if name == "cp" and len(args) == 2 and all(_plain_value(value) for value in args):
        return "copy-generated"
    return None


def _symlink_write_through(command: CanonicalCommand) -> bool:
    if not _exact_command(command) or len(command.segments) != 2 or len(command.redirects) != 1:
        return False
    link, writer = command.segments
    if _name(link) != "ln" or link.arguments[:1] != ("-s",) or len(link.arguments) != 3:
        return False
    link_path = link.arguments[2].rstrip("/")
    redirect = command.redirects[0]
    return (
        _name(writer) in {"echo", "printf"}
        and redirect.operator in {">", ">>"}
        and _plain_value(link.arguments[1])
        and _plain_value(link_path)
        and _plain_value(redirect.target)
        and redirect.target.startswith(f"{link_path}/")
    )


def _plain_command(command: CanonicalCommand) -> bool:
    return _exact_command(command) and not command.redirects


def _exact_command(command: CanonicalCommand) -> bool:
    return bool(command.segments) and all(
        (
            command.confidence == "exact",
            command.uncertainty_reason is None,
            command.dialect == "posix",
            command.transport == "shell_string",
            not command.wrapper_chain,
            not command.embedded_commands,
            all(
                segment.execution_context.startswith("top:")
                and not segment.wrapper_chain
                and not segment.environment_names
                and not segment.path_overridden
                for segment in command.segments
            ),
        )
    )


def _name(segment: CommandSegment) -> str:
    return Path(segment.executable or "").name.lower()


def _plain_value(value: str) -> bool:
    return (
        bool(value)
        and not value.startswith("-")
        and not Path(value).is_absolute()
        and ".." not in Path(value).parts
        and not any(marker in value for marker in ("$", "`", "<", ">", "|", ";", "&", "\x00"))
    )


__all__ = (
    "WORKSPACE_WRITE_CANDIDATE_VERSION",
    "workspace_write_candidate_factors",
    "workspace_write_candidate_operation",
)
