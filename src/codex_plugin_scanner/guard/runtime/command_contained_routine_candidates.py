"""Conservative syntax candidates for execution-bound routine containment."""

from __future__ import annotations

from pathlib import Path
from typing import Final

from .command_model import CanonicalCommand, CommandSegment
from .effect_contract import DecisionBasis
from .effect_decision import DecisionFactor, DecisionFactorSource

CONTAINED_ROUTINE_CANDIDATE_VERSION: Final = "guard.contained-routine-candidate.v1"


def contained_routine_candidate_factor(command: CanonicalCommand) -> DecisionFactor | None:
    """Require review until Guard itself executes the exact contained operation."""

    operation = contained_routine_candidate_operation(command)
    if operation is None:
        return None
    return DecisionFactor(
        source=DecisionFactorSource.POLICY,
        reason_code="contained-routine-proof-required",
        basis=DecisionBasis("review", None),
        operation_ref=f"operation:{operation}",
        producer_ref="policy:contained-routine-candidate-v1",
    )


def contained_routine_candidate_operation(command: CanonicalCommand) -> str | None:
    """Return the reviewed operation for the frozen routine-command grammar."""

    if not _plain_command(command) or len(command.segments) < 2:
        return None
    directory, *segments = command.segments
    if _name(directory) != "cd" or len(directory.arguments) != 1 or not _plain_value(directory.arguments[0]):
        return None
    signature = tuple((_name(segment), segment.arguments) for segment in segments)
    if signature == (("pytest", ("-q", "tests/test_guard_runtime.py")),):
        return "test"
    if signature == (("ruff", ("check", "src", "tests")),):
        return "lint"
    if signature == (("bun", ("run", "build")),):
        return "build"
    if signature in {
        (("bun", ("run", "typecheck", "2>&1")), ("head", ("-40",))),
        (("npx", ("tsc", "--noEmit", "--pretty", "2>&1")), ("head", ("-40",))),
    }:
        return "typecheck"
    if signature == (("find", ("src", "-name", "*.py", "-exec", "python", "-m", "py_compile", "{}", "+")),):
        return "compile-check"
    if signature in {
        (("cargo", ("tree", "--depth", "2")),),
        (("bun", ("pm", "ls", "--all")),),
        (("uv", ("tree", "--depth", "2")),),
    }:
        return "dependency-tree"
    if signature in {
        (("rg", ("-n", "error", "logs")), ("head", ("-40",))),
        (("git", ("status", "--porcelain=v1")), ("wc", ("-l",))),
    }:
        return "workspace-check"
    return None


def _plain_command(command: CanonicalCommand) -> bool:
    return bool(command.segments) and all(
        (
            command.confidence == "exact",
            command.uncertainty_reason is None,
            command.dialect == "posix",
            command.transport == "shell_string",
            not command.wrapper_chain,
            not command.redirects,
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
        and not any(marker in value for marker in ("$", "`", "<", ">", "|", ";", "&", "\x00"))
    )


__all__ = (
    "CONTAINED_ROUTINE_CANDIDATE_VERSION",
    "contained_routine_candidate_factor",
    "contained_routine_candidate_operation",
)
