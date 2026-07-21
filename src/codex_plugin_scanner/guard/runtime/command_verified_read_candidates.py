"""Conservative syntax candidates for execution-bound verified reads."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from .command_model import CanonicalCommand, CommandSegment
from .effect_contract import DecisionBasis
from .effect_decision import DecisionFactor, DecisionFactorSource
from .github_command_capabilities import classify_github_cli

VERIFIED_READ_CANDIDATE_VERSION: Final = "guard.verified-read-candidate.v1"
_COUNT = re.compile(r"(?:-[0-9]{1,6}|--(?:lines|bytes)=[0-9]{1,6})")
_SED_RANGE = re.compile(r"[0-9]{1,6}(?:,[0-9]{1,6})?p")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_LOCAL_EXECUTABLES = frozenset({"fd", "git", "head", "ls", "pwd", "rg", "sed", "tail"})


def verified_read_candidate_factor(command: CanonicalCommand) -> DecisionFactor | None:
    """Require review for read-looking syntax until an owned executor proves it."""

    operation = verified_read_candidate_operation(command)
    if operation is None:
        return None
    return DecisionFactor(
        source=DecisionFactorSource.POLICY,
        reason_code="verified-read-proof-required",
        basis=DecisionBasis("review", None),
        operation_ref=f"operation:{operation}",
        producer_ref="policy:verified-read-candidate-v1",
    )


def verified_read_candidate_operation(command: CanonicalCommand) -> str | None:
    """Return a stable operation only for the reviewed, proof-eligible grammar."""

    if not _plain_exact_command(command):
        return None
    segments = command.segments
    offset = 0
    if segments[0].executable == "cd":
        if len(segments[0].arguments) != 1 or not _plain_target(segments[0].arguments[0]):
            return None
        offset = 1
    if offset == len(segments):
        return None
    executable_names = tuple(_name(segment) for segment in segments[offset:])
    if executable_names == ("gh",):
        return _github_operation(segments[offset])
    if any(name not in _LOCAL_EXECUTABLES for name in executable_names):
        return None
    if not all(_local_segment_is_candidate(segment) for segment in segments[offset:]):
        return None
    if len(segments[offset:]) > 1 and not _bounded_pipeline(segments[offset:]):
        return None
    return "workspace-read"


def _plain_exact_command(command: CanonicalCommand) -> bool:
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


def _local_segment_is_candidate(segment: CommandSegment) -> bool:
    name = _name(segment)
    args = segment.arguments
    if name == "pwd":
        return not args
    if name == "ls":
        return all(arg.startswith("-") or _plain_target(arg) for arg in args)
    if name in {"head", "tail"}:
        return bool(args) and all(_COUNT.fullmatch(arg) is not None or _plain_target(arg) for arg in args)
    if name == "sed":
        return (
            len(args) >= 3
            and args[0] == "-n"
            and _SED_RANGE.fullmatch(args[1]) is not None
            and all(_plain_target(arg) for arg in args[2:])
        )
    if name == "fd":
        return _fd_candidate(args)
    if name == "rg":
        return _rg_candidate(args)
    if name == "git":
        return _git_candidate(args)
    return False


def _fd_candidate(args: tuple[str, ...]) -> bool:
    if len(args) < 2 or any(arg in {"-x", "-X", "--exec", "--exec-batch", "-L", "--follow"} for arg in args):
        return False
    return all(not _dynamic(arg) for arg in args) and any(_plain_target(arg) for arg in args)


def _rg_candidate(args: tuple[str, ...]) -> bool:
    if not args or any(
        arg in {"--hidden", "--follow", "-L", "--pre", "--pre-glob", "--files-with-matches"} or arg.startswith("--pre=")
        for arg in args
    ):
        return False
    positional = tuple(arg for arg in args if not arg.startswith("-"))
    targets = positional[1:]
    return (
        bool(positional)
        and bool(targets)
        and all(not _dynamic(arg) for arg in args)
        and all(_source_target(arg) for arg in targets)
    )


def _git_candidate(args: tuple[str, ...]) -> bool:
    return args in {
        ("rev-parse", "--show-toplevel"),
        ("status", "--short"),
        ("diff", "--check"),
        ("log", "-5", "--oneline"),
        ("show", "--stat", "--oneline", "HEAD"),
        ("branch", "--show-current"),
    }


def _bounded_pipeline(segments: tuple[CommandSegment, ...]) -> bool:
    if len(segments) != 2 or segments[0].pipeline_index != 0 or segments[1].pipeline_index != 1:
        return False
    return _name(segments[0]) in {"fd", "rg"} and _name(segments[1]) in {"head", "tail"}


def _github_operation(segment: CommandSegment) -> str | None:
    assessment = classify_github_cli(segment.arguments)
    if assessment.capability != "read_remote" or assessment.capabilities != ("read_remote",):
        return None
    args = segment.arguments
    if len(args) < 5 or args[:2] not in {("pr", "view"), ("pr", "checks")}:
        return None
    try:
        repository_index = args.index("--repo")
    except ValueError:
        return None
    if repository_index + 1 >= len(args) or _REPOSITORY.fullmatch(args[repository_index + 1]) is None:
        return None
    if not args[2].isdigit() or any(_dynamic(arg) for arg in args):
        return None
    return "github-pull-request-read"


def _name(segment: CommandSegment) -> str:
    return Path(segment.executable or "").name.lower()


def _plain_target(value: str) -> bool:
    return bool(value) and not value.startswith("-") and not _dynamic(value)


def _source_target(value: str) -> bool:
    normalized = value.replace("\\", "/").removeprefix("./")
    return _plain_target(value) and normalized.split("/", 1)[0] in {"src", "tests"}


def _dynamic(value: str) -> bool:
    return any(marker in value for marker in ("$", "`", "<", ">", "|", ";", "&", "\x00"))


__all__ = (
    "VERIFIED_READ_CANDIDATE_VERSION",
    "verified_read_candidate_factor",
    "verified_read_candidate_operation",
)
