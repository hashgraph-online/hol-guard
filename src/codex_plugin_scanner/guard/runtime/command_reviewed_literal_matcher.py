"""Rule-local evidence for a maintainer-reviewed, exact literal invocation.

This matcher does not approve a command. It can only lower its owning rule's
contribution to the existing evaluator. It deliberately excludes shell syntax,
wrappers, environment overrides, extra arguments, and uncertain parse boundaries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import final

from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand

_EXECUTABLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}")
_LITERAL_ARGUMENT = re.compile(
    r"(?:--?|--?[A-Za-z0-9][A-Za-z0-9_.-]*(?:=[A-Za-z0-9][A-Za-z0-9._:/@+-]*)?"
    r"|[A-Za-z0-9][A-Za-z0-9._:/@+-]*)"
)


def validate_reviewed_literal_argv(executable: str, arguments: tuple[str, ...]) -> str:
    """Validate a narrow literal grammar and return its one supported spelling."""
    if not isinstance(executable, str) or _EXECUTABLE.fullmatch(executable) is None:
        raise ValueError("Reviewed literal executable must be a bounded basename")
    if not isinstance(arguments, tuple) or not 1 <= len(arguments) <= 16:
        raise ValueError("Reviewed literal invocation needs one to sixteen argument tokens")
    if any(
        not isinstance(argument, str) or len(argument) > 64 or _LITERAL_ARGUMENT.fullmatch(argument) is None
        for argument in arguments
    ):
        raise ValueError("Reviewed literal arguments cannot contain shell syntax or expansions")
    expected = " ".join((executable, *arguments))
    if len(expected) > 120:
        raise ValueError("Reviewed literal invocation exceeds the command example limit")
    return expected


@final
@dataclass(frozen=True, slots=True)
class ReviewedLiteralCommandMatcher:
    executable: str
    arguments: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_reviewed_literal_argv(self.executable, self.arguments)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        expected = " ".join((self.executable, *self.arguments))
        if (
            command.dialect != "posix"
            or command.transport != "shell_string"
            or command.confidence != "exact"
            or command.raw_text != expected
            or command.normalized_text != expected
            or command.wrapper_chain
            or command.redirects
            or command.embedded_commands
            or command.path_overridden
            or len(command.segments) != 1
        ):
            return ()
        segment = command.segments[0]
        if (
            segment.executable != self.executable
            or segment.tokens != (self.executable, *self.arguments)
            or segment.arguments != self.arguments
            or segment.environment_names
            or segment.wrapper_chain
            or segment.path_overridden
            or segment.pipeline_index != 0
        ):
            return ()
        return (MatcherEvidence(0, self.executable, "Matched one explicitly reviewed literal invocation."),)
