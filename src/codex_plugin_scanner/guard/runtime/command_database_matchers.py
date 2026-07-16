"""Structured matchers for database command-line grammars."""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from .command_matcher_contracts import CommandMatcher, MatcherEvidence
from .command_model import CanonicalCommand, CommandSegment
from .command_structured_matchers import leading_flags_and_operands


@final
@dataclass(frozen=True, slots=True)
class ArgumentCommandMatcher:
    """Match a command-like argument and its payload without scanning free-form text."""

    executables: frozenset[str]
    command: str
    minimum_abbreviation_length: int
    minimum_position: int = 0

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_command = self.command.strip().lower()
        if not normalized_executables or not normalized_command:
            raise ValueError("ArgumentCommandMatcher requires executables and a command")
        if not 1 <= self.minimum_abbreviation_length <= len(normalized_command):
            raise ValueError("ArgumentCommandMatcher has an invalid minimum abbreviation length")
        if self.minimum_position < 0:
            raise ValueError("ArgumentCommandMatcher minimum position cannot be negative")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "command", normalized_command)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            for argument in segment.arguments[self.minimum_position :]:
                parts = argument.strip().lower().split(None, 1)
                if len(parts) != 2:
                    continue
                command_token = parts[0]
                if len(command_token) < self.minimum_abbreviation_length or not self.command.startswith(command_token):
                    continue
                evidence.append(
                    MatcherEvidence(
                        segment_index=index,
                        executable=segment.executable,
                        detail="Matched a structured command argument and required payload.",
                    )
                )
                break
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class CommandSequenceMatcher:
    """Match target commands in a documented multi-command grammar."""

    executables: frozenset[str]
    command_arities: tuple[tuple[str, int], ...]
    target_commands: frozenset[str]
    options_with_values: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_arities = tuple((name.strip().lower(), arity) for name, arity in self.command_arities)
        normalized_targets = frozenset(value.strip().lower() for value in self.target_commands if value.strip())
        normalized_options = frozenset(
            _normalize_option_token(value) for value in self.options_with_values if value.strip()
        )
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        command_names = tuple(name for name, _arity in normalized_arities)
        if not normalized_executables or not command_names or not normalized_targets:
            raise ValueError("CommandSequenceMatcher requires executables, commands, and targets")
        if len(set(command_names)) != len(command_names) or any(arity < 0 for _name, arity in normalized_arities):
            raise ValueError("CommandSequenceMatcher requires unique commands with non-negative arities")
        if not normalized_targets <= frozenset(command_names):
            raise ValueError("CommandSequenceMatcher targets must exist in the command grammar")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "command_arities", normalized_arities)
        object.__setattr__(self, "target_commands", normalized_targets)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        arities = dict(self.command_arities)
        command_names = tuple(arities)
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            if any(
                _normalize_option_token(argument.split("=", 1)[0]) in self.forbidden_flags
                for argument in segment.arguments
            ):
                continue
            _flags, operands = leading_flags_and_operands(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            operand_index = 0
            while operand_index < len(operands):
                token = operands[operand_index].strip().lower()
                candidates = tuple(name for name in command_names if name.startswith(token))
                if len(candidates) != 1:
                    break
                resolved_command = candidates[0]
                if resolved_command in self.target_commands:
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched a destructive command in a structured command sequence.",
                        )
                    )
                    break
                operand_index += 1 + arities[resolved_command]
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class LeadingSubcommandMatcher:
    """Match subcommands after case-sensitive leading option parsing."""

    executables: frozenset[str]
    subcommands: tuple[str, ...]
    options_with_values: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()
    required_flags_anywhere: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_subcommands = tuple(value.strip().lower() for value in self.subcommands if value.strip())
        normalized_options = frozenset(
            _normalize_option_token(value) for value in self.options_with_values if value.strip()
        )
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        normalized_required = frozenset(
            value.strip().lower() for value in self.required_flags_anywhere if value.strip()
        )
        if not normalized_executables or not normalized_subcommands:
            raise ValueError("LeadingSubcommandMatcher requires executables and subcommands")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "subcommands", normalized_subcommands)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)
        object.__setattr__(self, "required_flags_anywhere", normalized_required)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            leading_flags, operands = leading_flags_and_operands(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            lowered_operands = tuple(value.lower() for value in operands)
            if self.forbidden_flags & leading_flags or lowered_operands[: len(self.subcommands)] != self.subcommands:
                continue
            present_flags = _present_flags(tuple(argument.lower() for argument in segment.arguments))
            if not self.required_flags_anywhere <= present_flags:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched executable and leading-option-aware subcommands.",
                )
            )
        return tuple(evidence)


def database_matcher_index_hints(matcher: CommandMatcher) -> tuple[frozenset[str], frozenset[str]] | None:
    """Return conservative registry hints for database grammar matchers."""

    if isinstance(matcher, ArgumentCommandMatcher):
        return matcher.executables, frozenset({matcher.command})
    if isinstance(matcher, CommandSequenceMatcher):
        return matcher.executables, matcher.target_commands
    if isinstance(matcher, LeadingSubcommandMatcher):
        return matcher.executables, frozenset(matcher.subcommands)
    return None


def _segment_matches_executable(segment: CommandSegment, executables: frozenset[str]) -> bool:
    if segment.executable is None:
        return False
    executable = segment.executable.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return executable in executables


def _normalize_option_token(value: str) -> str:
    stripped = value.strip()
    return stripped.lower() if stripped.startswith("--") else stripped


def _present_flags(arguments: tuple[str, ...]) -> frozenset[str]:
    flags: set[str] = set(arguments)
    for argument in arguments:
        if argument.startswith("-") and "=" in argument:
            flags.add(argument.split("=", 1)[0])
        if argument.startswith("-") and not argument.startswith("--") and len(argument) > 2:
            flags.update(f"-{character}" for character in argument[1:] if character.isalnum())
    return frozenset(flags)
