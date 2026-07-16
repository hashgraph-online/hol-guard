"""Structured matchers for option-heavy command-line interfaces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from .command_matcher_contracts import CommandMatcher, MatcherEvidence
from .command_model import CanonicalCommand, CommandSegment


@final
@dataclass(frozen=True, slots=True)
class LeadingOperandCountMatcher:
    """Match commands with enough operands after documented leading options."""

    executables: frozenset[str]
    minimum_operands: int
    options_with_values: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_options = frozenset(
            _normalize_option_token(value) for value in self.options_with_values if value.strip()
        )
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        if not normalized_executables:
            raise ValueError("LeadingOperandCountMatcher requires executables")
        if self.minimum_operands < 1:
            raise ValueError("LeadingOperandCountMatcher requires at least one operand")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            leading_flags, operands = leading_flags_and_operands(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if self.forbidden_flags & leading_flags or len(operands) < self.minimum_operands:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail=f"Matched command with at least {self.minimum_operands} structured operands.",
                )
            )
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class OptionValueKeyMatcher:
    """Match documented option values whose leading key has execution semantics."""

    executables: frozenset[str]
    option_names: frozenset[str]
    value_keys: frozenset[str]
    forbidden_flags: frozenset[str] = frozenset()
    ignored_values: frozenset[str] = frozenset()
    required_key_values: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_options = frozenset(value.strip() for value in self.option_names if value.strip())
        normalized_keys = frozenset(value.strip().lower() for value in self.value_keys if value.strip())
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        normalized_ignored = frozenset(value.strip().lower() for value in self.ignored_values if value.strip())
        normalized_required = tuple(
            (key.strip().lower(), value.strip().lower())
            for key, value in self.required_key_values
            if key.strip() and value.strip()
        )
        if not normalized_executables or not normalized_options or not normalized_keys:
            raise ValueError("OptionValueKeyMatcher requires executables, option names, and value keys")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "option_names", normalized_options)
        object.__setattr__(self, "value_keys", normalized_keys)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)
        object.__setattr__(self, "ignored_values", normalized_ignored)
        object.__setattr__(self, "required_key_values", normalized_required)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            matched_flags = present_flags(segment.arguments, options_with_values=self.option_names)
            if self.forbidden_flags & matched_flags:
                continue
            settings: dict[str, str] = {}
            for option_value in _option_values(segment.arguments, self.option_names):
                key, value = _split_option_setting(option_value)
                if key:
                    settings.setdefault(key, value)
            if any(settings.get(key) != value for key, value in self.required_key_values):
                continue
            for key in self.value_keys:
                value = settings.get(key)
                if value is None or value in self.ignored_values:
                    continue
                evidence.append(
                    MatcherEvidence(
                        segment_index=index,
                        executable=segment.executable,
                        detail="Matched a structured option value with command execution semantics.",
                    )
                )
                break
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class EnvironmentNameMatcher:
    """Match command-local environment names without retaining their values."""

    executables: frozenset[str]
    environment_names: frozenset[str]

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_names = frozenset(value.strip().upper() for value in self.environment_names if value.strip())
        if not normalized_executables or not normalized_names:
            raise ValueError("EnvironmentNameMatcher requires executables and environment names")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "environment_names", normalized_names)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            present_names = frozenset(name.upper() for name in segment.environment_names)
            if not self.environment_names & present_names:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched a command-selecting environment name.",
                )
            )
        return tuple(evidence)


def structured_matcher_index_hints(matcher: CommandMatcher) -> tuple[frozenset[str], frozenset[str]] | None:
    """Return conservative registry hints for matchers in this module."""

    if isinstance(matcher, LeadingOperandCountMatcher):
        return matcher.executables, frozenset()
    if isinstance(matcher, OptionValueKeyMatcher):
        return matcher.executables, matcher.option_names
    if isinstance(matcher, EnvironmentNameMatcher):
        return matcher.executables, matcher.environment_names
    return None


def _segment_matches_executable(segment: CommandSegment, executables: frozenset[str]) -> bool:
    if segment.executable is None:
        return False
    executable = segment.executable.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return executable in executables


def leading_flags_and_operands(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
) -> tuple[frozenset[str], tuple[str, ...]]:
    flags: set[str] = set()
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            index += 1
            break
        if not argument.startswith("-") or argument == "-":
            break
        option_name = _normalize_option_token(argument.split("=", 1)[0])
        flags.add(option_name)
        short_option = argument[:2] if argument.startswith("-") and not argument.startswith("--") else option_name
        clustered_value_option: str | None = None
        clustered_value_attached = False
        if argument.startswith("-") and not argument.startswith("--") and len(argument) > 2:
            for offset, character in enumerate(argument[1:], start=1):
                if not character.isalnum():
                    break
                clustered_flag = f"-{character}"
                flags.add(clustered_flag)
                if clustered_flag in options_with_values:
                    clustered_value_option = clustered_flag
                    clustered_value_attached = offset < len(argument) - 1
                    break
        takes_value = (
            option_name in options_with_values
            or short_option in options_with_values
            or clustered_value_option is not None
        )
        has_attached_value = (
            "=" in argument
            or (
                argument.startswith("-")
                and not argument.startswith("--")
                and short_option in options_with_values
                and len(argument) > 2
            )
            or clustered_value_attached
        )
        if takes_value and not has_attached_value:
            index += 1
        index += 1
    return frozenset(flags), arguments[index:]


def _option_values(arguments: tuple[str, ...], option_names: frozenset[str]) -> tuple[str, ...]:
    values: list[str] = []
    ordered_options = sorted(option_names, key=len, reverse=True)
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        matched_option = next(
            (
                option
                for option in ordered_options
                if argument == option or argument.startswith(f"{option}=") or argument.startswith(option)
            ),
            None,
        )
        if matched_option is None:
            index += 1
            continue
        if argument == matched_option:
            if index + 1 < len(arguments):
                values.append(arguments[index + 1])
                index += 2
                continue
        elif argument.startswith(f"{matched_option}="):
            values.append(argument[len(matched_option) + 1 :])
        elif matched_option.startswith("-") and not matched_option.startswith("--"):
            values.append(argument[len(matched_option) :])
        index += 1
    return tuple(values)


def _normalize_option_token(value: str) -> str:
    stripped = value.strip()
    return stripped.lower() if stripped.startswith("--") else stripped


def _split_option_setting(value: str) -> tuple[str, str]:
    normalized = value.strip()
    if not normalized:
        return "", ""
    if "=" in normalized:
        key, setting = normalized.split("=", 1)
    else:
        parts = normalized.split(None, 1)
        key, setting = parts[0], parts[1] if len(parts) == 2 else ""
    return key.lower(), setting.strip().lower()


def present_flags(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
) -> frozenset[str]:
    flags: set[str] = set()
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            break
        flags.add(argument)
        if argument.startswith("-") and "=" in argument:
            flags.add(argument.split("=", 1)[0])
        if argument.startswith("-") and not argument.startswith("--") and len(argument) > 2:
            for character in argument[1:]:
                if not character.isalnum():
                    continue
                short_flag = f"-{character}"
                flags.add(short_flag)
                if short_flag in options_with_values:
                    break
        option_name = argument.split("=", 1)[0]
        index += 2 if option_name in options_with_values and "=" not in argument else 1
    return frozenset(flags)
