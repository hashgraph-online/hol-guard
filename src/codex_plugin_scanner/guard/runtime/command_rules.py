"""Reusable command rule and matcher contracts for Guard extensions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, final

from .command_matcher_contracts import CommandMatcher, MatcherEvidence
from .command_model import CanonicalCommand, CommandSegment
from .command_option_parsing import (
    flags_present_in_all_option_parses,
    known_option_advance,
    matches_subcommands_conservatively,
)

CommandRuleSeverity = Literal["critical", "high", "medium", "low"]
CommandRuleMode = Literal["required", "enforce", "review", "monitor", "disabled"]

_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
_VALID_MODES = frozenset({"required", "enforce", "review", "monitor", "disabled"})
_EMPTY_STRING_SET: frozenset[str] = frozenset()
_TRUTHY_FLAG_VALUES = frozenset({"1", "on", "true", "yes"})


@final
@dataclass(frozen=True, slots=True)
class ExecutableMatcher:
    """Match executable names with optional subcommand and flag constraints."""

    executables: frozenset[str]
    subcommands: tuple[str, ...] = ()
    required_flags: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()
    allow_leading_options: bool = False
    leading_options_with_values: frozenset[str] = frozenset()
    interspersed_options_with_values: frozenset[str] = frozenset()
    interspersed_flags: frozenset[str] = frozenset()
    options_with_values: frozenset[str] = frozenset()
    required_flags_in_all_arguments: bool = False
    fail_secure_unknown_options: bool = False

    def __post_init__(self) -> None:
        normalized = frozenset(value.strip().lower() for value in self.executables if value.strip())
        if not normalized:
            raise ValueError("ExecutableMatcher requires at least one executable")
        object.__setattr__(self, "executables", normalized)
        normalized_subcommands = tuple(value.strip().lower() for value in self.subcommands if value.strip())
        normalized_required_flags = frozenset(value.strip().lower() for value in self.required_flags if value.strip())
        normalized_forbidden_flags = frozenset(value.strip().lower() for value in self.forbidden_flags if value.strip())
        normalized_leading_options = frozenset(
            value.strip().lower() for value in self.leading_options_with_values if value.strip()
        )
        normalized_interspersed_options = frozenset(
            value.strip().lower() for value in self.interspersed_options_with_values if value.strip()
        )
        normalized_interspersed_flags = frozenset(
            value.strip().lower() for value in self.interspersed_flags if value.strip()
        )
        normalized_options = frozenset(value.strip().lower() for value in self.options_with_values if value.strip())
        object.__setattr__(self, "subcommands", normalized_subcommands)
        object.__setattr__(self, "required_flags", normalized_required_flags)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden_flags)
        object.__setattr__(self, "leading_options_with_values", normalized_leading_options)
        object.__setattr__(self, "interspersed_options_with_values", normalized_interspersed_options)
        object.__setattr__(self, "interspersed_flags", normalized_interspersed_flags)
        object.__setattr__(self, "options_with_values", normalized_options)
        if normalized_required_flags & normalized_forbidden_flags:
            raise ValueError("A matcher flag cannot be both required and forbidden")

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            subcommand_arguments = _without_options(
                lowered_arguments,
                self.interspersed_options_with_values,
                self.interspersed_flags,
            )
            if self.allow_leading_options:
                subcommand_arguments = _after_leading_options(
                    subcommand_arguments,
                    self.leading_options_with_values,
                    self.interspersed_flags,
                )
            if (
                self.subcommands
                and subcommand_arguments[: len(self.subcommands)] != self.subcommands
                and (
                    not self.fail_secure_unknown_options
                    or not matches_subcommands_conservatively(
                        lowered_arguments,
                        self.subcommands,
                        options_with_values=(
                            self.options_with_values
                            | self.leading_options_with_values
                            | self.interspersed_options_with_values
                        ),
                        known_flags=self.interspersed_flags,
                    )
                )
            ):
                continue
            if self.required_flags_in_all_arguments:
                flag_arguments = lowered_arguments
            elif self.subcommands:
                flag_arguments = subcommand_arguments[len(self.subcommands) :]
            else:
                flag_arguments = subcommand_arguments
            present_flags = _present_flags(
                flag_arguments,
                options_with_values=(
                    self.options_with_values | self.leading_options_with_values | self.interspersed_options_with_values
                ),
            )
            required_flags_present = self.required_flags <= present_flags
            if self.fail_secure_unknown_options and self.required_flags_in_all_arguments:
                required_flags_present = flags_present_in_all_option_parses(
                    lowered_arguments,
                    self.required_flags,
                    options_with_values=(
                        self.options_with_values
                        | self.leading_options_with_values
                        | self.interspersed_options_with_values
                    ),
                    known_flags=self.interspersed_flags | self.required_flags | self.forbidden_flags,
                )
            if not required_flags_present or self.forbidden_flags & present_flags:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched executable and structured argument constraints.",
                )
            )
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class ArgumentMatcher:
    """Match executable arguments without interpreting free-form shell text."""

    executables: frozenset[str]
    required_arguments: frozenset[str]

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_arguments = frozenset(value.strip().lower() for value in self.required_arguments if value.strip())
        if not normalized_executables or not normalized_arguments:
            raise ValueError("ArgumentMatcher requires executables and arguments")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "required_arguments", normalized_arguments)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            present_arguments = _present_flags(tuple(argument.lower() for argument in segment.arguments))
            if not self.required_arguments <= present_arguments:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched executable and required structured arguments.",
                )
            )
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class PipelineMatcher:
    """Match an ordered producer-to-consumer pipeline."""

    producer: CommandMatcher
    consumer: CommandMatcher

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        producer_evidence = self.producer.match(command)
        consumer_evidence = self.consumer.match(command)
        for producer in producer_evidence:
            for consumer in consumer_evidence:
                producer_segment = command.segments[producer.segment_index]
                consumer_segment = command.segments[consumer.segment_index]
                if (
                    consumer.segment_index == producer.segment_index + 1
                    and consumer_segment.execution_context == producer_segment.execution_context
                    and consumer_segment.pipeline_index == producer_segment.pipeline_index + 1
                ):
                    return (producer, consumer)
        return ()


@final
@dataclass(frozen=True, slots=True)
class AnyMatcher:
    """Match when any child matcher emits evidence."""

    matchers: tuple[CommandMatcher, ...]

    def __post_init__(self) -> None:
        if not self.matchers:
            raise ValueError("AnyMatcher requires at least one child matcher")

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for matcher in self.matchers:
            evidence.extend(matcher.match(command))
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class AllMatcher:
    """Match only when every child matcher emits evidence."""

    matchers: tuple[CommandMatcher, ...]

    def __post_init__(self) -> None:
        if not self.matchers:
            raise ValueError("AllMatcher requires at least one child matcher")

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for matcher in self.matchers:
            child_evidence = matcher.match(command)
            if not child_evidence:
                return ()
            evidence.extend(child_evidence)
        return tuple(evidence)


@dataclass(frozen=True, slots=True)
class CommandSafetyRule:
    """Stable rule metadata owned by one command safety extension."""

    rule_id: str
    title: str
    description: str
    severity: CommandRuleSeverity
    risk_classes: tuple[str, ...]
    action_classes: tuple[str, ...]
    safer_alternatives: tuple[str, ...]
    default_mode: CommandRuleMode = "review"
    matcher: CommandMatcher | None = None
    safe_variants: tuple[CommandSafeVariant, ...] = ()
    compatibility_fallback: bool = False

    def __post_init__(self) -> None:
        if not self.rule_id.startswith("command.") or self.rule_id != self.rule_id.lower():
            raise ValueError("Command safety rule IDs must be lowercase and start with 'command.'")
        if not self.title.strip() or not self.description.strip():
            raise ValueError(f"Command safety rule {self.rule_id} requires a title and description")
        if self.severity not in _VALID_SEVERITIES:
            raise ValueError(f"Command safety rule {self.rule_id} has invalid severity")
        if self.default_mode not in _VALID_MODES:
            raise ValueError(f"Command safety rule {self.rule_id} has invalid default mode")
        for field_name, values in (
            ("risk classes", self.risk_classes),
            ("safer alternatives", self.safer_alternatives),
        ):
            if not values or len(set(values)) != len(values):
                raise ValueError(f"Command safety rule {self.rule_id} requires unique {field_name}")
        if not self.action_classes and self.matcher is None:
            raise ValueError(f"Command safety rule {self.rule_id} requires an action class or matcher")
        if len(set(self.action_classes)) != len(self.action_classes):
            raise ValueError(f"Command safety rule {self.rule_id} requires unique action classes")
        safe_variant_ids = [variant.variant_id for variant in self.safe_variants]
        if len(set(safe_variant_ids)) != len(safe_variant_ids):
            raise ValueError(f"Command safety rule {self.rule_id} has duplicate safe variant IDs")

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "risk_classes": list(self.risk_classes),
            "action_classes": list(self.action_classes),
            "safer_alternatives": list(self.safer_alternatives),
            "default_mode": self.default_mode,
            "matcher_kind": type(self.matcher).__name__ if self.matcher is not None else "compatibility",
            "safe_variants": [variant.to_dict() for variant in self.safe_variants],
            "compatibility_fallback": self.compatibility_fallback,
        }


@dataclass(frozen=True, slots=True)
class CommandSafeVariant:
    """A structured rule exception that cannot weaken unrelated matches."""

    variant_id: str
    title: str
    matcher: CommandMatcher

    def __post_init__(self) -> None:
        if not self.variant_id or self.variant_id != self.variant_id.strip().lower():
            raise ValueError("Safe variant IDs must be non-empty lowercase strings")
        if not self.title.strip():
            raise ValueError(f"Safe variant {self.variant_id} requires a title")

    def to_dict(self) -> dict[str, str]:
        return {
            "variant_id": self.variant_id,
            "title": self.title,
            "matcher_kind": type(self.matcher).__name__,
        }


@dataclass(frozen=True, slots=True)
class CommandRuleMatch:
    """Rule-level evidence emitted without making a policy decision."""

    rule: CommandSafetyRule
    action_class: str | None
    reason: str
    command: CanonicalCommand
    matcher_evidence: tuple[MatcherEvidence, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule.rule_id,
            "severity": self.rule.severity,
            "risk_classes": list(self.rule.risk_classes),
            "action_class": self.action_class,
            "reason": self.reason,
            "safer_alternatives": list(self.rule.safer_alternatives),
            "matcher_evidence": [item.to_dict() for item in self.matcher_evidence],
            "parse_confidence": self.command.confidence,
        }


@dataclass(frozen=True, slots=True)
class MatcherIndexHints:
    """Conservative registry hints that never replace matcher evaluation."""

    executables: frozenset[str] = frozenset()
    keywords: frozenset[str] = frozenset()
    complete: bool = True


def matcher_index_hints(matcher: CommandMatcher) -> MatcherIndexHints:
    """Return conservative executable and keyword hints for a trusted matcher."""

    if isinstance(matcher, ExecutableMatcher):
        return MatcherIndexHints(
            executables=matcher.executables,
            keywords=frozenset((*matcher.subcommands, *matcher.required_flags)),
        )
    if isinstance(matcher, ArgumentMatcher):
        return MatcherIndexHints(
            executables=matcher.executables,
            keywords=matcher.required_arguments,
        )
    from .command_database_matchers import database_matcher_index_hints
    from .command_structured_matchers import structured_matcher_index_hints

    database_hints = database_matcher_index_hints(matcher)
    if database_hints is not None:
        executables, keywords = database_hints
        return MatcherIndexHints(executables=executables, keywords=keywords)
    structured_hints = structured_matcher_index_hints(matcher)
    if structured_hints is not None:
        executables, keywords = structured_hints
        return MatcherIndexHints(executables=executables, keywords=keywords)
    if isinstance(matcher, PipelineMatcher):
        return _merge_matcher_hints((matcher.producer, matcher.consumer))
    if isinstance(matcher, (AnyMatcher, AllMatcher)):
        return _merge_matcher_hints(matcher.matchers)
    return MatcherIndexHints(complete=False)


def _merge_matcher_hints(matchers: tuple[CommandMatcher, ...]) -> MatcherIndexHints:
    child_hints = tuple(matcher_index_hints(matcher) for matcher in matchers)
    return MatcherIndexHints(
        executables=frozenset(value for hints in child_hints for value in hints.executables),
        keywords=frozenset(value for hints in child_hints for value in hints.keywords),
        complete=all(hints.complete for hints in child_hints),
    )


def _segment_matches_executable(segment: CommandSegment, executables: frozenset[str]) -> bool:
    if segment.executable is None:
        return False
    executable = segment.executable.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return executable in executables


def _normalize_option_token(value: str) -> str:
    stripped = value.strip()
    return stripped.lower() if stripped.startswith("--") else stripped


def _present_flags(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str] = _EMPTY_STRING_SET,
) -> frozenset[str]:
    flags: set[str] = set()
    # Safe variants honor the final long-option assignment, matching common CLI parsers.
    effective_long_options: dict[str, tuple[str, str | None, bool]] = {}
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            break
        option_name, separator, option_value = argument.partition("=")
        is_long_option = argument.startswith("--")
        is_value_option = option_name in options_with_values
        if is_long_option:
            if is_value_option and not separator:
                option_value = arguments[index + 1] if index + 1 < len(arguments) else ""
            effective_long_options[option_name] = (
                argument,
                option_value if separator or is_value_option else None,
                is_value_option,
            )
        else:
            flags.add(argument)
            if argument.startswith("-") and separator:
                flags.add(option_name)
        if option_name.startswith("-") and not option_name.startswith("--") and len(option_name) > 2:
            for character in option_name[1:]:
                if not character.isalnum():
                    continue
                short_flag = f"-{character}"
                flags.add(short_flag)
                if short_flag in options_with_values:
                    break
        index += 2 if option_name in options_with_values and "=" not in argument else 1
    for option_name, (argument, option_value, is_value_option) in effective_long_options.items():
        flags.add(argument)
        if is_value_option or option_value is None or option_value in _TRUTHY_FLAG_VALUES:
            flags.add(option_name)
    return frozenset(flags)


def _after_leading_options(
    arguments: tuple[str, ...],
    options_with_values: frozenset[str],
    flags: frozenset[str],
) -> tuple[str, ...]:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            return arguments[index + 1 :]
        if not argument.startswith("-"):
            return arguments[index:]
        advance = known_option_advance(
            argument,
            options_with_values=options_with_values,
            known_flags=flags,
        )
        index += advance if advance is not None else 1
    return ()


def _without_options(
    arguments: tuple[str, ...],
    options_with_values: frozenset[str],
    flags: frozenset[str],
) -> tuple[str, ...]:
    if not options_with_values and not flags:
        return arguments
    retained: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            retained.extend(arguments[index + 1 :])
            break
        advance = known_option_advance(
            argument,
            options_with_values=options_with_values,
            known_flags=flags,
        )
        if advance is None:
            retained.append(argument)
            index += 1
            continue
        index += advance
    return tuple(retained)
