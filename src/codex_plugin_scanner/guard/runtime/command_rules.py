"""Reusable command rule and matcher contracts for Guard extensions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, final

from .command_model import CanonicalCommand, CommandSegment

CommandRuleSeverity = Literal["critical", "high", "medium", "low"]
CommandRuleMode = Literal["required", "enforce", "review", "monitor", "disabled"]

_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
_VALID_MODES = frozenset({"required", "enforce", "review", "monitor", "disabled"})


@dataclass(frozen=True, slots=True)
class MatcherEvidence:
    """Redaction-safe location emitted by one structured matcher."""

    segment_index: int
    executable: str | None
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "segment_index": self.segment_index,
            "executable": self.executable,
            "detail": self.detail,
        }


class CommandMatcher(Protocol):
    """Side-effect-free structured command matcher."""

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]: ...


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
        object.__setattr__(self, "subcommands", normalized_subcommands)
        object.__setattr__(self, "required_flags", normalized_required_flags)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden_flags)
        object.__setattr__(self, "leading_options_with_values", normalized_leading_options)
        if normalized_required_flags & normalized_forbidden_flags:
            raise ValueError("A matcher flag cannot be both required and forbidden")

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            subcommand_arguments = (
                _after_leading_options(lowered_arguments, self.leading_options_with_values)
                if self.allow_leading_options
                else lowered_arguments
            )
            if self.subcommands and subcommand_arguments[: len(self.subcommands)] != self.subcommands:
                continue
            present_flags = _present_flags(lowered_arguments)
            if not self.required_flags <= present_flags or self.forbidden_flags & present_flags:
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


def _segment_matches_executable(segment: CommandSegment, executables: frozenset[str]) -> bool:
    if segment.executable is None:
        return False
    executable = segment.executable.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return executable in executables


def _present_flags(arguments: tuple[str, ...]) -> frozenset[str]:
    flags: set[str] = set()
    for argument in arguments:
        flags.add(argument)
        if argument.startswith("-") and "=" in argument:
            flags.add(argument.split("=", 1)[0])
        if argument.startswith("-") and not argument.startswith("--") and len(argument) > 2:
            flags.update(f"-{character}" for character in argument[1:] if character.isalpha())
    return frozenset(flags)


def _after_leading_options(arguments: tuple[str, ...], options_with_values: frozenset[str]) -> tuple[str, ...]:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            return arguments[index + 1 :]
        if not argument.startswith("-"):
            return arguments[index:]
        option_name = argument.split("=", 1)[0]
        if option_name in options_with_values and "=" not in argument:
            index += 2
        else:
            index += 1
    return ()
