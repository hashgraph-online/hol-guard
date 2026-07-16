"""Reusable command rule and matcher contracts for Guard extensions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, final

from .command_model import CanonicalCommand, CommandSegment

CommandRuleSeverity = Literal["critical", "high", "medium", "low"]
CommandRuleMode = Literal["required", "enforce", "review", "monitor", "disabled"]

_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
_VALID_MODES = frozenset({"required", "enforce", "review", "monitor", "disabled"})
_EMPTY_STRING_SET: frozenset[str] = frozenset()


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
    interspersed_options_with_values: frozenset[str] = frozenset()
    interspersed_flags: frozenset[str] = frozenset()
    options_with_values: frozenset[str] = frozenset()
    required_flags_in_all_arguments: bool = False

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
                )
            if self.subcommands and subcommand_arguments[: len(self.subcommands)] != self.subcommands:
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
class ArgumentPositionMatcher:
    """Match an exact argument at one of a bounded set of positions."""

    executables: frozenset[str]
    required_argument: str
    positions: frozenset[int]
    forbidden_arguments: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_required = self.required_argument.strip().lower()
        normalized_forbidden = frozenset(value.strip().lower() for value in self.forbidden_arguments if value.strip())
        if not normalized_executables or not normalized_required or not self.positions:
            raise ValueError("ArgumentPositionMatcher requires executables, an argument, and positions")
        if any(position < 0 for position in self.positions):
            raise ValueError("ArgumentPositionMatcher positions cannot be negative")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "required_argument", normalized_required)
        object.__setattr__(self, "forbidden_arguments", normalized_forbidden)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            arguments = tuple(argument.lower() for argument in segment.arguments)
            if self.forbidden_arguments & frozenset(arguments):
                continue
            if not any(
                position < len(arguments) and arguments[position] == self.required_argument
                for position in self.positions
            ):
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched an exact structured argument position.",
                )
            )
        return tuple(evidence)


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
                if (
                    len(command_token) < self.minimum_abbreviation_length
                    or not self.command.startswith(command_token)
                ):
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
            _flags, operands = _leading_flags_and_operands(
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
            leading_flags, operands = _leading_flags_and_operands(
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
            leading_flags, operands = _leading_flags_and_operands(
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
    if isinstance(matcher, ArgumentCommandMatcher):
        return MatcherIndexHints(
            executables=matcher.executables,
            keywords=frozenset({matcher.command}),
        )
    if isinstance(matcher, ArgumentPositionMatcher):
        return MatcherIndexHints(
            executables=matcher.executables,
            keywords=frozenset({matcher.required_argument}),
        )
    if isinstance(matcher, CommandSequenceMatcher):
        return MatcherIndexHints(executables=matcher.executables, keywords=matcher.target_commands)
    if isinstance(matcher, LeadingOperandCountMatcher):
        return MatcherIndexHints(executables=matcher.executables)
    if isinstance(matcher, LeadingSubcommandMatcher):
        return MatcherIndexHints(executables=matcher.executables, keywords=frozenset(matcher.subcommands))
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


def _leading_flags_and_operands(
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
        if argument.startswith("-") and not argument.startswith("--") and len(argument) > 2:
            for character in argument[1:]:
                if not character.isalpha():
                    break
                clustered_flag = f"-{character}"
                flags.add(clustered_flag)
                if clustered_flag in options_with_values:
                    break
        takes_value = option_name in options_with_values or short_option in options_with_values
        has_attached_value = "=" in argument or (
            argument.startswith("-")
            and not argument.startswith("--")
            and short_option in options_with_values
            and len(argument) > 2
        )
        if takes_value and not has_attached_value:
            index += 1
        index += 1
    return frozenset(flags), arguments[index:]


def _normalize_option_token(value: str) -> str:
    stripped = value.strip()
    return stripped.lower() if stripped.startswith("--") else stripped


def _present_flags(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str] = _EMPTY_STRING_SET,
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
                if not character.isalpha():
                    continue
                short_flag = f"-{character}"
                flags.add(short_flag)
                if short_flag in options_with_values:
                    break
        option_name = argument.split("=", 1)[0]
        index += 2 if option_name in options_with_values and "=" not in argument else 1
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
        option_name = argument.split("=", 1)[0]
        attached_short_option = (
            argument[:2]
            if len(argument) > 2 and argument[0] == "-" and argument[1] != "-" and argument[:2] in options_with_values
            else None
        )
        if option_name in flags:
            index += 1
            continue
        if option_name not in options_with_values and attached_short_option is None:
            retained.append(argument)
            index += 1
            continue
        is_attached_short = attached_short_option is not None and option_name not in options_with_values
        index += 1 if "=" in argument or is_attached_short else 2
    return tuple(retained)
