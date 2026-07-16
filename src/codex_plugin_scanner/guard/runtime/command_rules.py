"""Reusable command rule and matcher contracts for Guard extensions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, final

from .command_matcher_contracts import CommandMatcher, MatcherEvidence
from .command_model import CanonicalCommand, CommandSegment

CommandRuleSeverity = Literal["critical", "high", "medium", "low"]
CommandRuleMode = Literal["required", "enforce", "review", "monitor", "disabled"]

_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
_VALID_MODES = frozenset({"required", "enforce", "review", "monitor", "disabled"})
_EMPTY_STRING_SET: frozenset[str] = frozenset()
_TRUTHY_FLAG_VALUES = frozenset({"1", "on", "true", "yes"})
_FALSEY_FLAG_VALUES = frozenset({"0", "false", "no", "off"})


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
    inverse_flag_pairs: frozenset[tuple[str, str]] = frozenset()
    required_option_values: tuple[tuple[str, frozenset[str]], ...] = ()
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
        normalized_inverse_pairs = frozenset(
            (positive.strip().lower(), negative.strip().lower())
            for positive, negative in self.inverse_flag_pairs
            if positive.strip() and negative.strip()
        )
        normalized_required_option_values = tuple(
            sorted(
                [
                    (
                        option.strip().lower(),
                        frozenset(value.strip().lower() for value in values if value.strip()),
                    )
                    for option, values in self.required_option_values
                    if option.strip()
                ],
                key=lambda item: item[0],
            )
        )
        object.__setattr__(self, "subcommands", normalized_subcommands)
        object.__setattr__(self, "required_flags", normalized_required_flags)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden_flags)
        object.__setattr__(self, "leading_options_with_values", normalized_leading_options)
        object.__setattr__(self, "interspersed_options_with_values", normalized_interspersed_options)
        object.__setattr__(self, "interspersed_flags", normalized_interspersed_flags)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "inverse_flag_pairs", normalized_inverse_pairs)
        object.__setattr__(self, "required_option_values", normalized_required_option_values)
        if normalized_required_flags & normalized_forbidden_flags:
            raise ValueError("A matcher flag cannot be both required and forbidden")
        inverse_names = [name for pair in normalized_inverse_pairs for name in pair]
        if len(inverse_names) != len(set(inverse_names)):
            raise ValueError("Inverse flag pairs cannot reuse an option name")
        required_option_names = [option for option, _values in normalized_required_option_values]
        if len(required_option_names) != len(set(required_option_names)):
            raise ValueError("Required option values cannot declare an option more than once")
        if any(not values for _option, values in normalized_required_option_values):
            raise ValueError("Required option values cannot be empty")

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
            semantics = _argument_semantics(
                flag_arguments,
                options_with_values=(
                    self.options_with_values | self.leading_options_with_values | self.interspersed_options_with_values
                ),
                inverse_flag_pairs=self.inverse_flag_pairs,
            )
            if not self.required_flags <= semantics.present_flags or self.forbidden_flags & semantics.present_flags:
                continue
            if any(
                semantics.option_value(option) not in allowed_values
                for option, allowed_values in self.required_option_values
            ):
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
            present_arguments = _argument_semantics(
                tuple(argument.lower() for argument in segment.arguments)
            ).present_flags
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
            keywords=frozenset(
                (*matcher.subcommands, *matcher.required_flags, *(name for name, _ in matcher.required_option_values))
            ),
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


@dataclass(frozen=True, slots=True)
class _EffectiveOption:
    name: str
    token: str
    value: str | None
    is_value_option: bool
    positive_flag: str | None = None
    negative_flag: str | None = None
    positive_polarity: bool = True


@dataclass(frozen=True, slots=True)
class _ArgumentSemantics:
    present_flags: frozenset[str]
    option_values: tuple[tuple[str, str | None], ...]

    def option_value(self, option: str) -> str | None:
        return next((value for name, value in self.option_values if name == option), None)


def _argument_semantics(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str] = _EMPTY_STRING_SET,
    inverse_flag_pairs: frozenset[tuple[str, str]] = frozenset(),
) -> _ArgumentSemantics:
    flags: set[str] = set()
    inverse_aliases = {
        alias: (positive, negative, alias == positive)
        for positive, negative in inverse_flag_pairs
        for alias in (positive, negative)
    }
    effective_options: dict[str, _EffectiveOption] = {}
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            break
        option_name, separator, option_value = argument.partition("=")
        is_long_option = argument.startswith("--")
        is_value_option = option_name in options_with_values
        inverse_alias = inverse_aliases.get(option_name)
        if is_long_option or inverse_alias is not None:
            if is_value_option and not separator:
                option_value = arguments[index + 1] if index + 1 < len(arguments) else ""
            effective_name = inverse_alias[0] if inverse_alias is not None else option_name
            effective_options[effective_name] = _EffectiveOption(
                name=effective_name,
                token=argument,
                value=option_value if separator or is_value_option else None,
                is_value_option=is_value_option,
                positive_flag=inverse_alias[0] if inverse_alias is not None else None,
                negative_flag=inverse_alias[1] if inverse_alias is not None else None,
                positive_polarity=inverse_alias[2] if inverse_alias is not None else True,
            )
        else:
            flags.add(argument)
            if argument.startswith("-") and separator:
                flags.add(option_name)
        if inverse_alias is None and option_name.startswith("-") and not option_name.startswith("--"):
            for character in option_name[1:]:
                if not character.isalnum():
                    continue
                short_flag = f"-{character}"
                short_alias = inverse_aliases.get(short_flag)
                if short_alias is None:
                    flags.add(short_flag)
                else:
                    effective_options[short_alias[0]] = _EffectiveOption(
                        name=short_alias[0],
                        token=short_flag,
                        value=None,
                        is_value_option=False,
                        positive_flag=short_alias[0],
                        negative_flag=short_alias[1],
                        positive_polarity=short_alias[2],
                    )
                if short_flag in options_with_values:
                    break
        index += 2 if option_name in options_with_values and "=" not in argument else 1
    for option in effective_options.values():
        flags.add(option.token)
        if option.positive_flag is not None and option.negative_flag is not None:
            assigned_value = _boolean_flag_value(option.value)
            if assigned_value is not None:
                enabled = assigned_value if option.positive_polarity else not assigned_value
                flags.add(option.positive_flag if enabled else option.negative_flag)
        elif option.is_value_option or option.value is None or option.value in _TRUTHY_FLAG_VALUES:
            flags.add(option.name)
    return _ArgumentSemantics(
        present_flags=frozenset(flags),
        option_values=tuple((name, option.value) for name, option in effective_options.items()),
    )


def _boolean_flag_value(value: str | None) -> bool | None:
    if value is None or value in _TRUTHY_FLAG_VALUES:
        return True
    if value in _FALSEY_FLAG_VALUES:
        return False
    return None


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
