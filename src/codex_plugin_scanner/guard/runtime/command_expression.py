"""Portable command-pattern policy expressions for HOL Guard 3.0.

Expressions deliberately operate on normalized command text. This module parses their
shape and bounds; it compiles nothing.

The dialect belongs to the runtime. ``guard-command`` holds the one glob translation and
the one regex engine, for authoring and for enforcement alike, so a pattern cannot be
accepted while a document is written and refused when a command runs against it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal, TypeAlias

CommandPatternOperator: TypeAlias = Literal["exact", "startsWith", "contains", "endsWith", "glob", "regex"]
CommandExpressionCombinator: TypeAlias = Literal["all", "any"]

MAX_COMMAND_PATTERN_LENGTH: Final = 512
MAX_COMMAND_CONDITIONS: Final = 64
MAX_NORMALIZED_COMMAND_LENGTH: Final = 4096
_COMMAND_PATTERN_OPERATORS: Final = frozenset({"exact", "startsWith", "contains", "endsWith", "glob", "regex"})
_COMMAND_EXPRESSION_COMBINATORS: Final = frozenset({"all", "any"})


class CommandExpressionError(ValueError):
    """Raised when an expression is outside the portable Guard dialect."""


def normalize_command_text(value: str) -> str:
    """Collapse command whitespace without modifying quoting or token spelling."""

    normalized = " ".join(value.strip().split())
    if not normalized:
        raise CommandExpressionError("command_value_required")
    if len(normalized) > MAX_NORMALIZED_COMMAND_LENGTH:
        raise CommandExpressionError("command_value_too_long")
    return normalized


@dataclass(frozen=True, slots=True)
class CommandCondition:
    field: Literal["command"]
    operator: CommandPatternOperator
    value: str
    case_sensitive: bool = False

    def __post_init__(self) -> None:
        if self.field != "command":
            raise CommandExpressionError("unsupported_command_condition_field")
        if self.operator not in _COMMAND_PATTERN_OPERATORS:
            raise CommandExpressionError("unsupported_command_pattern_operator")
        normalized_value = normalize_command_text(self.value)
        if len(normalized_value) > MAX_COMMAND_PATTERN_LENGTH:
            raise CommandExpressionError("command_pattern_too_long")
        object.__setattr__(self, "value", normalized_value)

    def to_mapping(self) -> dict[str, object]:
        return {
            "field": self.field,
            "operator": self.operator,
            "value": self.value,
            "caseSensitive": self.case_sensitive,
        }


@dataclass(frozen=True, slots=True)
class CommandExpression:
    combinator: CommandExpressionCombinator
    conditions: tuple[CommandCondition, ...]

    def __post_init__(self) -> None:
        if self.combinator not in _COMMAND_EXPRESSION_COMBINATORS:
            raise CommandExpressionError("unsupported_command_expression_combinator")
        if not self.conditions:
            raise CommandExpressionError("command_expression_conditions_required")
        if len(self.conditions) > MAX_COMMAND_CONDITIONS:
            raise CommandExpressionError("command_expression_conditions_limit")

    def to_mapping(self) -> dict[str, object]:
        return {
            "combinator": self.combinator,
            "conditions": [condition.to_mapping() for condition in self.conditions],
        }


def _command_operator(value: str) -> CommandPatternOperator:
    if value == "exact":
        return "exact"
    if value == "startsWith":
        return "startsWith"
    if value == "contains":
        return "contains"
    if value == "endsWith":
        return "endsWith"
    if value == "glob":
        return "glob"
    if value == "regex":
        return "regex"
    raise CommandExpressionError("unsupported_command_pattern_operator")


def _command_combinator(value: str) -> CommandExpressionCombinator:
    if value == "all":
        return "all"
    if value == "any":
        return "any"
    raise CommandExpressionError("unsupported_command_expression_combinator")


def command_expression_from_mapping(value: object) -> CommandExpression:
    if not isinstance(value, dict):
        raise CommandExpressionError("command_expression_must_be_object")
    combinator = value.get("combinator")
    conditions_value = value.get("conditions")
    if not isinstance(combinator, str):
        raise CommandExpressionError("command_expression_combinator_required")
    if not isinstance(conditions_value, list):
        raise CommandExpressionError("command_expression_conditions_required")
    conditions: list[CommandCondition] = []
    for condition_value in conditions_value:
        if not isinstance(condition_value, dict):
            raise CommandExpressionError("command_condition_must_be_object")
        field = condition_value.get("field")
        operator = condition_value.get("operator")
        raw_value = condition_value.get("value")
        case_sensitive = condition_value.get("caseSensitive", False)
        if field != "command":
            raise CommandExpressionError("unsupported_command_condition_field")
        if not isinstance(operator, str):
            raise CommandExpressionError("command_condition_operator_required")
        if not isinstance(raw_value, str):
            raise CommandExpressionError("command_condition_value_required")
        if not isinstance(case_sensitive, bool):
            raise CommandExpressionError("command_condition_case_sensitive_invalid")
        conditions.append(
            CommandCondition(
                field="command",
                operator=_command_operator(operator),
                value=raw_value,
                case_sensitive=case_sensitive,
            )
        )
    return CommandExpression(
        combinator=_command_combinator(combinator),
        conditions=tuple(conditions),
    )


__all__ = [
    "MAX_COMMAND_CONDITIONS",
    "MAX_COMMAND_PATTERN_LENGTH",
    "MAX_NORMALIZED_COMMAND_LENGTH",
    "CommandCondition",
    "CommandExpression",
    "CommandExpressionCombinator",
    "CommandExpressionError",
    "CommandPatternOperator",
    "command_expression_from_mapping",
    "normalize_command_text",
]
