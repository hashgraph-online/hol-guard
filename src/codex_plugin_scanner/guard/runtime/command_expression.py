"""Portable command-pattern policy expressions for HOL Guard 3.0.

Expressions deliberately operate on normalized command text. These are carriers for
the shape the runtime hands back; they parse nothing and compile nothing.

The dialect belongs to the runtime. ``guard-command`` holds the one shape parser, the
one glob translation and the one regex engine, for authoring and for enforcement alike,
so a pattern cannot be accepted while a document is written and refused when a command
runs against it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypeAlias

CommandPatternOperator: TypeAlias = Literal["exact", "startsWith", "contains", "endsWith", "glob", "regex"]
CommandExpressionCombinator: TypeAlias = Literal["all", "any"]


class CommandExpressionError(ValueError):
    """Raised when an expression is outside the portable Guard dialect."""


@dataclass(frozen=True, slots=True)
class CommandCondition:
    field: Literal["command"]
    operator: CommandPatternOperator
    value: str
    case_sensitive: bool = False

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

    def to_mapping(self) -> dict[str, object]:
        return {
            "combinator": self.combinator,
            "conditions": [condition.to_mapping() for condition in self.conditions],
        }


__all__ = [
    "CommandCondition",
    "CommandExpression",
    "CommandExpressionCombinator",
    "CommandExpressionError",
    "CommandPatternOperator",
]
