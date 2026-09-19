"""Strict native literal-expression materialization; no source or runtime admission.

The existing canonical projection remains attached in full. Expression entries
have the same order as its rows, including generic and non-applicable rows.
A native consumer must apply those selectors and target dispositions itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .policy_command_projection import CanonicalCommandProjection
from .policy_document_types import PolicyCompilationError
from .runtime.command_expression import (
    MAX_COMMAND_CONDITIONS,
    MAX_COMMAND_PATTERN_LENGTH,
    MAX_NORMALIZED_COMMAND_LENGTH,
    CommandExpression,
    CommandExpressionError,
)

NATIVE_COMMAND_EXPRESSION_SCHEMA = "guard-native-command-expression.v1"
NATIVE_COMMAND_LITERAL_OPERATORS = frozenset({"exact", "startsWith", "contains", "endsWith"})
# Python str.isspace(), deliberately including the four information separators.
NATIVE_COMMAND_WHITESPACE_CODEPOINTS = (
    0x09,
    0x0A,
    0x0B,
    0x0C,
    0x0D,
    0x1C,
    0x1D,
    0x1E,
    0x1F,
    0x20,
    0x85,
    0xA0,
    0x1680,
    0x2000,
    0x2001,
    0x2002,
    0x2003,
    0x2004,
    0x2005,
    0x2006,
    0x2007,
    0x2008,
    0x2009,
    0x200A,
    0x2028,
    0x2029,
    0x202F,
    0x205F,
    0x3000,
)
_WHITESPACE = frozenset(NATIVE_COMMAND_WHITESPACE_CODEPOINTS)


def normalize_native_command_text(value: str) -> str:
    """Explicit shared normalization for the first native literal dialect.

    Lengths count Unicode scalar values, not UTF-8 bytes. Invalid Unicode cannot
    be represented by the native JSON consumer and is rejected, never repaired.
    """
    if not isinstance(value, str):
        raise CommandExpressionError("command_value_required")
    parts: list[str] = []
    pending_space = False
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise CommandExpressionError("command_unicode_invalid")
        if codepoint in _WHITESPACE:
            pending_space = bool(parts)
            continue
        if pending_space:
            parts.append(" ")
            pending_space = False
        parts.append(character)
        if len(parts) > MAX_NORMALIZED_COMMAND_LENGTH:
            raise CommandExpressionError("command_value_too_long")
    if not parts:
        raise CommandExpressionError("command_value_required")
    return "".join(parts)


def native_command_expression_payload(expression: CommandExpression, *, rule_id: str) -> str:
    """Serialize only the existing AST subset whose native semantics are fixed."""

    def reject(code: str) -> None:
        raise PolicyCompilationError(code, rule_id)

    if not isinstance(expression, CommandExpression):
        reject("native_command_expression_invalid")
    if expression.combinator not in {"all", "any"} or not 1 <= len(expression.conditions) <= MAX_COMMAND_CONDITIONS:
        reject("native_command_expression_invalid")
    for condition in expression.conditions:
        if condition.field != "command" or condition.operator not in NATIVE_COMMAND_LITERAL_OPERATORS:
            reject("native_command_operator_unsupported")
        if condition.case_sensitive is not True:
            reject("native_command_casefold_unsupported")
        try:
            normalized = normalize_native_command_text(condition.value)
        except CommandExpressionError as error:
            raise PolicyCompilationError("native_command_value_unsupported", rule_id) from error
        if normalized != condition.value or len(normalized) > MAX_COMMAND_PATTERN_LENGTH:
            reject("native_command_value_unsupported")
    # Keep the established all/any AST and exact field names; no new syntax.
    return json.dumps(expression.to_mapping(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class NativeCommandProjection:
    schema: str
    projection: CanonicalCommandProjection
    expression_payloads: tuple[str | None, ...]


def materialize_native_command_projection(projection: CanonicalCommandProjection) -> NativeCommandProjection:
    """Refuse the complete source when any active rule exceeds native support.

    Validation happens before returning any output and includes rules targeting
    a different device. No selector, lifetime, source identity or disposition is
    dropped. This does not authenticate the source or enable an enforcement lane.
    """
    payloads = tuple(
        native_command_expression_payload(row.expression, rule_id=row.identity.rule_id)
        if row.expression is not None
        else None
        for row in projection.rows
    )
    return NativeCommandProjection(NATIVE_COMMAND_EXPRESSION_SCHEMA, projection, payloads)
