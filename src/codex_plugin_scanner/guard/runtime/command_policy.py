"""Compile policy-document command expressions into runtime command decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from ..models import GuardAction
from ..policy_document import GuardPolicyDocument
from .command_expression import CommandExpression, matches_command_expression

_POLICY_ACTIONS: Final = frozenset({"allow", "warn", "review", "block"})
_ACTION_PRECEDENCE: Final = {"allow": 0, "warn": 1, "review": 2, "block": 3}


def _policy_action(effect: str) -> GuardAction:
    if effect == "allow":
        return "allow"
    if effect == "warn":
        return "warn"
    if effect == "review":
        return "review"
    if effect == "block":
        return "block"
    raise ValueError(f"unsupported_command_policy_effect:{effect}")


@dataclass(frozen=True, slots=True)
class CommandPolicyRule:
    """One enforceable command expression projected from a policy document rule."""

    rule_id: str
    action: GuardAction
    expression: CommandExpression


@dataclass(frozen=True, slots=True)
class CommandPolicyEvaluation:
    """The strongest policy action and all rule ids that produced it."""

    action: GuardAction
    matching_rule_ids: tuple[str, ...]


def compile_command_policy_rules(document: GuardPolicyDocument) -> tuple[CommandPolicyRule, ...]:
    """Return every enabled document rule that has a typed command expression."""

    rules: list[CommandPolicyRule] = []
    for rule in document.rules:
        expression = rule.match.command_expression
        if not rule.enabled or expression is None:
            continue
        action = _policy_action(rule.effect)
        rules.append(
            CommandPolicyRule(
                rule_id=rule.id,
                action=action,
                expression=expression,
            )
        )
    return tuple(rules)


def evaluate_command_policy_rules(rules: tuple[CommandPolicyRule, ...], command: str) -> CommandPolicyEvaluation:
    """Apply all matching rules and choose the strictest effective Guard action."""

    matches = tuple(rule for rule in rules if matches_command_expression(rule.expression, command))
    if not matches:
        return CommandPolicyEvaluation(action="allow", matching_rule_ids=())
    action = max(matches, key=lambda rule: _ACTION_PRECEDENCE[rule.action]).action
    return CommandPolicyEvaluation(
        action=action,
        matching_rule_ids=tuple(rule.rule_id for rule in matches),
    )


__all__ = [
    "CommandPolicyEvaluation",
    "CommandPolicyRule",
    "compile_command_policy_rules",
    "evaluate_command_policy_rules",
]
