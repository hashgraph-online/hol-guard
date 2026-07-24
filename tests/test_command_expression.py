from __future__ import annotations

from typing import Literal

import pytest

from codex_plugin_scanner.guard.runtime.command_expression import (
    CommandCondition,
    CommandExpression,
    CommandExpressionError,
    command_expression_from_mapping,
    matches_command_expression,
    validate_command_expression,
)


def _expression(combinator: Literal["all", "any"], *conditions: CommandCondition) -> CommandExpression:
    return CommandExpression(combinator=combinator, conditions=tuple(conditions))


def test_all_expression_requires_each_typed_condition() -> None:
    expression = _expression(
        "all",
        CommandCondition("command", "startsWith", "docker compose"),
        CommandCondition("command", "endsWith", "--detach"),
    )

    assert matches_command_expression(expression, "docker   compose up --detach")
    assert not matches_command_expression(expression, "docker compose up")


def test_any_expression_supports_exact_glob_and_case_flag() -> None:
    expression = _expression(
        "any",
        CommandCondition("command", "exact", "git push", case_sensitive=False),
        CommandCondition("command", "glob", "docker compose *"),
    )

    assert matches_command_expression(expression, "GIT PUSH")
    assert matches_command_expression(expression, "docker compose up --detach")
    assert not matches_command_expression(expression, "git commit -m ship")


def test_omitted_case_flag_preserves_case_insensitive_legacy_exact_matching() -> None:
    expression = command_expression_from_mapping(
        {
            "combinator": "all",
            "conditions": [{"field": "command", "operator": "exact", "value": "git push"}],
        }
    )

    assert matches_command_expression(expression, "GIT PUSH")


def test_regex_validation_and_matching_share_runtime_dialect() -> None:
    expression = _expression(
        "all",
        CommandCondition("command", "regex", r"^docker\s+compose\s+(up|down)$"),
    )

    validate_command_expression(expression)
    assert matches_command_expression(expression, "docker compose up")
    assert not matches_command_expression(expression, "docker compose logs")


def test_invalid_regex_is_rejected_before_evaluation() -> None:
    expression = _expression("all", CommandCondition("command", "regex", "[unclosed"))

    with pytest.raises(CommandExpressionError, match="invalid_command_regex"):
        validate_command_expression(expression)


def test_mapping_requires_explicit_boolean_combinator() -> None:
    with pytest.raises(CommandExpressionError, match="command_expression_combinator_required"):
        command_expression_from_mapping(
            {"conditions": [{"field": "command", "operator": "exact", "value": "git push"}]}
        )
