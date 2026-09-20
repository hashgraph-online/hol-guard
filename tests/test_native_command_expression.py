"""Shared literal vectors and complete-source native admission boundaries."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_command_expression import (
    NATIVE_COMMAND_EXPRESSION_SCHEMA,
    NATIVE_COMMAND_WHITESPACE_CODEPOINTS,
    materialize_native_command_projection,
    native_command_expression_payload,
    normalize_native_command_text,
)
from codex_plugin_scanner.guard.policy_command_projection import (
    CanonicalCommandProjection,
    project_canonical_command_policy,
)
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml
from codex_plugin_scanner.guard.policy_publication_binding import PolicyPublicationBinding
from codex_plugin_scanner.guard.runtime.command_expression import (
    CommandCondition,
    CommandExpressionError,
    command_expression_from_mapping,
    matches_command_expression,
    normalize_command_text,
)

VECTOR_PATH = Path(__file__).parents[1] / "spec/guard-policy/v1alpha1/native-command-expression-vectors.json"
VECTORS: dict[str, Any] = json.loads(VECTOR_PATH.read_text())
TARGET = "22222222-2222-4222-8222-222222222222"
WORKSPACE = "11111111-1111-4111-8111-111111111111"


def expression(operator: str = "exact", *, case: bool = True, value: str = "printf value") -> dict[str, Any]:
    return {
        "combinator": "all",
        "conditions": [{"field": "command", "operator": operator, "value": value, "caseSensitive": case}],
    }


def project(expressions: list[dict[str, Any] | None], *, target: str | None = None) -> CanonicalCommandProjection:
    rules = [
        {
            "id": f"rule-{index}",
            "enabled": True,
            "effect": "block",
            "match": {
                **({"commands": item} if item is not None else {}),
                "harnesses": ["codex"],
                "workspaces": ["/synthetic/workspace"],
                **({"devices": [target]} if target else {}),
            },
            "lifetime": {"mode": "until", "expiresAt": "2030-01-01T00:00:00Z"},
            "provenance": {"source": "builder", "createdAt": "2026-09-18T00:00:00Z"},
        }
        for index, item in enumerate(expressions)
    ]
    document = parse_policy_document_yaml(
        json.dumps(
            {
                "apiVersion": "guard.hashgraphonline.com/v1alpha1",
                "kind": "GuardPolicy",
                "metadata": {"id": "native-expression-policy", "name": "Synthetic policy", "revision": 8},
                "spec": {"defaults": {"mode": "enforce"}, "rules": rules},
            }
        )
    )
    return project_canonical_command_policy(
        document,
        publication=PolicyPublicationBinding(42, "sha256:" + "b" * 64, "local-installation"),
        workspace_id=WORKSPACE,
        target_device_id=TARGET,
    )


@pytest.mark.parametrize("vector", VECTORS["normalization"], ids=lambda value: value["id"])
def test_shared_native_normalization_contract(vector: dict[str, Any]) -> None:
    if "error" in vector:
        with pytest.raises(CommandExpressionError, match=vector["error"]):
            normalize_native_command_text(vector["input"])
        if vector["error"] != "command_unicode_invalid":
            with pytest.raises(CommandExpressionError, match=vector["error"]):
                normalize_command_text(vector["input"])
    else:
        assert normalize_native_command_text(vector["input"]) == vector["output"]
        assert normalize_command_text(vector["input"]) == vector["output"]


def test_explicit_whitespace_set_matches_every_python_unicode_codepoint() -> None:
    assert tuple(value for value in range(0x110000) if chr(value).isspace()) == NATIVE_COMMAND_WHITESPACE_CODEPOINTS


@pytest.mark.parametrize("vector", VECTORS["evaluations"], ids=lambda value: value["id"])
def test_shared_literal_vectors_use_the_actual_existing_evaluator(vector: dict[str, Any]) -> None:
    parsed = command_expression_from_mapping(vector["expression"])
    encoded = native_command_expression_payload(parsed, rule_id="fixture")
    assert json.loads(encoded) == vector["expression"]
    assert matches_command_expression(parsed, vector["command"]) is vector["matches"]
    assert normalize_native_command_text(vector["command"]) == normalize_command_text(vector["command"])


@pytest.mark.parametrize("vector", VECTORS["unsupported"], ids=lambda value: value["id"])
def test_unsupported_clause_refuses_entire_native_source_even_off_target(vector: dict[str, Any]) -> None:
    projection = project([expression(), vector["expression"]], target="other-server-target")
    assert all(not row.applicable_to_target for row in projection.rows)
    with pytest.raises(PolicyCompilationError, match=vector["error"]) as caught:
        materialize_native_command_projection(projection)
    assert caught.value.rule_id == "rule-1"


def test_native_materializer_retains_complete_source_and_row_alignment() -> None:
    original = project([expression(), None, expression("contains")])
    materialized = materialize_native_command_projection(original)
    assert materialized.schema == NATIVE_COMMAND_EXPRESSION_SCHEMA
    assert materialized.projection is original
    assert len(materialized.expression_payloads) == len(original.rows) == 3
    assert materialized.expression_payloads[1] is None
    assert original.source.publication.bundle_version == 42
    assert original.source.policy_version == "8"
    assert original.source.target_device_id == TARGET
    assert original.source.publication.installation_id == "local-installation"
    for index in (0, 2):
        payload = materialized.expression_payloads[index]
        item = original.rows[index]
        assert payload is not None and item.expression is not None
        assert json.loads(payload) == item.expression.to_mapping()
        assert item.selector.harness == "codex"
        assert item.selector.workspace == "/synthetic/workspace"
        assert item.selector.expires_at == "2030-01-01T00:00:00Z"
        assert item.applicable_to_target


@pytest.mark.parametrize(
    "invalid",
    [
        {"combinator": "all", "conditions": []},
        {"combinator": "all", "conditions": expression()["conditions"] * 65},
        expression(value="x" * 513),
        {"combinator": "not", "conditions": expression()["conditions"]},
    ],
)
def test_existing_typed_parser_rejects_invalid_expression_bounds(invalid: dict[str, Any]) -> None:
    with pytest.raises(CommandExpressionError):
        command_expression_from_mapping(invalid)


def test_native_materializer_refuses_unicode_that_native_json_cannot_represent() -> None:
    parsed = command_expression_from_mapping(expression(value="printf" + chr(0xD800)))
    with pytest.raises(PolicyCompilationError, match="native_command_value_unsupported"):
        native_command_expression_payload(parsed, rule_id="fixture")


def test_direct_typed_condition_cannot_bypass_exact_boolean_admission() -> None:
    parsed = command_expression_from_mapping(expression())
    malformed = replace(parsed.conditions[0], case_sensitive=1)  # type: ignore[arg-type]
    with pytest.raises(PolicyCompilationError, match="native_command_casefold_unsupported"):
        native_command_expression_payload(replace(parsed, conditions=(malformed,)), rule_id="fixture")


def test_unsupported_later_clause_cannot_be_hidden_by_any_short_circuit() -> None:
    parsed = command_expression_from_mapping(expression())
    unsupported = CommandCondition(field="command", operator="regex", value=".*", case_sensitive=True)
    parsed = replace(parsed, combinator="any", conditions=(*parsed.conditions, unsupported))
    with pytest.raises(PolicyCompilationError, match="native_command_operator_unsupported"):
        native_command_expression_payload(parsed, rule_id="fixture")


def test_normalizer_rejects_unpaired_unicode_surrogate() -> None:
    with pytest.raises(CommandExpressionError, match="command_unicode_invalid"):
        normalize_native_command_text("printf" + chr(0xD800))
