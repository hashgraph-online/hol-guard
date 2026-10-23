from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from codex_plugin_scanner.guard.policy_document import canonical_policy_document_bytes
from codex_plugin_scanner.guard.policy_document_yaml import (
    PolicyDocumentError,
    parse_policy_document_yaml,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "spec" / "guard-policy" / "v1alpha1" / "fixtures"


def _document_with_commands(commands: dict[str, object]) -> str:
    document = parse_policy_document_yaml((FIXTURES / "valid" / "basic.yaml").read_bytes())
    value = json.loads(canonical_policy_document_bytes(document))
    value["spec"]["rules"][0]["match"]["commands"] = commands
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=False)


def test_a_condition_keeps_its_spelling_and_loses_only_its_spacing() -> None:
    source = _document_with_commands(
        {
            "combinator": "all",
            "conditions": [{"field": "command", "operator": "startsWith", "value": "  docker   compose  "}],
        }
    )

    document = parse_policy_document_yaml(source)

    commands = document.rules[0].match.to_mapping()["commands"]
    assert commands == {
        "combinator": "all",
        "conditions": [
            {"field": "command", "operator": "startsWith", "value": "docker compose", "caseSensitive": False}
        ],
    }


def test_a_value_that_is_only_spacing_is_refused_at_its_rule() -> None:
    source = _document_with_commands(
        {"combinator": "all", "conditions": [{"field": "command", "operator": "exact", "value": " "}]}
    )

    with pytest.raises(PolicyDocumentError) as error:
        parse_policy_document_yaml(source)

    assert error.value.diagnostics[0].code == "command_value_required"
    assert error.value.diagnostics[0].path == ("spec", "rules", 0, "match", "commands")
