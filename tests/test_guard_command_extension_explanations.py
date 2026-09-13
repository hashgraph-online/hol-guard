from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.command_extension_explanations import (
    EXTENSION_EXPLANATION_SCHEMA_VERSION,
    explanation_catalog_digest,
    parse_extension_explanation_catalog,
    sanitize_external_explanation_value,
    validate_builtin_explanation_coverage,
)


def _payload() -> dict[str, object]:
    return {
        "schema_version": EXTENSION_EXPLANATION_SCHEMA_VERSION,
        "revision": 7,
        "extensions": [
            {
                "extension_id": "command.filesystem",
                "everyday_name": "File changes",
                "everyday_purpose": "Protects files and folders from risky changes.",
                "search_synonyms": ["files", "folders"],
                "technical_synonyms": ["filesystem", "rm"],
                "dialects": ["posix", "powershell", "cmd"],
            }
        ],
        "rules": [
            {
                "rule_id": "command.filesystem.delete",
                "action_intent_id": "filesystem.delete",
                "target_kind": "filesystem_item",
                "consequence_ids": ["filesystem.irreversible_loss"],
                "safer_step_ids": ["filesystem.preview", "filesystem.backup"],
                "safe_variant_id": "filesystem.trash",
                "minimum_confidence": "exact",
            }
        ],
    }


def test_catalog_parses_typed_presentation_metadata_and_has_stable_digest() -> None:
    first = parse_extension_explanation_catalog(_payload())
    second = parse_extension_explanation_catalog(_payload())
    assert first == second
    assert first.digest == second.digest
    assert first.rule("command.filesystem.delete") is not None
    assert len(first.digest) == 64


def test_catalog_rejects_schema_mismatch_and_rollback() -> None:
    bad = _payload()
    bad["schema_version"] = 2
    with pytest.raises(ValueError, match="schema"):
        parse_extension_explanation_catalog(bad)
    with pytest.raises(ValueError, match="rollback"):
        parse_extension_explanation_catalog(_payload(), minimum_revision=8)


@pytest.mark.parametrize("field", ["action", "enforcement_action", "policy_action", "decision", "verdict"])
def test_external_metadata_cannot_emit_enforcement(field: str) -> None:
    payload = _payload()
    rules = payload["rules"]
    assert isinstance(rules, list)
    rule = rules[0]
    assert isinstance(rule, dict)
    rule[field] = "allow"
    with pytest.raises(ValueError, match="enforcement"):
        parse_extension_explanation_catalog(payload)


def test_external_metadata_cannot_suppress_all_consequences() -> None:
    payload = _payload()
    rules = payload["rules"]
    assert isinstance(rules, list)
    rule = rules[0]
    assert isinstance(rule, dict)
    rule["consequence_ids"] = []
    with pytest.raises(ValueError, match="suppress"):
        parse_extension_explanation_catalog(payload)


def test_external_values_are_redacted_and_bounded() -> None:
    secret = "sk-abcdefgh12345678"
    value = sanitize_external_explanation_value(f"token {secret} " + "x" * 200, limit=80)
    assert secret not in value
    assert len(value) <= 80


def test_builtin_rules_require_metadata_or_explicit_generic_fallback() -> None:
    catalog = parse_extension_explanation_catalog(_payload())
    validate_builtin_explanation_coverage(
        rule_ids=("command.filesystem.delete", "command.filesystem.copy"),
        catalog=catalog,
        explicit_generic_fallbacks=("command.filesystem.copy",),
    )
    with pytest.raises(ValueError, match="lack explanation"):
        validate_builtin_explanation_coverage(
            rule_ids=("command.filesystem.delete", "command.filesystem.copy"),
            catalog=catalog,
        )


def test_combined_digest_binds_command_catalog_and_explanation_metadata() -> None:
    catalog = parse_extension_explanation_catalog(_payload())
    first = explanation_catalog_digest(command_catalog_digest="a" * 64, metadata_catalog=catalog)
    second = explanation_catalog_digest(command_catalog_digest="b" * 64, metadata_catalog=catalog)
    assert first != second
