from __future__ import annotations

import json
from dataclasses import replace
from importlib import resources
from pathlib import Path

import pytest
import yaml

from codex_plugin_scanner.guard.policy_bundle_parser import (
    canonical_policy_bundle_payload,
    computed_policy_bundle_hash,
    payload_hash_for_policy_bundle,
)
from codex_plugin_scanner.guard.policy_document import (
    canonical_policy_document_bytes,
    policy_document_digest,
    validate_effective_rule_ids,
)
from codex_plugin_scanner.guard.policy_document_yaml import (
    MAX_POLICY_BYTES,
    MAX_POLICY_TOKENS,
    PolicyDocumentError,
    format_policy_document_yaml,
    parse_policy_document_yaml,
    policy_document_schema,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec" / "guard-policy" / "v1alpha1"
FIXTURES = SPEC / "fixtures"


def _basic_mapping() -> dict[str, object]:
    document = parse_policy_document_yaml((FIXTURES / "valid" / "basic.yaml").read_bytes())
    return json.loads(canonical_policy_document_bytes(document))


def _yaml(value: dict[str, object]) -> str:
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=False)


def test_normative_and_packaged_schema_are_identical() -> None:
    normative = (SPEC / "schema.json").read_bytes()
    packaged = (
        resources.files("codex_plugin_scanner.guard")
        .joinpath("schemas")
        .joinpath("guard-policy-v1alpha1.schema.json")
        .read_bytes()
    )

    assert packaged == normative
    assert policy_document_schema()["$id"] == "https://guard.hashgraphonline.com/schema/policy/v1alpha1"

    mutable_copy = policy_document_schema()
    mutable_copy.clear()
    assert policy_document_schema()["$id"] == "https://guard.hashgraphonline.com/schema/policy/v1alpha1"


def test_valid_conformance_fixtures_are_stable() -> None:
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))

    for relative_path in manifest["valid"]:
        document = parse_policy_document_yaml((FIXTURES / relative_path).read_bytes())
        formatted = format_policy_document_yaml(document)
        reparsed = parse_policy_document_yaml(formatted)

        assert reparsed == document
        assert format_policy_document_yaml(reparsed) == formatted
        assert canonical_policy_document_bytes(reparsed) == canonical_policy_document_bytes(document)
        assert policy_document_digest(reparsed) == policy_document_digest(document)


def test_provenance_update_and_import_fields_round_trip() -> None:
    mapping = _basic_mapping()
    spec = mapping["spec"]
    assert isinstance(spec, dict)
    rules = spec["rules"]
    assert isinstance(rules, list)
    first_rule = rules[0]
    assert isinstance(first_rule, dict)
    provenance = first_rule["provenance"]
    assert isinstance(provenance, dict)
    provenance.update(
        {
            "updatedAt": "2026-07-16T12:00:00Z",
            "updatedBy": "editor@example.com",
            "importSourceDigest": "sha256:canonical-import",
            "previousRuleRevision": 4,
        }
    )

    document = parse_policy_document_yaml(_yaml(mapping))

    assert document.rules[0].provenance.to_mapping() == provenance


def test_provenance_updated_at_rejects_invalid_calendar_date() -> None:
    mapping = _basic_mapping()
    spec = mapping["spec"]
    assert isinstance(spec, dict)
    rules = spec["rules"]
    assert isinstance(rules, list)
    first_rule = rules[0]
    assert isinstance(first_rule, dict)
    provenance = first_rule["provenance"]
    assert isinstance(provenance, dict)
    provenance["updatedAt"] = "2026-02-31T12:00:00Z"

    with pytest.raises(PolicyDocumentError) as error:
        parse_policy_document_yaml(_yaml(mapping))

    assert error.value.diagnostics[0].code == "invalid_timestamp"
    assert error.value.diagnostics[0].path == ("spec", "rules", 0, "provenance", "updatedAt")


def test_yaml_11_ambiguous_scalars_remain_strings() -> None:
    document = parse_policy_document_yaml((FIXTURES / "valid" / "extensions-and-scalars.yaml").read_bytes())

    labels = dict(document.metadata.labels)
    assert labels == {
        "infinity": ".inf",
        "leading-zero": "0123",
        "no-value": "no",
        "not-a-number": ".nan",
        "off-value": "off",
        "on-value": "on",
        "sexagesimal": "12:34:56",
        "tilde-value": "~",
        "timestamp-text": "2026-07-15",
        "yes-value": "yes",
    }


def test_invalid_conformance_fixtures_have_bounded_codes() -> None:
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))

    for relative_path, expected_code in manifest["invalid"].items():
        source = (FIXTURES / relative_path).read_bytes()
        with pytest.raises(PolicyDocumentError) as error:
            parse_policy_document_yaml(source)

        assert error.value.diagnostics[0].code == expected_code
        assert len(error.value.diagnostics) <= 20
        assert "redacted-fixture-value" not in str(error.value)


def test_extensions_are_preserved_and_signed() -> None:
    source = (FIXTURES / "valid" / "extensions-and-scalars.yaml").read_bytes()
    document = parse_policy_document_yaml(source)
    changed = replace(document, extensions=(("x-document-note", '"changed"'),))

    assert "x-document-note" in document.to_mapping()
    assert policy_document_digest(changed) != policy_document_digest(document)


def test_duplicate_rule_ids_fail_across_explicit_document_set() -> None:
    document = parse_policy_document_yaml((FIXTURES / "valid" / "basic.yaml").read_bytes())

    with pytest.raises(ValueError, match="duplicate_effective_rule_id"):
        validate_effective_rule_ids((document, document))


def test_canonical_hash_vector_is_cross_language_stable() -> None:
    vector = json.loads((FIXTURES / "hashes" / "basic.json").read_text(encoding="utf-8"))
    document = parse_policy_document_yaml((FIXTURES / "valid" / "basic.yaml").read_bytes())

    assert canonical_policy_document_bytes(document).decode("utf-8") == vector["canonicalJson"]
    assert policy_document_digest(document) == vector["sha256"]


def test_legacy_bundle_v1_hash_projection_is_unchanged() -> None:
    vector = json.loads((FIXTURES / "hashes" / "legacy-bundle-v1.json").read_text(encoding="utf-8"))
    payload = vector["payload"]

    assert computed_policy_bundle_hash(payload) == vector["bundleHash"]
    assert payload_hash_for_policy_bundle(payload) == vector["payloadHash"]
    assert canonical_policy_bundle_payload(payload).decode("utf-8") == vector["canonicalSigningPayload"]


def test_precedence_vectors_cover_required_collision_families() -> None:
    fixture = json.loads((FIXTURES / "decisions" / "precedence.json").read_text(encoding="utf-8"))
    names = {vector["name"] for vector in fixture["vectors"]}

    assert names == {
        "eligible local once beats persisted",
        "exact artifact beats newer global",
        "expired exact row is excluded",
        "newer local wins equal specificity",
        "newer remote wins equal specificity",
    }


def test_encoded_size_limit_runs_before_yaml_parsing() -> None:
    with pytest.raises(PolicyDocumentError) as error:
        parse_policy_document_yaml(b"x" * (MAX_POLICY_BYTES + 1))

    assert error.value.diagnostics == (error.value.diagnostics[0],)
    assert error.value.diagnostics[0].code == "limit_bytes"


def test_token_limit_stops_large_yaml_before_object_construction() -> None:
    source = "items:\n" + ("- value\n" * (MAX_POLICY_TOKENS // 2 + 1))

    with pytest.raises(PolicyDocumentError) as error:
        parse_policy_document_yaml(source)

    assert error.value.diagnostics[0].code == "limit_tokens"


@pytest.mark.parametrize(
    ("test_case", "expected_code"),
    (
        ("depth", "limit_depth"),
        ("rules", "limit_collection"),
        ("matcher-values", "limit_collection"),
        ("string", "limit_string"),
        ("float", "unsupported_float"),
        ("expression", "schema_additionalProperties"),
    ),
)
def test_structural_limits_and_expression_fields_fail(test_case: str, expected_code: str) -> None:
    value = _basic_mapping()
    spec = value["spec"]
    assert isinstance(spec, dict)
    rules = spec["rules"]
    assert isinstance(rules, list)
    rule = rules[0]
    assert isinstance(rule, dict)

    if test_case == "depth":
        nested: object = "leaf"
        for _ in range(34):
            nested = [nested]
        value["x-deep"] = nested
    elif test_case == "rules":
        spec["rules"] = [json.loads(json.dumps(rule)) for _ in range(1_001)]
    elif test_case == "matcher-values":
        match = rule["match"]
        assert isinstance(match, dict)
        match["packages"] = [f"package-{index}" for index in range(257)]
    elif test_case == "string":
        value["x-long"] = "x" * 4_097
    elif test_case == "float":
        value["x-float"] = 1.5
    else:
        match = rule["match"]
        assert isinstance(match, dict)
        match["expression"] = "artifact.startsWith('pkg:')"

    with pytest.raises(PolicyDocumentError) as error:
        parse_policy_document_yaml(_yaml(value))

    assert error.value.diagnostics[0].code == expected_code


def test_multiple_yaml_documents_fail() -> None:
    source = (FIXTURES / "valid" / "basic.yaml").read_text(encoding="utf-8")

    with pytest.raises(PolicyDocumentError) as error:
        parse_policy_document_yaml(f"{source}---\n{source}")

    assert error.value.diagnostics[0].code == "yaml_document_count"


def test_diagnostic_does_not_echo_unknown_value() -> None:
    source = """apiVersion: guard.hashgraphonline.com/v1alpha1
kind: GuardPolicy
metadata:
  id: policy.invalid
  name: Invalid
  revision: 1
spec:
  defaults:
    mode: prompt
    unknown: do-not-log-this
  rules: []
"""

    with pytest.raises(PolicyDocumentError) as error:
        parse_policy_document_yaml(source)

    assert "do-not-log-this" not in str(error.value)
    assert error.value.diagnostics[0].line is not None
    assert error.value.diagnostics[0].column is not None


def test_extension_objects_may_use_sensitive_looking_keys_without_secret_values() -> None:
    value = _basic_mapping()
    value["x-vendor"] = {
        "authorization": False,
        "credentials": None,
        "token": "disabled",
    }

    document = parse_policy_document_yaml(_yaml(value))

    assert document.to_mapping()["x-vendor"] == value["x-vendor"]


def test_deep_yaml_and_huge_integers_return_bounded_diagnostics() -> None:
    basic = _yaml(_basic_mapping())
    deep = f"{basic}\nx-deep: {'[' * 40}null{']' * 40}\n"
    huge_integer = f"{basic}\nx-integer: {'9' * 10_000}\n"

    for source in (deep, huge_integer):
        with pytest.raises(PolicyDocumentError) as error:
            parse_policy_document_yaml(source)

        assert len(str(error.value)) <= 4_096
        assert error.value.diagnostics[0].code.startswith("limit_")


def test_unpaired_surrogate_returns_invalid_utf8() -> None:
    with pytest.raises(PolicyDocumentError) as error:
        parse_policy_document_yaml("\ud800")

    assert error.value.diagnostics[0].code == "invalid_utf8"


def test_diagnostic_paths_escape_attacker_controlled_mapping_keys() -> None:
    value = _basic_mapping()
    value["line\nbreak"] = True

    with pytest.raises(PolicyDocumentError) as error:
        parse_policy_document_yaml(_yaml(value))

    assert "line\nbreak" not in str(error.value)
    assert len(str(error.value)) <= 4_096


def test_extension_integers_are_limited_to_cross_language_safe_range() -> None:
    value = _basic_mapping()
    value["x-integer"] = 9_007_199_254_740_992

    with pytest.raises(PolicyDocumentError) as error:
        parse_policy_document_yaml(_yaml(value))

    assert error.value.diagnostics[0].code == "schema_oneOf"


def test_quoted_digit_string_is_not_treated_as_an_integer_limit() -> None:
    source = _yaml(_basic_mapping()) + 'x-string: "12345678901234567"\n'

    document = parse_policy_document_yaml(source)

    assert document.to_mapping()["x-string"] == "12345678901234567"


def test_yaml_escaped_surrogate_is_rejected_before_canonicalization() -> None:
    source = _yaml(_basic_mapping()) + 'x-bad: "\\uD800"\n'

    with pytest.raises(PolicyDocumentError) as error:
        parse_policy_document_yaml(source)

    assert error.value.diagnostics[0].code == "invalid_unicode"


def test_canonical_object_keys_use_utf16_order() -> None:
    value = _basic_mapping()
    value["x-sort"] = {"\ue000": "bmp", "😀": "astral"}

    canonical = canonical_policy_document_bytes(parse_policy_document_yaml(_yaml(value))).decode("utf-8")

    assert canonical.index('"😀"') < canonical.index('"\ue000"')
