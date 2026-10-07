"""Declared-data detection stays bounded and never emits sample values."""

from __future__ import annotations

import json
from dataclasses import asdict

import pytest

from codex_plugin_scanner.guard.runtime.structured_data_sensitivity import (
    MAX_INPUT_BYTES,
    DeclaredField,
    DeclaredSchema,
    classifier_rule_version,
    classify_declared_content,
)


def _schema() -> DeclaredSchema:
    return DeclaredSchema(
        fields=(
            DeclaredField(("employee", "email"), "protected_personal", category="email_address"),
            DeclaredField(("employee", "id"), "protected_personal", "integer", "employee_id"),
            DeclaredField(("note",), "ordinary"),
        )
    )


def test_declared_personal_fields_are_detected_without_emitting_values() -> None:
    sample = "casey.sandbox@example.invalid"
    employee_id = 987654321
    payload = json.dumps({"employee": {"email": sample, "id": employee_id}, "note": "ordinary contact"})

    result = classify_declared_content(payload, schema=_schema())

    assert result.status == "matched"
    assert result.complete is True
    assert {(match.category, match.field_path) for match in result.matches} == {
        ("personal.email_address", ("employee", "email")),
        ("personal.employee_id", ("employee", "id")),
    }
    assert sample not in json.dumps(asdict(result))
    assert str(employee_id) not in json.dumps(asdict(result))


def test_contact_like_text_is_ordinary_only_when_schema_declares_it() -> None:
    sample = "casey.sandbox@example.invalid"
    result = classify_declared_content(json.dumps({"note": sample}), schema=_schema())
    unknown = classify_declared_content(json.dumps({"other": sample}), schema=_schema())

    assert result.status == "no_declared_match"
    assert result.complete is True
    assert unknown.status == "unsupported"
    assert unknown.reason_code == "unknown_field"
    assert result.rule_version == unknown.rule_version


def test_zero_integer_identifier_is_still_present() -> None:
    result = classify_declared_content('{"employee":{"id":0}}', schema=_schema())

    assert result.status == "matched"
    assert any(match.category == "personal.employee_id" for match in result.matches)


@pytest.mark.parametrize("value", ("", "   "))
def test_blank_declared_personal_string_is_absent(value: str) -> None:
    result = classify_declared_content(json.dumps({"employee": {"email": value}}), schema=_schema())

    assert result.status == "no_declared_match"
    assert result.complete is True


def test_existing_credential_rules_are_reused_without_value_or_hash() -> None:
    sample = "ghp_" + "A" * 24
    result = classify_declared_content(f"token={sample}")

    assert result.status == "matched"
    assert any(match.category == "credential.github-token" for match in result.matches)
    encoded = json.dumps(asdict(result))
    assert sample not in encoded
    assert result.rule_version == classifier_rule_version()


def test_early_credential_match_reports_only_scanned_bytes_with_schema() -> None:
    sample = "ghp_" + "A" * 24
    payload = json.dumps({"token": sample, "note": "x" * 5000})
    schema = DeclaredSchema((DeclaredField(("token",), "ordinary"), DeclaredField(("note",), "ordinary")))

    result = classify_declared_content(payload, schema=schema)

    assert result.status == "matched"
    assert result.complete is False
    assert 0 < result.bytes_scanned < len(payload.encode("utf-8"))


@pytest.mark.parametrize(
    ("payload", "reason"),
    (
        (b"\xff", "invalid_utf8"),
        (b"x" * (MAX_INPUT_BYTES + 1), "input_too_large"),
        ("x" * (MAX_INPUT_BYTES + 1), "input_too_large"),
        ('{"note":"a","note":"b"}', "invalid_or_duplicate_json"),
        ('{"note":"\\u0061"}', "encoded_or_escaped_content"),
        (json.dumps({"note": "C:\\Users\\sample"}), "encoded_or_escaped_content"),
        ('{"note":["a"]}', "array_unsupported"),
        ('{"employee":{"id":true}}', "field_type_invalid"),
        ('{"employee":{"email":{}}}', "field_type_invalid"),
        ('{"other":{}}', "unknown_field"),
        ('{"employee":{"other":{}}}', "unknown_field"),
        ('{"note":NaN}', "invalid_or_duplicate_json"),
    ),
)
def test_unclassifiable_inputs_never_become_no_match(payload: bytes | str, reason: str) -> None:
    result = classify_declared_content(payload, schema=_schema())

    assert result.status == "unsupported"
    assert result.complete is False
    assert result.reason_code == reason


def test_empty_declared_parent_object_has_no_present_fields() -> None:
    result = classify_declared_content('{"employee":{}}', schema=_schema())

    assert result.status == "no_declared_match"
    assert result.complete is True


@pytest.mark.parametrize("deadline", (0.0, -1.0))
def test_expired_deadline_is_unsupported_even_for_benign_text(deadline: float) -> None:
    result = classify_declared_content("ordinary contact", deadline_monotonic=deadline)

    assert result.status == "unsupported"
    assert result.complete is False
    assert result.reason_code == "scan_budget_exhausted"


def test_match_limit_is_strict_and_returns_no_values() -> None:
    schema = DeclaredSchema(
        tuple(DeclaredField((f"person{i}",), "protected_personal", category="person_name") for i in range(17))
    )
    payload = json.dumps({f"person{i}": f"Synthetic Person {i}" for i in range(17)})

    result = classify_declared_content(payload, schema=schema)

    assert result.status == "unsupported"
    assert result.reason_code == "match_limit_exceeded"
    assert result.complete is False
    assert len(result.matches) == 16
    assert "Synthetic Person" not in json.dumps(asdict(result))


def test_schema_and_rule_version_reject_ambiguous_declarations() -> None:
    field = DeclaredField(("note",), "ordinary")
    with pytest.raises(ValueError):
        DeclaredSchema((field, field))
    with pytest.raises(ValueError):
        DeclaredField(("note",), "protected_personal", category="arbitrary_label")
    with pytest.raises(ValueError):
        DeclaredField(("dynamic-key",), "ordinary")
    with pytest.raises(ValueError):
        DeclaredField("email", "ordinary")  # type: ignore[arg-type]

    assert classifier_rule_version(_schema()) != classifier_rule_version(DeclaredSchema((field,)))
