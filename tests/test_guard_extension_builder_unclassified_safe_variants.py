"""Reviewed literals reach the unclassified rule, and optional metadata reaches the source."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.discover import discover
from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import canonical_json
from codex_plugin_scanner.guard.extension_builder.kit import build_kit
from codex_plugin_scanner.guard.extension_builder.models import (
    load_discovery,
    make_discovery,
    make_operation,
    validate_metadata,
)
from codex_plugin_scanner.guard.extension_builder.render_native import (
    DEFAULT_EXTENSION_DESCRIPTION,
    command_fixture_path,
    command_source_path,
)
from codex_plugin_scanner.guard.extension_builder.review import default_review, load_review
from tests.extension_builder_support import cli_document, make_kit, metadata


def _source(kit) -> dict[str, object]:
    return json.loads(kit.native_files()[command_source_path(kit.discovery.metadata)])


def _rules(kit) -> dict[str, dict[str, object]]:
    extension = _source(kit)["extension"]
    return {rule["rule_id"]: rule for rule in extension["rules"]}


def _cases(kit) -> list[dict[str, object]]:
    payload = json.loads(kit.native_files()[command_fixture_path(kit.discovery.metadata)])
    return payload["cases"] if isinstance(payload, dict) else payload


def test_unclassified_rule_carries_every_reviewed_literal(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, reviewed=True)
    catalog_id = kit.discovery.metadata.catalog_id
    unclassified = _rules(kit)[f"{catalog_id}.unclassified"]
    arguments = [variant["matcher"]["config"]["arguments"] for variant in unclassified["safe_variants"]]
    assert arguments == [["items", "list", "--json"]]
    assert unclassified["default_mode"] == "review"


def test_unclassified_rule_without_reviewed_literals_is_unchanged(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, reviewed=False)
    unclassified = _rules(kit)[f"{kit.discovery.metadata.catalog_id}.unclassified"]
    assert unclassified["safe_variants"] == []


def test_each_reviewed_literal_gets_a_fixture_case_on_the_unclassified_rule(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, reviewed=True)
    catalog_id = kit.discovery.metadata.catalog_id
    safe = [case for case in _cases(kit) if "-safe-" in case["id"]]
    assert {case["rule_id"] for case in safe} == {
        f"{catalog_id}.unclassified",
        next(case["rule_id"] for case in safe if not case["id"].endswith("-unclassified")),
    }
    for case in safe:
        assert case["expected_action"] == "review"
        assert case["expected_effective_segments"] == []
        assert case["command"] == "builder-demo items list --json"


def test_more_than_64_reviewed_literals_is_a_builder_error(tmp_path: Path) -> None:
    base = make_kit(tmp_path).discovery
    operations = tuple(make_operation("cli", path=(f"operation{i}",), evidence={}) for i in range(65))
    discovery = make_discovery(base.metadata, "cli", "0" * 64, operations, base.limitations)
    payload = default_review(discovery).to_dict()
    for operation in discovery.operations:
        payload["entries"][operation.operation_id].update(
            {
                "reviewed": True,
                "rationale": "Reviewed against the synthetic fixture implementation.",
                "evidenceUrl": discovery.metadata.homepage,
                "safeArgv": [list(operation.path)],
            }
        )
    review = load_review(payload, discovery)
    with pytest.raises(BuilderError) as error:
        build_kit(discovery, review)
    assert error.value.code == "safe_variant_limit"


def test_license_and_description_default_when_absent(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, reviewed=True)
    extension = _source(kit)["extension"]
    assert extension["license"] is None
    assert extension["description"] == DEFAULT_EXTENSION_DESCRIPTION
    assert "license" not in kit.discovery.metadata.to_dict()
    assert "description" not in kit.discovery.metadata.to_dict()


def test_license_and_description_render_from_discovery_metadata(tmp_path: Path) -> None:
    source = tmp_path / "cli-source.json"
    source.write_text(canonical_json(cli_document()), encoding="utf-8")
    described = dataclasses.replace(metadata(), license="MIT", description="Inspects demo items.")
    discovery = discover("cli", source, described)
    extension = _source(build_kit(discovery, default_review(discovery)))["extension"]
    assert extension["license"] == "MIT"
    assert extension["description"] == "Inspects demo items."
    replayed = load_discovery(json.loads(canonical_json(discovery.to_dict())))
    assert replayed.metadata.license == "MIT"
    assert replayed.binding == discovery.binding


def test_optional_metadata_changes_the_binding(tmp_path: Path) -> None:
    source = tmp_path / "cli-source.json"
    source.write_text(canonical_json(cli_document()), encoding="utf-8")
    plain = discover("cli", source, metadata())
    licensed = discover("cli", source, dataclasses.replace(metadata(), license="MIT"))
    assert plain.binding != licensed.binding


@pytest.mark.parametrize(
    ("field", "value"),
    [("license", "MIT; rm"), ("license", "not a license"), ("description", "two\nlines"), ("description", "x" * 513)],
)
def test_invalid_optional_metadata_is_rejected(field: str, value: str) -> None:
    with pytest.raises(BuilderError):
        validate_metadata(dataclasses.replace(metadata(), **{field: value}))
