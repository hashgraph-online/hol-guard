from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.ci.final_release_evidence import FinalEvidenceError, validate_final_evidence, verify_component_files
from scripts.ci.final_release_evidence import _load as load_final_evidence
from scripts.ci.generate_release_evidence_contract import generate
from scripts.ci.verify_installed_release_matrix import _load as load_matrix
from scripts.ci.verify_installed_release_matrix import validate_matrix
from scripts.ci.verify_release_negative_outcomes import validate_negative_outcomes
from tests.test_release_required_evidence import _payload

VERSION = "3.0.1"
SOURCE_SHA = "a" * 40
RULE_DIGEST = "b" * 64


def test_generated_contract_fixtures_validate_together(tmp_path: Path) -> None:
    _generate(tmp_path)

    matrix = validate_matrix(
        load_matrix(tmp_path / "installed-release-matrix.json"),
        expected_version=VERSION,
        expected_source_sha=SOURCE_SHA,
        expected_rule_digest=RULE_DIGEST,
        windows_waiver="contract-fixture",
    )
    assert len(matrix["platforms"]) == 3

    negatives = validate_negative_outcomes(
        json.loads((tmp_path / "negative-outcomes.json").read_text(encoding="utf-8"))
    )
    assert [case["name"] for case in negatives["cases"]] == [
        "draft",
        "wrong-workspace",
        "stale",
        "unavailable-runtime",
        "immutable-block",
    ]
    assert all(case["passed"] is False for case in negatives["cases"])

    final = validate_final_evidence(
        load_final_evidence(tmp_path / "final-release-evidence.json"),
        expected_version=VERSION,
        expected_source_sha=SOURCE_SHA,
        expected_rule_digest=RULE_DIGEST,
    )
    assert final["release_ready"] is False
    assert (
        json.loads((tmp_path / "final-release-evidence.json").read_text(encoding="utf-8"))["release"]["commit_sha"]
        == SOURCE_SHA
    )


def _generate(directory: Path) -> None:
    negative = directory / "negative-input.json"
    negative.write_text(json.dumps(_payload()))
    collection = directory / "collection-input.json"
    collection.write_text(
        json.dumps(
            {
                "schema": "hol-guard-release-collection.v1",
                "source_sha": SOURCE_SHA,
                "evidence_kind": "collection-and-configuration",
                "missing_required": [],
                "deselected_required": [],
                "installed_runtime_verified": False,
                "collected_release_cases": 5,
                "default_collected_cases": 5,
            }
        )
    )
    generate(
        directory,
        version=VERSION,
        source_sha=SOURCE_SHA,
        rule_digest=RULE_DIGEST,
        negative_outcomes=negative,
        required_collection=collection,
    )


def test_final_contract_binds_required_evidence_bytes_and_stays_a_fixture(tmp_path: Path) -> None:
    _generate(tmp_path)
    manifest = load_final_evidence(tmp_path / "final-release-evidence.json")
    verify_component_files(manifest, tmp_path, source_sha=SOURCE_SHA)
    assert manifest["evidence_kind"] == "contract-fixture"
    for label in ("negative_outcomes", "required_collection"):
        component = manifest["evidence"][label]
        path = tmp_path / component["name"]
        assert component["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    (tmp_path / "negative-outcomes.json").write_text("{}")
    with pytest.raises(FinalEvidenceError, match="digest does not match"):
        verify_component_files(manifest, tmp_path, source_sha=SOURCE_SHA)


def test_generator_requires_executed_outcomes_from_the_same_source(tmp_path: Path) -> None:
    _generate(tmp_path)
    negative = tmp_path / "negative-input.json"
    payload = _payload()
    payload["source_sha"] = "c" * 40
    negative.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        generate(
            tmp_path,
            version=VERSION,
            source_sha=SOURCE_SHA,
            rule_digest=RULE_DIGEST,
            negative_outcomes=negative,
            required_collection=tmp_path / "collection-input.json",
        )
