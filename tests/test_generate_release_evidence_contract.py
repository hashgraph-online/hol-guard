from __future__ import annotations

import json
from pathlib import Path

from scripts.ci.final_release_evidence import _load as load_final_evidence
from scripts.ci.final_release_evidence import validate_final_evidence
from scripts.ci.generate_release_evidence_contract import generate
from scripts.ci.verify_installed_release_matrix import _load as load_matrix
from scripts.ci.verify_installed_release_matrix import validate_matrix

VERSION = "3.0.1"
SOURCE_SHA = "a" * 40
RULE_DIGEST = "b" * 64


def test_generated_contract_fixtures_validate_together(tmp_path: Path) -> None:
    generate(tmp_path, version=VERSION, source_sha=SOURCE_SHA, rule_digest=RULE_DIGEST)

    matrix = validate_matrix(
        load_matrix(tmp_path / "installed-release-matrix.json"),
        expected_version=VERSION,
        expected_source_sha=SOURCE_SHA,
        expected_rule_digest=RULE_DIGEST,
        windows_waiver="contract-fixture",
    )
    assert len(matrix["platforms"]) == 3

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
