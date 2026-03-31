"""Schema contract smoke tests."""

import json
from pathlib import Path

from codex_plugin_scanner.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"


def test_schema_files_exist():
    assert (ROOT / "schemas" / "scan-result.v1.json").exists()
    assert (ROOT / "schemas" / "verify-result.v1.json").exists()
    assert (ROOT / "schemas" / "plugin-quality.v1.json").exists()


def test_submit_artifact_contains_schema_contract(tmp_path):
    artifact = tmp_path / "plugin-quality.json"
    rc = main(["submit", str(FIXTURES / "good-plugin"), "--attest", str(artifact)])
    assert rc == 0
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "plugin-quality.v1"
    assert "digest" in payload
