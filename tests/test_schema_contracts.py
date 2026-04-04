"""Schema contract smoke tests."""

import json
from pathlib import Path

from jsonschema import validate

from codex_plugin_scanner.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"


def test_schema_files_exist():
    assert (ROOT / "schemas" / "scan-result.v1.json").exists()
    assert (ROOT / "schemas" / "verify-result.v1.json").exists()
    assert (ROOT / "schemas" / "plugin-quality.v1.json").exists()


def test_scan_output_matches_schema_required_keys(capsys):
    rc = main(["scan", str(FIXTURES / "good-plugin"), "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    schema = json.loads((ROOT / "schemas" / "scan-result.v1.json").read_text(encoding="utf-8"))
    validate(instance=payload, schema=schema)


def test_repository_scan_output_matches_schema_required_keys(capsys):
    rc = main(["scan", str(FIXTURES / "multi-plugin-repo"), "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    schema = json.loads((ROOT / "schemas" / "scan-result.v1.json").read_text(encoding="utf-8"))
    validate(instance=payload, schema=schema)


def test_verify_output_matches_schema_required_keys(capsys):
    rc = main(["verify", str(FIXTURES / "good-plugin"), "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    schema = json.loads((ROOT / "schemas" / "verify-result.v1.json").read_text(encoding="utf-8"))
    validate(instance=payload, schema=schema)


def test_repository_verify_output_matches_schema_required_keys(capsys):
    rc = main(["verify", str(FIXTURES / "multi-plugin-repo"), "--format", "json"])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    schema = json.loads((ROOT / "schemas" / "verify-result.v1.json").read_text(encoding="utf-8"))
    validate(instance=payload, schema=schema)


def test_submit_artifact_matches_schema_required_keys(tmp_path):
    artifact = tmp_path / "plugin-quality.json"
    rc = main(["submit", str(FIXTURES / "good-plugin"), "--attest", str(artifact)])
    assert rc == 0
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "schemas" / "plugin-quality.v1.json").read_text(encoding="utf-8"))
    validate(instance=payload, schema=schema)
