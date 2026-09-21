from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "rust_io_privacy_gate.py"
SPEC = importlib.util.spec_from_file_location("rust_io_privacy_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_privacy_gate_proves_current_route_and_evidence_shapes() -> None:
    report = MODULE.validate(ROOT)

    assert report["schema"] == "hol-guard.native-hook-io-privacy.v1"
    assert report["status"] == "passed"
    assert "raw_payload" in report["excluded_fields"]


def test_artifact_validator_accepts_bounded_receipt() -> None:
    artifact = {
        "schema": "hol-guard-native-hook-evidence.v1",
        "harness": "pi",
        "event_name": "PostToolUse",
        "decision": "allow",
        "reason_code": "source_full_scan_allow",
        "workspace_bound": True,
    }

    assert MODULE.validate_artifact(artifact) == []


@pytest.mark.parametrize(
    "artifact",
    [
        {"command": "cat /private/source"},
        {"safe": "/Users/alice/project"},
        {"safe": "ghp_" + "a" * 32},
        {"safe": "fn main() {}\n"},
    ],
)
def test_artifact_validator_rejects_raw_content_and_private_material(artifact: object) -> None:
    assert MODULE.validate_artifact(artifact)


def test_static_gate_rejects_new_command_field_in_serializer(tmp_path: Path) -> None:
    paths = {relative for relative, _name, _class_name in MODULE._SERIALIZERS} | {
        "src/codex_plugin_scanner/guard/native_route_receipt.py"
    }
    for relative in paths:
        source = ROOT / relative
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)

    queue = tmp_path / "src/codex_plugin_scanner/guard/runtime/hook_enrichment_queue.py"
    source = queue.read_text(encoding="utf-8")
    marker = '                "schema": "hol-guard-native-hook-evidence.v1",\n'
    assert marker in source
    queue.write_text(source.replace(marker, '                "command": "raw",\n' + marker, 1), encoding="utf-8")

    with pytest.raises(RuntimeError, match="forbidden raw-content artifact field"):
        MODULE.validate(tmp_path)
