"""The approval gate must inspect the invoked native wheel workflow."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_approval_gate", ROOT / "scripts/ci/native_approval_contract_gate.py"
)
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


@pytest.fixture
def approval_source(tmp_path):
    paths = (
        gate.WORKFLOW,
        gate.PUBLISH_WORKFLOW,
        gate.RELEASE_WHEEL_WORKFLOW,
        gate.MANAGED_RESIDENT,
        gate.MANAGED_OWNER_LOCK,
        Path("rust/crates/guard-runtime/src/managed_resident_tests.rs"),
        Path("rust/crates/guard-runtime/src/edge.rs"),
        Path("rust/crates/guard-runtime/src/edge_tests.rs"),
        Path("rust/crates/guard-runtime/src/policy_enforcement.rs"),
        Path("rust/crates/guard-runtime/src/policy_enforcement_tests.rs"),
    )
    for path in paths:
        destination = tmp_path / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / path).read_bytes())
    return tmp_path


def test_approval_gate_accepts_actual_invoked_wheel_source(approval_source):
    gate._check_ownership_contract(approval_source)


@pytest.mark.parametrize(
    "missing",
    [
        "uses: ./.github/workflows/release-native-wheel.yml",
        "--require-release-root",
        "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX",
        "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX",
    ],
)
def test_approval_gate_rejects_missing_wheel_invocation_or_root_contract(approval_source, missing):
    workflow = gate.PUBLISH_WORKFLOW if missing.startswith("uses:") else gate.RELEASE_WHEEL_WORKFLOW
    path = approval_source / workflow
    path.write_text(path.read_text().replace(missing, "removed-contract"))
    # Root-contract text in the caller cannot stand in for the actual build steps.
    publish = approval_source / gate.PUBLISH_WORKFLOW
    with publish.open("a") as stream:
        stream.write("\n# --require-release-root HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX ")
        stream.write("HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX\n")
    with pytest.raises(RuntimeError, match="release workflow does not"):
        gate._check_ownership_contract(approval_source)


def test_approval_gate_rejects_missing_invoked_workflow(approval_source):
    (approval_source / gate.RELEASE_WHEEL_WORKFLOW).unlink()
    with pytest.raises(RuntimeError, match="required approval source is missing"):
        gate._check_ownership_contract(approval_source)
