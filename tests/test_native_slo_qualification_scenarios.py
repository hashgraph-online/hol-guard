from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.native_slo_qualification_scenarios import _retained_scenario, validate_receipt_profile


def test_legacy_receipt_path_requires_exact_audited_build() -> None:
    validate_receipt_profile("candidate", {"build_sha": "new-candidate"})
    validate_receipt_profile("baseline_2e672d2", {"build_sha": "2e672d2d950c6ec471005ddba46e49bba16dc23b"})
    for build in (None, "unknown", "2e672d2", "new-candidate"):
        with pytest.raises(ValueError, match="exact audited native build"):
            validate_receipt_profile("baseline_2e672d2", {"build_sha": build})
    with pytest.raises(ValueError, match="unsupported"):
        validate_receipt_profile("legacy", {})


def test_known_side_contract_failure_is_retained_as_failure(tmp_path: Path) -> None:
    def fail() -> dict[str, object]:
        raise RuntimeError("registered_surface_copilot_schema_mismatch")

    destination = tmp_path / "failed.json"
    result = _retained_scenario(fail, evidence_file=destination, scope="installed_delivery")
    assert result["passed"] is False
    assert result["scope"] == "installed_delivery"
    assert json.loads(destination.read_text()) == result
    with pytest.raises(FileExistsError):
        _retained_scenario(fail, evidence_file=destination, scope="installed_delivery")


def test_failed_observed_mixed_gate_cannot_become_a_pass(tmp_path: Path) -> None:
    observed = {"passed": False, "checks": {"offered_latency": False}, "failures": {"timed_out": 1}}
    assert _retained_scenario(lambda: observed, evidence_file=tmp_path / "mixed.json", scope="mixed") == observed
