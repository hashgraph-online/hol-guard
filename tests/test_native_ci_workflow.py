"""Preserve native artifact provenance and full qualification during CI changes."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _workflow(name: str) -> dict:
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))


def test_ci_rust_cache_can_only_be_written_by_main_pushes() -> None:
    action = yaml.safe_load((ROOT / ".github/actions/setup-rust/action.yml").read_text(encoding="utf-8"))
    cache = next(step for step in action["runs"]["steps"] if step.get("uses", "").startswith("Swatinem/"))
    assert cache["with"]["save-if"] == "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
    assert cache["with"]["cache-workspace-crates"] is True
    assert cache["with"]["cache-bin"] is False
    assert "inputs.targets" in cache["with"]["shared-key"]
    assert action["inputs"]["toolchain"]["default"] == "1.88.0"
    assert "continue-on-error" not in cache


def test_parallel_macos_proofs_use_this_runs_matching_platform_wheel() -> None:
    workflow = _workflow("native-wheel-ci.yml")
    build = workflow["jobs"]["macos-build"]
    proof = workflow["jobs"]["macos"]
    assert proof["needs"] == "macos-build"
    assert {item["target"] for item in build["strategy"]["matrix"]["include"]} == {
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    }
    assert {item["target"] for item in proof["strategy"]["matrix"]["include"]} == {
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    }
    upload = next(step for step in build["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
    download = next(step for step in proof["steps"] if step.get("uses", "").startswith("actions/download-artifact@"))
    assert download["with"] == {"name": upload["with"]["name"]}
    assert "matrix.target" in download["with"]["name"]
    # A failed build/proof may never be turned into a green installed gate.
    for job in (build, proof):
        assert "continue-on-error" not in job
        assert all(not step.get("continue-on-error") for step in job["steps"])
    assert set(proof["strategy"]["matrix"]["proof"]) == {"default", "pi", "extensions", "performance"}


def test_bounded_stress_never_claims_full_soak_qualification() -> None:
    workflow = _workflow("native-wheel-ci.yml")
    assert workflow[True]["schedule"]
    assert "workflow_dispatch" in workflow[True]
    steps = workflow["jobs"]["linux-x64"]["steps"]
    full = next(step for step in steps if "--enforce-soak" in step.get("run", ""))
    smoke = next(step for step in steps if "--json native-stress-smoke.json" in step.get("run", ""))
    assert full["if"] == "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
    assert "--requests 100000" in full["run"]
    assert "--receipts 250000" in full["run"]
    assert "--json native-soak.json" in full["run"]
    assert smoke["if"] == "github.event_name != 'schedule' && github.event_name != 'workflow_dispatch'"
    assert "--enforce-soak" not in smoke["run"]
    assert "native-soak.json" not in smoke["run"]
    provenance = next(step for step in steps if "validate_release_artifacts.py" in step.get("run", ""))
    assert "if" not in provenance


def test_authority_source_and_both_distribution_formats_are_gated_together() -> None:
    workflow = _workflow("rust-authority-ownership.yml")
    calls = [
        step["run"]
        for step in workflow["jobs"]["ownership"]["steps"]
        if "python_capability_cleanup_gate.py" in step.get("run", "")
    ]
    assert len(calls) == 1
    assert '--artifact "$BUILT_WHEEL" --artifact "$BUILT_SDIST"' in calls[0]
    assert "uv build --wheel --sdist" in calls[0]
    assert "--root ." in calls[0]


@pytest.mark.parametrize("name", ["native-wheel-ci.yml", "rust-runtime-windows-resident.yml"])
def test_windows_build_failure_cannot_fall_through_to_a_cached_binary(name: str) -> None:
    for job in _workflow(name)["jobs"].values():
        for step in job.get("steps", []):
            if step.get("shell") != "pwsh":
                continue
            lines = step.get("run", "").splitlines()
            for index, line in enumerate(lines):
                if line.startswith(("cargo ", "rustfmt ")):
                    assert lines[index + 1] == "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
