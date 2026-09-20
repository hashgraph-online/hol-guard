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
    assert cache["with"]["cache-bin"] is True
    assert "inputs.targets" in cache["with"]["shared-key"]
    # Reuse the existing trusted dependency cache on the first migration PR.
    # A new prefix forces several minutes of cold compilation on macOS Intel.
    assert cache["with"]["prefix-key"] == "v0-rust"
    assert action["inputs"]["cache-key"]["default"] == "native-wheel"
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
def test_windows_build_and_proof_failures_cannot_fall_through(name: str) -> None:
    for job in _workflow(name)["jobs"].values():
        for step in job.get("steps", []):
            if step.get("shell") != "pwsh":
                continue
            lines = step.get("run", "").splitlines()
            if len(lines) == 1:
                continue
            for index, line in enumerate(lines):
                if line.startswith(
                    ("cargo ", "rustfmt ", "uv ", ".venv\\", ".\\rust\\", "rust/target/")
                ) and not line.endswith("`"):
                    assert lines[index + 1] == "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"


@pytest.mark.parametrize(
    ("name", "integration_job", "runner"),
    [
        ("rust-runtime-windows-resident.yml", "windows-resident", "windows-latest"),
        ("rust-daemon-edge-hardening.yml", "cross-platform", "windows-2025"),
    ],
)
def test_parallel_windows_workspace_checks_remain_required(name: str, integration_job: str, runner: str) -> None:
    jobs = _workflow(name)["jobs"]
    checks = jobs["windows-workspace"]
    integration = jobs[integration_job]
    assert checks["runs-on"] == runner
    assert "if" not in checks
    assert "continue-on-error" not in checks
    assert "needs" not in checks
    assert "needs" not in integration
    commands = "\n".join(step.get("run", "") for step in checks["steps"])
    assert "cargo clippy --manifest-path rust/Cargo.toml --locked --workspace --all-targets -- -D warnings" in commands
    assert "cargo test --manifest-path rust/Cargo.toml --locked --workspace --all-targets" in commands
    integration_commands = "\n".join(step.get("run", "") for step in integration["steps"])
    assert "cargo build --manifest-path rust/Cargo.toml --locked --release -p hol-guard-runtime" in integration_commands
    if name == "rust-runtime-windows-resident.yml":
        assert "test_guard_native_runtime_windows_resident.py" in integration_commands
    else:
        assert "test_native_hook_client.py" in integration_commands
        assert "test_native_hook_client_transport.py" in integration_commands
