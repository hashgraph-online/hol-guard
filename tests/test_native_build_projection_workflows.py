"""Native Python proofs must use the catalog compiled into their own runtime."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from scripts.ci import verify_native_command_program as verifier

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    "cline-contract-ci.yml",
    "rust-authority-ownership.yml",
    "rust-command-model-differential.yml",
    "rust-command-shadow.yml",
    "rust-daemon-edge-hardening.yml",
    "rust-posttool-authority-acceptance.yml",
    "rust-pretool-adversarial.yml",
    "rust-pretool-authority-acceptance.yml",
    "rust-runtime-differential.yml",
    "rust-runtime-mutation-differential.yml",
    "rust-runtime-performance.yml",
    "rust-runtime-recovery.yml",
    "rust-runtime-rule-contract.yml",
    "rust-runtime-windows-resident.yml",
    "rust-runtime.yml",
)


@pytest.mark.parametrize("name", WORKFLOWS)
def test_native_python_proofs_stage_matching_resources(name: str) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
    observed = 0
    for job in workflow["jobs"].values():
        steps = job.get("steps", [])
        for index, step in enumerate(steps):
            script = step.get("run", "")
            builds = [line for line in script.splitlines() if "cargo build --manifest-path rust/Cargo.toml" in line]
            builds = [line for line in builds if "-p hol-guard-runtime" in line]
            if not builds:
                continue
            observed += 1
            assert len(builds) == 1
            assert "-p guard-command" in builds[0]
            assert "--bin guard-command-source" in builds[0]
            later = "\n".join(item.get("run", "") for item in steps[index:])
            assert "scripts/ci/verify_native_command_program.py --compiler" in later
            before_proof = later.split("pytest", 1)[0]
            assert "verify_native_command_program.py" in before_proof
            assert "continue-on-error" not in step
    assert observed >= 1


@pytest.mark.parametrize("argument", ["rust/target/release/guard-command-source", "compiler.exe"])
def test_windows_verifier_resolves_the_existing_compiler_suffix(monkeypatch, argument: str) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", argument])
    calls = []
    monkeypatch.setattr(verifier, "_run", calls.append)
    assert verifier.main() == 0
    expected = argument if argument.endswith(".exe") else argument + ".exe"
    assert calls[0][-1] == expected
    assert calls[1] == [*calls[0], "--check"]


def test_native_identity_watches_production_inputs_not_the_whole_test_tree() -> None:
    identity = (ROOT / "rust/build_support/command_identity.rs").read_text()
    assert 'root.join("crates").display()' not in identity
    assert 'collect(&directory.join("src"), &mut files)' in identity
    assert 'root.join("Cargo.lock")' in identity
    assert 'root.join("Cargo.toml")' in identity
    assert 'println!("cargo:rerun-if-changed={}", directory.display())' in identity


def test_source_only_acceptance_runs_on_main_and_pull_requests() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/extension-fixture-isolation.yml").read_text())
    events = workflow.get("on", workflow.get(True))
    assert "pull_request" in events and events["push"]["branches"] == ["main"]
    job = workflow["jobs"]["source-only-acceptance"]
    assert "continue-on-error" not in job
    acceptance = next(
        step
        for step in job["steps"]
        if "check_extension_fixture_isolation.py" in step.get("run", "") and "--output" in step["run"]
    )
    assert "continue-on-error" not in acceptance and "if" not in acceptance
