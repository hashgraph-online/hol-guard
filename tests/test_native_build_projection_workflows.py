"""Native Python proofs must use the catalog compiled into their own runtime."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from scripts.ci import verify_native_command_program as verifier
from tests.support.ci_workflow import expand_ci_job_actions

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
    """Verify native Python proofs stage matching resources."""
    workflow = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows" / name).read_text()))
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
    """Verify windows verifier resolves the existing compiler suffix."""
    # This test mocks compilation, so it must not export into the runner environment.
    monkeypatch.delenv("GITHUB_ENV", raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", argument])
    calls = []
    monkeypatch.setattr(verifier, "_run", calls.append)
    assert verifier.main() == 0
    expected = argument if argument.endswith(".exe") else argument + ".exe"
    assert calls[0][-1] == expected
    assert calls[1] == [*calls[0], "--check"]


def test_dependency_setup_does_not_compile_projections_in_each_coverage_shard() -> None:
    """The native producer builds once; coverage consumers download matching outputs."""
    action = yaml.safe_load((ROOT / ".github/actions/setup-ci-python/action.yml").read_text())
    assert all("stage-command-projections" not in step.get("uses", "") for step in action["runs"]["steps"])
    assert all("build_native_command_program.py" not in step.get("run", "") for step in action["runs"]["steps"])
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["coverage"]["steps"]
    download = next(
        index
        for index, step in enumerate(steps)
        if step.get("with", {}).get("name") == "pytest-native-command-projections"
    )
    tests = next(index for index, step in enumerate(steps) if "run_projection_shard.py" in step.get("run", ""))
    assert download < tests


@pytest.mark.parametrize("name", ["mdm-local-lab.yml", "mdm-artifacts.yml"])
def test_mdm_labs_generate_resources_before_indirect_test_collection(name: str) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
    steps = workflow["jobs"].get("conformance", workflow["jobs"].get("tests"))["steps"]
    prepare = next(
        index for index, step in enumerate(steps) if step.get("uses") == "./.github/actions/stage-command-projections"
    )
    collect = next(index for index, step in enumerate(steps) if "scripts/mdm/run-local-lab.py" in step.get("run", ""))
    assert prepare < collect


def test_native_identity_watches_production_inputs_not_the_whole_test_tree() -> None:
    """Verify native identity watches production inputs not the whole test tree."""
    identity = (ROOT / "rust/build_support/command_identity.rs").read_text()
    assert 'root.join("crates").display()' not in identity
    assert 'collect(&directory.join("src"), &mut files)' in identity
    assert 'root.join("Cargo.lock")' in identity
    assert 'root.join("Cargo.toml")' in identity
    assert 'println!("cargo:rerun-if-changed={}", directory.display())' in identity


def test_source_only_acceptance_runs_on_main_and_pull_requests() -> None:
    """Verify source only acceptance runs on main and pull requests."""
    workflow = expand_ci_job_actions(
        yaml.safe_load((ROOT / ".github/workflows/extension-fixture-isolation.yml").read_text())
    )
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


@pytest.mark.parametrize("name", ["guard-command-source", "guard-command-source.exe"])
def test_acceptance_packaging_uses_its_own_compiler_without_exporting_to_parent(monkeypatch, tmp_path, name):
    """A changed acceptance checkout must never reuse the parent checkout's compiler."""
    import os

    from scripts.ci.check_extension_fixture_isolation import acceptance_environment

    root = tmp_path / "isolated checkout"
    target = tmp_path / "isolated target"
    compiler = target / "debug" / name
    parent_environment = tmp_path / "parent-github-env"
    parent_environment.write_text("EXISTING=value\n")
    monkeypatch.setenv("GITHUB_ENV", str(parent_environment))
    monkeypatch.setenv("HOL_GUARD_BUILD_SOURCE_COMPILER", "/parent/checkout/compiler")
    monkeypatch.setenv("CARGO_TARGET_DIR", "/parent/checkout/target")
    env = acceptance_environment(root, target, compiler)
    assert env["HOL_GUARD_BUILD_SOURCE_COMPILER"] == str(compiler)
    assert env["CARGO_TARGET_DIR"] == str(target)
    assert env["PYTHONPATH"] == os.pathsep.join((str(root / "src"), str(root)))
    assert "GITHUB_ENV" not in env
    assert os.environ["GITHUB_ENV"] == str(parent_environment)
    assert os.environ["HOL_GUARD_BUILD_SOURCE_COMPILER"] == "/parent/checkout/compiler"
    assert parent_environment.read_text() == "EXISTING=value\n"


@pytest.mark.parametrize(
    ("workflow_name", "job_name", "test_command"),
    [
        ("mdm-local-lab.yml", "conformance", "scripts/mdm/run-local-lab.py"),
        ("guard-gauntlet-gate.yml", "contracts", "pytest"),
        ("guard-gauntlet-evidence.yml", "contracts", "pytest"),
    ],
)
def test_standalone_contract_jobs_stage_resources_before_test_imports(workflow_name, job_name, test_command):
    """Local lab and evidence-judge imports require the same compiled package resources."""
    workflow = yaml.safe_load((ROOT / ".github/workflows" / workflow_name).read_text())
    steps = workflow["jobs"][job_name]["steps"]
    stage = next(i for i, step in enumerate(steps) if step.get("uses") == "./.github/actions/stage-command-projections")
    test = next(i for i, step in enumerate(steps) if test_command in step.get("run", ""))
    assert stage < test
    assert not steps[stage].get("continue-on-error")
    assert "if" not in steps[stage]
