"""Test workers retain their tools without downloading the type-checker runtime."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]


def test_ci_group_preserves_dev_tools_except_the_type_checker() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dev = project["project"]["optional-dependencies"]["dev"]
    group = project["dependency-groups"]["ci-test"]
    assert set(group) == {requirement for requirement in dev if not requirement.startswith("basedpyright")}
    assert any(requirement.startswith("basedpyright") for requirement in dev)
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    package = next(package for package in lock["package"] if package["name"] == "hol-guard")
    assert {item["name"] for item in package["dev-dependencies"]["ci-test"]} == {
        "build",
        "pytest",
        "pytest-cov",
        "ruff",
    }


def test_test_workers_select_the_frozen_group_without_default_dev_dependencies() -> None:
    for filename in ("setup-ci-python", "native-regression"):
        action = yaml.safe_load((ROOT / f".github/actions/{filename}/action.yml").read_text())
        commands = "\n".join(step.get("run", "") for step in action["runs"]["steps"])
        assert "uv sync --frozen --no-dev --group ci-test" in commands
        assert "--extra dev" not in commands
    workflow = yaml.safe_load((ROOT / ".github/workflows/native-wheel-ci.yml").read_text())
    for job in ("wheel-contracts", "linux-build", "linux-proof", "windows-build", "windows-proof"):
        commands = "\n".join(step.get("run", "") for step in workflow["jobs"][job]["steps"])
        assert "uv sync --frozen --no-dev --group ci-test" in commands
    proof_setup = (ROOT / "scripts/ci/install-native-proof-dependencies.sh").read_text()
    assert "extras=(--group ci-test)" in proof_setup
    assert "--frozen --no-dev --no-install-project" in proof_setup


@pytest.mark.parametrize("job", ["compatibility", "deep-compatibility", "cross-platform", "windows-updater"])
def test_compatibility_workers_select_the_frozen_test_group(job: str) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    commands = "\n".join(step.get("run", "") for step in workflow["jobs"][job]["steps"])
    assert "uv sync --frozen --no-dev --group ci-test --python ${{ matrix.python-version }}" in commands
    assert "--extra dev" not in commands
    assert "uv run --no-sync pytest" in commands


def test_reporting_and_optional_workers_preserve_their_dependency_boundaries() -> None:
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    commands = {name: "\n".join(step.get("run", "") for step in job["steps"]) for name, job in jobs.items()}
    assert "uv sync --frozen --no-dev --group ci-test --python ${{ env.CI_PYTHON_VERSION }}" in commands["sonar"]
    assert (
        "uv sync --frozen --no-dev --group ci-test --extra cisco --group cisco-mcp --python 3.13"
        in commands["cisco-full"]
    )
    assert "uv sync --frozen --no-dev --group ci-test --extra mdm-build" in commands["cross-platform"]
    assert "uv sync --frozen --extra dev" in commands["quality"]
    assert "uv sync --frozen --extra dev" in commands["mutation-baseline"]


def test_staged_evaluator_wheel_selects_test_tools_without_installing_the_source_project() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/evaluation-wheel-ci.yml").read_text())
    commands = "\n".join(step.get("run", "") for step in workflow["jobs"]["staged-evaluator-wheel"]["steps"])
    assert "uv sync --frozen --no-dev --group ci-test --no-install-project --python 3.12" in commands
    assert "--extra dev" not in commands
    assert "uv build --wheel" in commands
    assert "--no-deps evaluation-dist/*.whl" in commands


def test_coverage_cache_keeps_prebuilt_wheels_for_read_only_workers() -> None:
    action = yaml.safe_load((ROOT / ".github/actions/setup-ci-python/action.yml").read_text())
    uv_steps = [step for step in action["runs"]["steps"] if step.get("uses", "").startswith("astral-sh/setup-uv@")]
    assert len(uv_steps) == 2
    assert all(step["with"]["prune-cache"] is False for step in uv_steps)
    assert all(step["with"]["save-cache"] == "${{ inputs.save-cache }}" for step in uv_steps)
    assert action["inputs"]["save-cache"]["default"] == "false"
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    producer = next(
        step for step in jobs["coverage-plan"]["steps"] if step.get("uses") == "./.github/actions/setup-ci-python"
    )
    consumer = next(
        step for step in jobs["coverage"]["steps"] if step.get("uses") == "./.github/actions/setup-ci-python"
    )
    assert producer["with"]["save-cache"] == "true"
    assert consumer["with"].get("save-cache", "false") == "false"
    assert producer["with"]["python-version"] == consumer["with"]["python-version"]
    assert producer["with"]["cache-dependency-glob"] == consumer["with"]["cache-dependency-glob"]
    assert "coverage-plan" in jobs["coverage"]["needs"]


@pytest.mark.skipif(os.name == "nt", reason="macOS proof setup executes in Bash")
@pytest.mark.parametrize("proof", ["default", "pi", "extensions", "performance"])
def test_macos_proof_setup_preserves_its_dependency_boundary(tmp_path: Path, proof: str) -> None:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    uv = binaries / "uv"
    uv.write_text(f"#!{sys.executable}\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n")
    uv.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/ci/install-native-proof-dependencies.sh")],
        cwd=tmp_path,
        env={**os.environ, "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}", "NATIVE_PROOF": proof},
        text=True,
        capture_output=True,
        check=True,
        timeout=10,
    )
    expected = ["sync", "--frozen", "--no-dev", "--no-install-project", "--python", "3.12"]
    if proof == "extensions":
        expected += ["--group", "ci-test"]
    assert json.loads(result.stdout) == expected
