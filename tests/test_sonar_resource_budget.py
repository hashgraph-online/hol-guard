"""Keep Sonar resource tuning separate from analysis scope and quality gates."""

from __future__ import annotations

import shlex
from pathlib import Path

import yaml

from tests.support.ci_workflow import expand_ci_job_actions

ROOT = Path(__file__).resolve().parents[1]


def test_sonar_analysis_uses_bounded_resources_only_in_its_dedicated_job() -> None:
    """Use all four public-runner CPUs without changing the runner cost or scan scope."""
    workflow = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")))
    job = workflow["jobs"]["sonar"]
    scan = next(step for step in job["steps"] if step.get("name") == "Analyze with SonarQube Cloud")

    assert job["runs-on"] == "ubuntu-latest"
    assert "needs" not in job
    assert shlex.split(scan["with"]["args"]) == ["-Dsonar.python.analysis.threads=4"]
    assert shlex.split(scan["env"]["SONAR_SCANNER_JAVA_OPTS"]) == ["-Xmx6g"]
    assert "SONAR_SCANNER_JAVA_OPTS" not in workflow.get("env", {})
    assert "SONAR_SCANNER_JAVA_OPTS" not in job.get("env", {})
    assert not scan.get("continue-on-error", False)
    assert scan["if"] == "steps.token-presence.outputs.has-token == 'true'"


def test_resource_tuning_keeps_current_attempt_coverage_and_quality_gate() -> None:
    """The tuned scanner still follows complete coverage and precedes a blocking gate."""
    workflow = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")))
    job = workflow["jobs"]["sonar"]
    steps = job["steps"]
    names = [step.get("name", "") for step in steps]
    ordered = [
        "Wait for successful pytest coverage producers",
        "Download pytest coverage data",
        "Prepare Python coverage",
        "Analyze with SonarQube Cloud",
        "SonarQube Quality Gate check",
    ]
    indices = [names.index(name) for name in ordered]
    assert indices == sorted(indices)
    download = steps[indices[1]]
    assert download["with"]["pattern"] == "pytest-coverage-${{ github.run_attempt }}-*"
    for index in indices:
        assert not steps[index].get("continue-on-error", False)
        assert steps[index]["if"] == "steps.token-presence.outputs.has-token == 'true'"
    assert job["permissions"] == {"contents": "read", "actions": "read"}
    assert not job.get("continue-on-error", False)
    assert len(workflow["jobs"]["coverage"]["strategy"]["matrix"]["shard-index"]) == 128


def test_resource_tuning_leaves_python_rust_and_coverage_sources_enabled() -> None:
    """Resource tuning must not become a shortcut around source or coverage analysis."""
    properties = dict(
        line.split("=", 1)
        for line in (ROOT / "sonar-project.properties").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    assert properties["sonar.sources"] == "src,rust"
    assert properties["sonar.tests"] == "tests,rust"
    assert properties["sonar.rust.cargo.manifestPaths"] == "rust/Cargo.toml"
    assert properties["sonar.python.coverage.reportPaths"] == "coverage-reports/coverage-*.xml"
