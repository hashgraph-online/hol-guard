from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.ci.build_pytest_shard_plan import SCHEDULING_ONLY_NODE_IDS

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ci" / "pytest_shard.py"
SCHEDULING_SENSITIVE_NODE = (
    "tests/test_guard_hook_process_runner.py::"
    "test_scheduler_and_runner_complete_48_routine_reviews_without_capacity_denial"
)
STORAGE_LIVENESS_NODE = (
    "tests/test_guard_daemon_storage_liveness.py::test_locked_storage_hook_burst_fails_safe_without_stranding_daemon"
)
SPEC = importlib.util.spec_from_file_location("pytest_shard", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
pytest_shard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pytest_shard)


def test_ci_shards_cover_every_test_file_once_and_deterministically() -> None:
    expected = pytest_shard.discover_test_files(ROOT)
    shards = pytest_shard.build_test_shards(ROOT, 4)

    assert shards == pytest_shard.build_test_shards(ROOT, 4)
    assert all(shards)
    assert sorted(path for shard in shards for path in shard) == expected
    assert sum(len(shard) for shard in shards) == len(set().union(*map(set, shards)))


def _workflow_job(workflow: str, job_name: str, next_job_name: str | None) -> str:
    section = workflow.split(f"  {job_name}:\n", maxsplit=1)[1]
    if next_job_name is not None:
        section = section.split(f"\n  {next_job_name}:", maxsplit=1)[0]
    return section


def test_ci_workflow_cancels_stale_runs_and_uses_precomputed_affinity_shards() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    payload = yaml.safe_load(workflow)
    jobs = payload["jobs"]
    plan_action = yaml.safe_load((ROOT / ".github/actions/plan-pytest/action.yml").read_text())
    plan_steps = plan_action["runs"]["steps"]
    collector = next(step["run"] for step in plan_steps if "build_pytest_shard_plan.py" in step.get("run", ""))
    assert "cancel-in-progress: true" in workflow
    assert "CI_UV_CACHE_DEPENDENCY_GLOB" in workflow
    assert "actions: read" in workflow
    assert "**/pyproject.toml" not in workflow
    assert '--shard-count "$CI_PLAN_SHARD_COUNT"' in collector
    assert "--ignore" not in collector
    assert "--deselect" not in collector
    assert payload["env"]["CI_PYTHON_VERSION"] == "3.12.14"
    assert payload["env"]["CI_COVERAGE_PYTHON_VERSION"] == "3.14.7"

    for planner, executor, version, env_name, count, width in (
        ("test-plan", "tests", "3.12", "CI_PYTHON_VERSION", 32, 2),
        ("coverage-plan", "coverage", "3.14", "CI_COVERAGE_PYTHON_VERSION", 128, 3),
    ):
        plan_job = jobs[planner]
        execution_job = jobs[executor]
        assert execution_job["needs"] == planner
        assert execution_job["strategy"]["matrix"]["shard-index"] == list(range(count))
        for job in (plan_job, execution_job):
            setup = next(step for step in job["steps"] if step.get("uses") == "./.github/actions/setup-ci-python")
            assert setup["with"]["python-version"] == "${{ env." + env_name + " }}"
        plan = next(step for step in plan_job["steps"] if step.get("uses") == "./.github/actions/plan-pytest")
        assert plan["with"]["python-version"] == version
        assert plan["with"]["shard-count"] == str(count)
        download = next(
            step for step in execution_job["steps"] if step.get("uses", "").startswith("actions/download-artifact@")
        )
        assert download["with"]["name"] == f"pytest-shard-plan-{version}"
        commands = "\n".join(step.get("run", "") for step in execution_job["steps"])
        assert f"shard-%0{width}d.txt" in commands
        assert "python scripts/ci/pytest_shard.py" not in commands
        assert "--ignore" not in commands
        assert '"@$shard_file"' in commands

    tests_job = _workflow_job(workflow, "tests", "coverage")
    coverage_job = _workflow_job(workflow, "coverage", "duration-manifest-candidate")
    scheduling_job = _workflow_job(workflow, "scheduling-sensitive", "compatibility")
    assert "--cov" not in tests_job
    assert "GUARD_PYTEST_UNDER_COVERAGE" not in tests_job
    assert "--cov --cov-branch --cov-report=" in coverage_job
    assert "COVERAGE_CORE: sysmon" in coverage_job
    assert "-p pytest_coverage_core" in coverage_job
    assert jobs["coverage"]["name"] == "coverage (3.14, ${{ matrix.shard-index }})"
    assert set(jobs["compatibility"]["strategy"]["matrix"]["python-version"]) == {"3.10", "3.11", "3.13", "3.14"}
    for node in (SCHEDULING_SENSITIVE_NODE, STORAGE_LIVENESS_NODE):
        assert f"--deselect {node}" in coverage_job
        assert node in scheduling_job
    assert coverage_job.count("--deselect ") == 2
    assert {SCHEDULING_SENSITIVE_NODE, STORAGE_LIVENESS_NODE} == SCHEDULING_ONLY_NODE_IDS
    assert "--cov" not in scheduling_job

    candidate = jobs["duration-manifest-candidate"]
    assert candidate["needs"] == "coverage"
    assert candidate["if"] == "needs.coverage.result == 'success'"
    assert 'test "${#reports[@]}" -eq 128' in "\n".join(step.get("run", "") for step in candidate["steps"])
    sonar_job = _workflow_job(workflow, "sonar", "scheduling-sensitive")
    assert "bash scripts/ci/prepare_sonar_analysis.sh" in sonar_job
    sonar_setup = (ROOT / "scripts/ci/prepare_sonar_analysis.sh").read_text(encoding="utf-8")
    assert 'test "${#reports[@]}" -eq 128' in sonar_setup
    assert "vars.SONAR_CI_ENABLED == 'true'" in sonar_job
    gate = jobs["ci-python-312"]
    assert gate["name"] == "ci (3.12)"
    assert gate["if"] == "always()"
    assert set(gate["needs"]) == {
        "quality",
        "test-plan",
        "tests",
        "coverage-plan",
        "coverage",
        "compatibility",
        "scheduling-sensitive",
    }

    cache_consumers = (
        ("compatibility", "deep-compatibility", 1),
        ("deep-compatibility", "mutation-baseline", 1),
        ("mutation-baseline", "ci-python-312", 1),
        ("cross-platform", "windows-updater", 2),
        ("windows-updater", None, 2),
    )
    for job_name, next_job_name, expected_count in cache_consumers:
        job = _workflow_job(workflow, job_name, next_job_name)
        assert job.count("save-cache: false") >= expected_count


@pytest.mark.parametrize(
    "failed_dependency", ["TEST_PLAN_RESULT", "TESTS_RESULT", "COVERAGE_PLAN_RESULT", "COVERAGE_RESULT"]
)
@pytest.mark.parametrize("result", ["failure", "skipped", "cancelled"])
def test_required_python_gate_rejects_either_incomplete_suite(failed_dependency: str, result: str) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    step = workflow["jobs"]["ci-python-312"]["steps"][0]
    env = dict(os.environ, **dict.fromkeys(step["env"], "success"))
    env[failed_dependency] = result

    completed = subprocess.run(["bash", "-e", "-c", step["run"]], env=env, capture_output=True, check=False)

    assert completed.returncode != 0


def test_sonar_scope_includes_native_rust_workspace() -> None:
    config = (ROOT / "sonar-project.properties").read_text(encoding="utf-8")
    properties = dict(
        line.split("=", 1) for line in config.splitlines() if line and not line.startswith("#") and "=" in line
    )

    assert properties["sonar.sources"] == "src,rust"
    assert properties["sonar.tests"] == "tests,rust"
    assert properties["sonar.test.inclusions"] == (
        "**/test_*.py,rust/**/tests/**/*.rs,rust/**/*_tests.rs,"
        "rust/crates/guard-command/testdata/generate_*_fixtures.py"
    )
    assert properties["sonar.rust.cargo.manifestPaths"] == "rust/Cargo.toml"
    assert "src/codex_plugin_scanner/guard/daemon/static/**" in properties["sonar.exclusions"]
    assert "rust/**/tests/**" in properties["sonar.exclusions"]
    assert "rust/**/*_tests.rs" in properties["sonar.exclusions"]
    assert "src/codex_plugin_scanner/guard/daemon/static/**" in properties["sonar.cpd.exclusions"]
    assert "tests/**" in properties["sonar.cpd.exclusions"]
    assert "rust/**/tests/**" in properties["sonar.cpd.exclusions"]
    assert "rust/**/*_tests.rs" in properties["sonar.cpd.exclusions"]
