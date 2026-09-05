from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ci" / "pytest_shard.py"
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
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    plan_job = _workflow_job(workflow, "test-plan", "tests")
    tests_job = _workflow_job(workflow, "tests", "duration-manifest-candidate")
    sonar_job = _workflow_job(workflow, "sonar", "scheduling-sensitive")

    assert "cancel-in-progress: true" in workflow
    assert "CI_UV_CACHE_DEPENDENCY_GLOB" in workflow
    assert "actions: read" in workflow
    assert "**/pyproject.toml" not in workflow
    assert "--shard-count 96" in plan_job
    assert "build_pytest_shard_plan.py" in plan_job
    assert "Restore latest trusted duration telemetry" in plan_job
    assert '.workflow_run.head_branch == "release/3.0"' in plan_job
    assert 'test "$event" = "push"' in plan_job
    assert 'test "$conclusion" = "success"' in plan_job
    assert 'test "$branch" = "release/3.0"' in plan_job
    assert 'test "$workflow_path" = ".github/workflows/ci.yml"' in plan_job
    assert "needs: test-plan" in tests_job
    assert "name: pytest-shard-plan" in tests_job
    assert "shard-%02d.txt" in tests_job
    assert "python scripts/ci/pytest_shard.py" not in tests_job
    assert 'test "${#reports[@]}" -eq 96' in workflow
    assert "vars.SONAR_CI_ENABLED == 'true'" in sonar_job
    assert "name: ci (3.12)" in workflow
    assert "needs: [quality, test-plan, tests, compatibility, scheduling-sensitive]" in workflow

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


def test_sonar_scope_includes_native_rust_workspace() -> None:
    config = (ROOT / "sonar-project.properties").read_text(encoding="utf-8")
    properties = dict(
        line.split("=", 1)
        for line in config.splitlines()
        if line and not line.startswith("#") and "=" in line
    )

    assert properties["sonar.sources"] == "src,rust"
    assert properties["sonar.tests"] == "tests,rust"
    assert properties["sonar.test.inclusions"] == (
        "**/test_*.py,rust/**/tests/**/*.rs,rust/**/*_tests.rs"
    )
    assert properties["sonar.rust.cargo.manifestPaths"] == "rust/Cargo.toml"
    assert "src/codex_plugin_scanner/guard/daemon/static/**" in properties["sonar.exclusions"]
    assert "rust/**/tests/**" in properties["sonar.exclusions"]
    assert "rust/**/*_tests.rs" in properties["sonar.exclusions"]
    assert "src/codex_plugin_scanner/guard/daemon/static/**" in properties["sonar.cpd.exclusions"]
    assert "tests/**" in properties["sonar.cpd.exclusions"]
    assert "rust/**/tests/**" in properties["sonar.cpd.exclusions"]
    assert "rust/**/*_tests.rs" in properties["sonar.cpd.exclusions"]
