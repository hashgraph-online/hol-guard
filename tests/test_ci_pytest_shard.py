from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ci" / "pytest_shard.py"
CODEQL_WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"
FUZZ_WORKFLOW = ROOT / ".github" / "workflows" / "fuzz.yml"
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


def test_node_shards_split_large_files_without_overlap() -> None:
    nodes = [f"tests/test_large.py::test_case_{index}" for index in range(40)]
    shards = pytest_shard.build_node_shards(nodes, 16)

    assert shards == pytest_shard.build_node_shards(list(reversed(nodes)), 16)
    assert all(shards)
    assert sorted(node for shard in shards for node in shard) == sorted(nodes)
    assert max(map(len, shards)) - min(map(len, shards)) <= 1


def test_ci_workflow_cancels_stale_runs_and_executes_each_shard() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    tests_job = workflow.split("  tests:\n", maxsplit=1)[1].split("\n  ci-python-312:", maxsplit=1)[0]

    assert "cancel-in-progress: true" in workflow
    assert "timeout-minutes: 25" in tests_job
    assert workflow.count('version: "0.9.26"') == workflow.count("astral-sh/setup-uv@")
    assert workflow.count("id: setup-uv-primary") == 5
    assert workflow.count("continue-on-error: true") == 5
    assert workflow.count("if: steps.setup-uv-primary.outcome == 'failure'") == 5
    assert workflow.count("astral-sh/setup-uv@") == 12
    assert workflow.count("uv run --no-sync python scripts/ci/pytest_shard.py") == 2
    assert "--shard-count 16" in tests_job
    assert "--granularity node" in tests_job
    assert "name: ci (3.12)" in workflow
    assert "needs: [quality, tests, compatibility]" in workflow
    assert "COMPATIBILITY_RESULT" in workflow
    assert "pnpm" not in workflow


def test_expensive_security_workflows_fit_the_pr_feedback_budget() -> None:
    codeql = CODEQL_WORKFLOW.read_text(encoding="utf-8")
    fuzz = FUZZ_WORKFLOW.read_text(encoding="utf-8")
    codeql_config = yaml.safe_load(codeql)

    assert codeql_config[True]["push"]["branches"] == ["main"]
    assert "group: codeql-${{ github.event.pull_request.number || github.ref }}" in codeql
    assert "cancel-in-progress: true" in codeql
    assert "fuzz-seconds: 60" in fuzz
    assert "fuzz-seconds: 600" not in fuzz
    assert "group: fuzz-${{ github.event.pull_request.number || github.ref }}" in fuzz
