from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ci" / "pytest_shard.py"
CODEQL_WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"
FUZZ_WORKFLOW = ROOT / ".github" / "workflows" / "fuzz.yml"
sys.path.insert(0, str(SCRIPT_PATH.parent))
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


def test_duration_aware_node_shards_balance_known_and_unknown_nodes() -> None:
    nodes = [f"tests/test_duration.py::test_case_{index}" for index in range(5)]
    durations = {
        pytest_shard.node_id_digest(nodes[0]): 10.0,
        pytest_shard.node_id_digest(nodes[1]): 9.0,
        pytest_shard.node_id_digest(nodes[2]): 1.0,
        pytest_shard.node_id_digest(nodes[3]): 1.0,
    }

    shards = pytest_shard.build_node_shards(nodes, 2, durations)
    estimates = pytest_shard._estimate_node_durations(nodes, durations)
    loads = [sum(estimates[node] for node in shard) for shard in shards]

    assert shards == pytest_shard.build_node_shards(list(reversed(nodes)), 2, durations)
    assert sorted(node for shard in shards for node in shard) == sorted(nodes)
    assert max(loads) - min(loads) <= 1.0


def test_node_shards_reject_duplicate_node_ids() -> None:
    with pytest.raises(ValueError, match="unique"):
        pytest_shard.build_node_shards(["tests/test_a.py::test_case"] * 2, 1)


def test_stale_duration_manifest_falls_back_without_blocking_sharding(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing_manifest = tmp_path / "missing.json.gz"

    assert pytest_shard._load_current_durations(missing_manifest, 28) is None
    assert "equal-weight fallback" in capsys.readouterr().err


def test_unreadable_duration_manifest_falls_back_without_blocking_sharding(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "durations.json.gz"
    monkeypatch.setattr(
        pytest_shard,
        "load_duration_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("permission denied")),
    )

    assert pytest_shard._load_current_durations(manifest, 28) is None
    assert "permission denied" in capsys.readouterr().err


def test_ci_workflow_cancels_stale_runs_and_executes_each_shard() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    tests_job = workflow.split("  tests:\n", maxsplit=1)[1].split("\n  ci-python-312:", maxsplit=1)[0]
    mutation_job = workflow.split("  mutation-baseline:\n", maxsplit=1)[1].split("\n  ci-python-312:", maxsplit=1)[0]

    assert "cancel-in-progress: true" in workflow
    assert "timeout-minutes: 25" in tests_job
    assert workflow.count('version: "0.9.26"') == workflow.count("astral-sh/setup-uv@")
    assert workflow.count("id: setup-uv-primary") == 5
    assert workflow.count("continue-on-error: true") == 5
    assert workflow.count("if: steps.setup-uv-primary.outcome == 'failure'") == 5
    assert "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'" in mutation_job
    assert "timeout-minutes: 8" in mutation_job
    assert "persist-credentials: false" in mutation_job
    assert "mutmut run --max-children 4" in mutation_job
    assert "mutation_gate.py --target command-model" in mutation_job
    assert workflow.count("uv run --no-sync python scripts/ci/pytest_shard.py") == 2
    assert "--shard-count 16" in tests_job
    assert 'python-version: "3.12.13"' in tests_job
    assert "uv sync --frozen --extra dev --python 3.12.13" in tests_job
    assert "--granularity node" in tests_job
    assert "PYTHONPATH=scripts/ci GUARD_PYTEST_DURATION_OUTPUT=pytest-durations.json" in tests_job
    assert "--duration-manifest ci/pytest-duration-manifest.json.gz" in tests_job
    assert "-p pytest_duration_report @pytest-nodes.txt" in tests_job
    assert "Upload pytest duration artifact" in tests_job
    assert "pytest-durations-${{ matrix.shard-index }}" in tests_job
    assert "duration-manifest-candidate:" in workflow
    assert "pytest-duration-manifest-candidate" in workflow
    assert "persist-credentials: false" in workflow
    assert "mapfile -t files" not in workflow
    assert "name: ci (3.12)" in workflow
    assert "needs: [quality, tests, compatibility]" in workflow
    assert "COMPATIBILITY_RESULT" in workflow
    assert "pnpm" not in workflow


def test_ci_validates_and_publishes_test_inventory_before_quality_checks() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "Validate protected test invariants" in workflow
    assert "scripts/ci/test_inventory.py --output test-inventory.json" in workflow
    assert "Publish test inventory" in workflow


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
