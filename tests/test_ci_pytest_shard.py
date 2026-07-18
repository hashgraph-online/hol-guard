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


def test_ci_workflow_cancels_stale_runs_and_executes_each_shard() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "cancel-in-progress: true" in workflow
    assert "timeout-minutes: 15" in workflow
    assert "python scripts/ci/pytest_shard.py" in workflow
    assert "shard-index: [0, 1, 2, 3]" in workflow
