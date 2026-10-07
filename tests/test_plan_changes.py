"""Tests for scripts/ci/plan_changes.py lane classification.

The planner's only safety property is conservative escalation: a diff the fast
data lane cannot safely cover must select the full lane. These tests pin that
contract, including the adversarial cases a malicious or careless PR could use to
try to skip protection.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.ci.plan_changes import LANE_DATA, LANE_FULL, plan

ROOT = Path(__file__).resolve().parents[1]


def _commit(root: Path, message: str) -> str:
    subprocess.run(
        ["git", "-C", str(root), "commit", "--allow-empty", "-qm", message],
        check=True,
    )
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "t"], check=True)
    return root


def _write(root: Path, rel: str, body: str = "x") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    subprocess.run(["git", "-C", str(root), "add", rel], check=True)


def test_contribution_source_only_selects_data_lane(repo: Path) -> None:
    _write(repo, "contributions/extensions/command.foo.json")
    base = _commit(repo, "base")
    _write(repo, "contributions/extensions/command.bar.json")
    head = _commit(repo, "add ext")
    result = plan(base, head, root=repo)
    assert result.lanes == [LANE_DATA]
    assert result.data_only is True


def test_workflow_change_escalates_to_full(repo: Path) -> None:
    _write(repo, "contributions/extensions/command.foo.json")
    base = _commit(repo, "base")
    _write(repo, ".github/workflows/ci.yml")
    head = _commit(repo, "edit workflow")
    result = plan(base, head, root=repo)
    assert result.lanes == [LANE_FULL]
    assert result.data_only is False


def test_data_plus_code_mix_escalates(repo: Path) -> None:
    _write(repo, "contributions/extensions/command.foo.json")
    _write(repo, "src/codex_plugin_scanner/x.py")
    base = _commit(repo, "base")
    _write(repo, "contributions/extensions/command.bar.json")
    _write(repo, "src/codex_plugin_scanner/y.py")
    head = _commit(repo, "mixed")
    result = plan(base, head, root=repo)
    assert result.lanes == [LANE_FULL]


def test_trust_contract_escalates(repo: Path) -> None:
    _write(repo, "contracts/extensions/trust-class-map.v1.json")
    base = _commit(repo, "base")
    _write(repo, "contracts/extensions/trust-class-map.v1.json", "{}")
    head = _commit(repo, "trust change")
    result = plan(base, head, root=repo)
    assert result.lanes == [LANE_FULL]


def test_python_test_change_escalates(repo: Path) -> None:
    _write(repo, "tests/test_guard_x.py")
    base = _commit(repo, "base")
    _write(repo, "tests/test_guard_y.py")
    head = _commit(repo, "test change")
    result = plan(base, head, root=repo)
    assert result.lanes == [LANE_FULL]


def test_empty_diff_escalates(repo: Path) -> None:
    # An empty or ambiguous diff must never hand out the cheap lane blind.
    _write(repo, "README.md")
    base = _commit(repo, "base")
    head = base
    result = plan(base, head, root=repo)
    assert result.lanes == [LANE_FULL]
    assert result.escalate_reason == "empty-diff"


def test_lockfile_escalates(repo: Path) -> None:
    _write(repo, "contributions/extensions/command.foo.json")
    _write(repo, "uv.lock")
    base = _commit(repo, "base")
    _write(repo, "contributions/extensions/command.bar.json")
    _write(repo, "uv.lock", "updated")
    head = _commit(repo, "dep bump")
    result = plan(base, head, root=repo)
    assert result.lanes == [LANE_FULL]


def test_authority_catalog_escalates(repo: Path) -> None:
    # Generated/packaging/activation surfaces under contracts/extensions/ are
    # authority-bearing: they always take the full lane even inside a data diff.
    _write(repo, "contributions/extensions/command.foo.json")
    _write(repo, "contracts/extensions/command-catalog.v1.json")
    base = _commit(repo, "base")
    _write(repo, "contributions/extensions/command.bar.json")
    _write(repo, "contracts/extensions/command-catalog.v1.json", "{}")
    head = _commit(repo, "catalog churn")
    result = plan(base, head, root=repo)
    assert result.lanes == [LANE_FULL]


def test_symlink_escalates(repo: Path) -> None:
    # A symlink under a data path must not ride the cheap lane.
    _write(repo, "contributions/extensions/command.foo.json")
    base = _commit(repo, "base")
    (repo / "contributions/extensions/command.link.json").symlink_to("command.foo.json")
    subprocess.run(["git", "-C", str(repo), "add", "contributions/extensions/command.link.json"], check=True)
    head = _commit(repo, "symlink")
    result = plan(base, head, root=repo)
    assert result.lanes == [LANE_FULL]
    assert "unsafe-file-mode" in result.escalate_reason
