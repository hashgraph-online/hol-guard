"""Narrow Git fetches must preserve trusted comparisons and complete analysis history."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.ci.plan_changes import plan
from scripts.ci.pr_merge_base import comparison_base

ROOT = Path(__file__).resolve().parents[1]
FETCH_HISTORY = ROOT / "scripts/ci/fetch_analysis_history.sh"


def git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *arguments], text=True, timeout=30).strip()


def commit(root: Path, path: str, content: str) -> str:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    git(root, "add", path)
    git(root, "commit", "-qm", path)
    return git(root, "rev-parse", "HEAD")


@pytest.fixture
def history(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    origin = tmp_path / "origin"
    origin.mkdir()
    git(origin, "init", "-q", "-b", "main")
    git(origin, "config", "user.name", "CI regression")
    git(origin, "config", "user.email", "ci@example.invalid")
    git(origin, "config", "commit.gpgsign", "false")
    root = commit(origin, "module.py", "VALUE = 1\n")
    commit(origin, "scripts/ci/plan_changes.py", "TRUSTED = True\n")
    for index in range(4):
        common = commit(origin, "history.txt", f"{index}\n")
    git(origin, "checkout", "-qb", "contributor")
    commit(origin, "module.py", "VALUE = 2\n")
    head = commit(origin, "scripts/ci/plan_changes.py", "TRUSTED = False\n")
    git(origin, "checkout", "-q", "main")
    for index in range(3):
        base = commit(origin, "main.txt", f"{index}\n")
    git(origin, "checkout", "-qb", "unrelated", root)
    unrelated = commit(origin, "unrelated.txt", "Not needed for the analyzed revision.\n")
    git(origin, "tag", "unrelated-tag")
    git(origin, "checkout", "-q", "main")
    return origin, common, base, head, unrelated


@pytest.mark.parametrize("source", ["main", "contributor"])
@pytest.mark.parametrize("initial_depth", [1, None])
def test_analysis_fetch_preserves_blame_and_merge_base_without_unrelated_refs(history, tmp_path, source, initial_depth):
    origin, common, base, head, unrelated = history
    sha = base if source == "main" else head
    control, candidate = tmp_path / "control", tmp_path / "candidate"
    git(tmp_path, "clone", "-q", origin.as_uri(), str(control))
    git(control, "checkout", "-q", sha)
    arguments = ["clone", "-q", "--no-tags", "--single-branch", "--branch", source]
    if initial_depth:
        arguments += ["--depth", str(initial_depth)]
    git(tmp_path, *arguments, origin.as_uri(), str(candidate))
    subprocess.run(
        ["bash", str(FETCH_HISTORY)],
        cwd=candidate,
        env={**os.environ, "GITHUB_SHA": sha},
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert git(candidate, "rev-parse", "HEAD") == sha
    assert git(candidate, "rev-parse", "--is-shallow-repository") == "false"
    assert git(candidate, "rev-parse", "origin/main") == base
    assert git(candidate, "merge-base", "HEAD", "origin/main") == (base if source == "main" else common)
    assert git(candidate, "rev-list", "HEAD") == git(control, "rev-list", "HEAD")
    assert "origin/unrelated" not in git(candidate, "branch", "-r")
    assert git(candidate, "tag") == ""
    assert unrelated not in git(candidate, "rev-list", "--all").splitlines()
    paths = git(control, "ls-files").splitlines()
    assert paths == git(candidate, "ls-files").splitlines()
    for path in paths:
        assert (control / path).read_bytes() == (candidate / path).read_bytes()
        assert git(candidate, "blame", "--porcelain", "HEAD", "--", path) == git(
            control, "blame", "--porcelain", "HEAD", "--", path
        )


@pytest.mark.parametrize("depth", [1, 2])
def test_two_merge_parent_depth_preserves_trusted_planner_and_exact_diff(history, tmp_path, depth):
    origin, _, base, head, _ = history
    git(origin, "merge", "--no-ff", "-qm", "PR merge", "contributor")
    merge = git(origin, "rev-parse", "HEAD")
    checkout = tmp_path / "merge"
    git(tmp_path, "clone", "-q", "--no-tags", "--depth", str(depth), origin.as_uri(), str(checkout))
    assert git(checkout, "rev-parse", "--is-shallow-repository") == "true"
    if depth == 1:
        with pytest.raises(ValueError, match="expected two-parent PR merge"):
            comparison_base(head, merge, root=checkout)
        return
    assert comparison_base(head, merge, root=checkout) == base
    assert git(checkout, "rev-list", "--count", "HEAD") == "3"
    assert git(checkout, "show", f"{base}:scripts/ci/plan_changes.py") == "TRUSTED = True"
    assert git(checkout, "show", f"{head}:scripts/ci/plan_changes.py") == "TRUSTED = False"
    assert plan(base, head, root=checkout) == plan(base, head, root=origin)


@pytest.mark.parametrize("sha", ["main", "--all", "A" * 40, "a" * 39, "a" * 40 + "\n", "f" * 40])
def test_analysis_fetch_rejects_invalid_or_mismatched_source(history, sha):
    origin, _, base, _, _ = history
    result = subprocess.run(
        ["bash", str(FETCH_HISTORY)],
        cwd=origin,
        env={**os.environ, "GITHUB_SHA": sha},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert git(origin, "rev-parse", "HEAD") == base


def test_ci_fetches_only_the_history_required_by_each_consumer():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    planner = workflow["jobs"]["plan"]["steps"]
    assert planner[0]["with"]["fetch-depth"] == 2
    assert planner[0]["with"]["persist-credentials"] is False
    sonar = workflow["jobs"]["sonar"]["steps"]
    assert sonar[0]["with"]["fetch-depth"] == 1
    assert sonar[0]["with"]["persist-credentials"] is False
    assert sonar[1]["run"] == "bash scripts/ci/fetch_analysis_history.sh"
    assert sonar[2]["uses"] == "./.github/actions/ci-job-sonar"
