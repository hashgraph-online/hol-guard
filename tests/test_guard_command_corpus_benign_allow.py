"""Benign reviewed-corpus seeds that are plain read work must be allowed quietly.

The decision-diff oracle floors every benign seed at "review" and its digests are
frozen, so it cannot say "this seed must be allow". This focused test replays the
read-only benign seeds through the real native path, with satisfied proofs (the
fixture worktree exists and is a real repository), and fails when one is reviewed.
A seed that is still reviewed is listed in ``PENDING`` with its current reason; a
listed seed that starts passing fails the test so the marker is removed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from tests.benign_fp_gate_fixture import BenignFixture
from tests.test_guard_benign_false_positive_gate import (
    GateCase,
    _describe,
    _quiet_allow,
    _review,
    gate_environment,  # noqa: F401  (module-scoped pytest fixture)
)

_MANIFEST = json.loads(
    (Path(__file__).parent / "fixtures" / "guard-command-corpus" / "seed-manifest.json").read_text(encoding="utf-8")
)
_READ_ONLY_FAMILIES = ("navigation-public-read", "source-search-read", "git-local")
_READ_ONLY_EXTRA = {("shell-composition", "cd-pipeline"), ("shell-composition", "json-pipeline")}
PENDING: dict[str, str] = {
    "git-local/branches": "native_command_review_required",
    "git-local/diff-check": "native_git_execution_context_review",
    "git-local/recent-log": "native_git_execution_context_review",
    "git-local/show-stat": "native_git_execution_context_review",
    "navigation-public-read/directory-list": "native_command_review_required",
    "navigation-public-read/repository-root": "native_command_review_required",
    "navigation-public-read/status": "native_git_execution_context_review",
    "navigation-public-read/working-directory": "native_command_review_required",
    "shell-composition/cd-pipeline": "native_command_review_required",
    "shell-composition/json-pipeline": "native_git_execution_context_review",
    "source-search-read/source-files": "native_command_review_required",
    "source-search-read/source-view": "native_command_review_required",
    "source-search-read/symbol-search": "native_command_review_required",
    "source-search-read/targeted-search": "native_command_review_required",
}


def _seeds() -> list[tuple[str, str]]:
    seeds: list[tuple[str, str]] = []
    for workflow in _MANIFEST["benign_workflows"]:
        for seed_id, command in workflow["seeds"]:
            if workflow["id"] in _READ_ONLY_FAMILIES or (workflow["id"], seed_id) in _READ_ONLY_EXTRA:
                seeds.append((f"{workflow['id']}/{seed_id}", command))
    return seeds


_SEEDS = _seeds()


def _case(seed_id: str, command: str) -> GateCase:
    # The corpus works inside a synthetic workspace; run it in the real fixture worktree instead.
    local = re.sub(r"cd workspace/\S+", "cd ${WORKTREE}", command.replace("{variant}", "0"))
    return GateCase(seed_id, seed_id, "corpus", "codex", "shell", {"command": local}, "worktree", "allow")


@pytest.mark.parametrize(("seed_id", "command"), _SEEDS, ids=[seed for seed, _ in _SEEDS])
def test_read_only_benign_corpus_seed_is_not_reviewed(
    seed_id: str,
    command: str,
    gate_environment: tuple[BenignFixture, HookWorker],  # noqa: F811
) -> None:
    fixture, worker = gate_environment
    case = _case(seed_id, command)
    result, approvals = _review(case, fixture, worker)
    passed = _quiet_allow(result, approvals)
    if seed_id in PENDING:
        assert not passed, f"stale pending marker: {seed_id} now allows quietly ({PENDING[seed_id]})"
        return
    assert passed, f"benign corpus seed was reviewed: {_describe(case, result, approvals)}"


def test_read_only_seed_selection_is_not_empty_and_pending_names_real_seeds() -> None:
    assert len(_SEEDS) >= 12
    assert set(PENDING) <= {seed for seed, _ in _SEEDS}
