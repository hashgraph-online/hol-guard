"""Git rules cases: the staged fixture turns the user's git rules on the way a live run does."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.git_rules_cases import (
    GIT_RULES_BLOCK_REASONS,
    GIT_RULES_CASES,
    HOOK_BYPASS_CASE,
    NAMED_COMMIT_CHECK,
    NAMED_STAGE_CASE,
    NOT_COMMITTED_CHECK,
    NOTHING_STAGED_CHECK,
    STAGE_ALL_CASE,
    STOPPED_CASES,
    git_rules_checks,
    stage_git_rules_cases,
)
from codex_plugin_scanner.guard.hook_execution_environment import collect_hook_execution_environment
from codex_plugin_scanner.guard.hook_review.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore

pytestmark = pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX git fixtures")

_GIT_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_AUTHOR_NAME": "Fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "Fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
}


def _git(workspace: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(workspace), *args], env=_GIT_ENV, check=True, capture_output=True)


def _stage(tmp_path: Path, scenario_id: str) -> tuple[Path, Path, Path]:
    home, workspace, guard_home = tmp_path / "home", tmp_path / "workspace", tmp_path / "guard-home"
    home.mkdir()
    workspace.mkdir()
    _git(workspace, "init", "-q")
    (workspace / "README.md").write_text("# Fixture\n", encoding="utf-8")
    _git(workspace, "add", "README.md")
    _git(workspace, "commit", "-q", "-m", "Initial")
    stage_git_rules_cases(guard_home, workspace, scenario_id)
    return home, workspace, guard_home


def _review(home: Path, workspace: Path, guard_home: Path, command: str) -> dict[str, object]:
    store = GuardStore(guard_home, source="default", prime_policy_integrity=False, allow_system_keyring=False)
    worker = HookWorker(store=store, workspace=workspace)
    try:
        return worker.review_http_payload(
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "session_id": "gauntlet-git-rules",
                "tool_call_id": "git-rules-1",
                "cwd": str(workspace),
                "guard_execution_environment": collect_hook_execution_environment(),
            },
            params={},
            default_harness="claude-code",
            home_dir=home,
            guard_home=guard_home,
            workspace=workspace,
        )
    finally:
        worker.close()


def _denied(result: dict[str, object]) -> bool:
    output = result.get("hookSpecificOutput")
    decision = output.get("permissionDecision") if isinstance(output, dict) else None
    return decision == "deny" or result.get("decision") in {"block", "deny"}


def _catalog() -> dict[str, object]:
    return {scenario.id: scenario for scenario in load_catalog() if scenario.id in GIT_RULES_CASES}


def test_catalog_names_every_git_rules_case_with_its_expectation():
    scenarios = _catalog()
    assert set(scenarios) == GIT_RULES_CASES
    for case in STOPPED_CASES:
        assert scenarios[case].expectation == "block"
        assert set(scenarios[case].decision_paths) == GIT_RULES_BLOCK_REASONS[case]
    assert scenarios[NAMED_STAGE_CASE].expectation == "allow"


def test_staging_refuses_a_guard_home_that_already_sets_risk_actions(tmp_path: Path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text('[risk_actions]\nguard_bypass = "block"\n', encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "README.md").write_text("# Fixture\n", encoding="utf-8")
    with pytest.raises(ValueError):
        stage_git_rules_cases(guard_home, workspace, STAGE_ALL_CASE)


@pytest.mark.parametrize("scenario_id", sorted(STOPPED_CASES))
def test_a_broken_git_rule_is_held_with_its_own_finding(tmp_path: Path, native_hook_force: Path, scenario_id: str):
    home, workspace, guard_home = _stage(tmp_path, scenario_id)
    (command,) = _catalog()[scenario_id].commands
    result = _review(home, workspace, guard_home, command)
    assert _denied(result), result
    (reason,) = GIT_RULES_BLOCK_REASONS[scenario_id]
    assert reason in str(result), result
    expected = NOT_COMMITTED_CHECK if scenario_id == HOOK_BYPASS_CASE else NOTHING_STAGED_CHECK
    assert git_rules_checks(workspace, scenario_id) == {expected: True}


def test_staging_and_committing_by_name_breaks_no_rule(tmp_path: Path, native_hook_force: Path):
    home, workspace, guard_home = _stage(tmp_path, NAMED_STAGE_CASE)
    for command in _catalog()[NAMED_STAGE_CASE].commands:
        result = _review(home, workspace, guard_home, command)
        assert "native_git_" not in str(result), result
        subprocess.run(["/bin/sh", "-c", command], cwd=workspace, env=_GIT_ENV, check=True, capture_output=True)
    assert git_rules_checks(workspace, NAMED_STAGE_CASE) == {NAMED_COMMIT_CHECK: True}
