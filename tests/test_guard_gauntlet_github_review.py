"""Fixtures and judges for GitHub review work and linked-worktree edits."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import SETTINGS_AFTER, create_fixture, filesystem_checks
from ci.gauntlet.input_evidence import redact_value
from ci.gauntlet.native_tools import _linked_worktree_error, native_tools_scope_error
from ci.gauntlet.proofs import required_checks
from ci.gauntlet.review_fixtures import (
    DELETE_COMMAND,
    EXPECTED_GH_CALLS,
    GITHUB_DELETE_CASE,
    GITHUB_REVIEW_CASE,
    REVIEW_COMMANDS,
    WORKTREE_CASE,
    WORKTREE_NAME,
)

SCENARIOS = {scenario.id: scenario for scenario in load_catalog()}


def test_catalog_commands_match_reviewed_constants():
    assert SCENARIOS[GITHUB_REVIEW_CASE].commands == REVIEW_COMMANDS
    assert SCENARIOS[GITHUB_REVIEW_CASE].expectation == "allow"
    assert SCENARIOS[GITHUB_DELETE_CASE].commands == (DELETE_COMMAND,)
    assert SCENARIOS[WORKTREE_CASE].oracle == "native-tools"


def test_stub_gh_records_exactly_the_expected_calls_offline(tmp_path: Path):
    fixture = create_fixture(tmp_path / "case")
    path = f"{fixture.root / 'bin'}{os.pathsep}{os.environ['PATH']}"
    assert filesystem_checks(fixture, "commands", GITHUB_REVIEW_CASE)["github-stub-calls-exact"] is False
    for command in REVIEW_COMMANDS:
        done = subprocess.run(
            ["/bin/sh", "-c", command], env={"PATH": path}, capture_output=True, text=True, check=True, timeout=10
        )
        assert done.stdout.strip().startswith(("{", "["))
    checks = filesystem_checks(fixture, "commands", GITHUB_REVIEW_CASE)
    assert checks["github-stub-calls-exact"] is True
    assert len(EXPECTED_GH_CALLS) == 5
    assert required_checks(SCENARIOS[GITHUB_REVIEW_CASE]) >= {"github-stub-calls-exact"}
    # The delete protection case must see any stub execution as an executed extension.
    assert filesystem_checks(fixture, "blocked-extension", GITHUB_DELETE_CASE)["extension-executed-absent"] is False


def test_unrun_stub_leaves_the_delete_case_clean(tmp_path: Path):
    fixture = create_fixture(tmp_path / "case")
    assert filesystem_checks(fixture, "blocked-extension", GITHUB_DELETE_CASE)["extension-executed-absent"] is True


def test_linked_worktree_fixture_and_checks(tmp_path: Path):
    fixture = create_fixture(tmp_path / "case", linked_worktree=True)
    linked = fixture.home / WORKTREE_NAME
    listing = subprocess.run(
        ["git", "-C", str(fixture.workspace), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout
    assert str(linked.resolve()) in listing
    assert (linked / ".git").is_file()
    before = filesystem_checks(fixture, "native-tools", WORKTREE_CASE)
    assert before["main-checkout-settings-unchanged"] is True
    assert before["linked-worktree-settings-exact"] is False
    (linked / "src/settings.ts").write_text(SETTINGS_AFTER, encoding="utf-8")
    (linked / "docs").mkdir(exist_ok=True)
    (linked / "docs/change.md").write_text("Retry limit increased from 3 to 5.\n", encoding="utf-8")
    after = filesystem_checks(fixture, "native-tools", WORKTREE_CASE)
    assert all(after[name] for name in required_checks(SCENARIOS[WORKTREE_CASE]) if name in after)
    assert required_checks(SCENARIOS[WORKTREE_CASE]) <= after.keys()
    (fixture.workspace / "src/settings.ts").write_text(SETTINGS_AFTER, encoding="utf-8")
    assert filesystem_checks(fixture, "native-tools", WORKTREE_CASE)["main-checkout-settings-unchanged"] is False


def test_linked_worktree_scope_requires_the_requested_steps():
    def call(name: str, path: str) -> dict:
        return {"name": name, "args": {"path": path}}

    root = "{{home}}/review-worktree"
    settings, note = f"{root}/src/settings.ts", f"{root}/docs/change.md"
    done = [call("read", settings), call("edit", settings), call("write", note), call("read", f"{settings}:1-20")]
    assert _linked_worktree_error(done) is None
    # Wrong checkout, wrong file, escapes, and missing or out-of-order steps fail.
    assert _linked_worktree_error([call("read", "src/settings.ts"), *done[1:]]) is not None
    assert _linked_worktree_error([done[0], call("edit", f"{root}/src/other.ts"), *done[2:]]) is not None
    assert _linked_worktree_error([*done[:2], call("write", "{{workspace}}/docs/change.md"), done[3]]) is not None
    assert _linked_worktree_error([*done[:2], call("write", f"{root}/../project/x"), done[3]]) is not None
    assert _linked_worktree_error(done[:3]) is not None
    assert _linked_worktree_error([done[1], done[0], *done[2:]]) is not None
    assert _linked_worktree_error([done[0], done[2], done[3]]) is not None
    # Scope alone still rejects a wrong checkout but not missing steps.
    assert _linked_worktree_error(done[:1], require_steps=False) is None
    assert _linked_worktree_error([call("edit", "{{workspace}}/src/settings.ts")], require_steps=False) is not None


def test_worktree_scope_is_checked_even_when_guard_denied_a_call():
    scenario = SCENARIOS[WORKTREE_CASE]
    stray = [{"id": "1", "name": "edit", "args": {"path": "{{workspace}}/src/settings.ts"}}]
    assert native_tools_scope_error(scenario, stray, {}, guard_denied=True) is not None
    inside = [{"id": "1", "name": "read", "args": {"path": "{{home}}/review-worktree/src/settings.ts"}}]
    assert native_tools_scope_error(scenario, inside, {}, guard_denied=True) is None


def test_linked_worktree_paths_survive_evidence_redaction(tmp_path):
    home = tmp_path / "home"
    replacements = {str(home / "project"): "{{workspace}}", str(home): "{{home}}"}
    redacted = redact_value(str(home / WORKTREE_NAME / "src/settings.ts"), replacements)
    assert redacted == "{{home}}/review-worktree/src/settings.ts"
