"""The benign first-contact omp scenarios and the realistic fixture they run in."""

from __future__ import annotations

import re
import subprocess

import pytest

from ci.gauntlet.catalog import load_catalog, load_catalog_data
from ci.gauntlet.fixtures import create_fixture

_NATIVE_TOOLS = tuple(s for s in load_catalog() if s.oracle == "native-tools")


def test_native_tools_scenarios_cover_the_omp_tool_family_and_are_allow_only() -> None:
    assert {tool for s in _NATIVE_TOOLS for tool in s.required_tools} >= {
        "glob",
        "grep",
        "eval",
        "task",
        "wait",
        "read",
        "write",
        "todo",
        "bash",
    }
    assert all(s.expectation == "allow" for s in _NATIVE_TOOLS)


def test_native_tools_oracle_rejects_a_block_expectation_or_missing_tools() -> None:
    row = {"id": "x-case", "expectation": "allow", "oracle": "native-tools", "prompt": "p"}
    with pytest.raises(ValueError):
        load_catalog_data({"schema": "hol.guard-gauntlet.scenarios.v1", "scenarios": [row]})
    with pytest.raises(ValueError):
        load_catalog_data(
            {
                "schema": "hol.guard-gauntlet.scenarios.v1",
                "scenarios": [{**row, "expectation": "block", "required_tools": ["glob"]}],
            }
        )


def test_realistic_fixture_has_lfs_config_nested_repo_and_linked_worktree(tmp_path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True)
    assert '[filter "lfs"]' in (fixture.home / ".gitconfig").read_text(encoding="utf-8")
    nested = fixture.workspace / "tools/nested-repo"
    assert (nested / ".git").exists()
    listing = subprocess.run(
        ["git", "-C", str(fixture.workspace), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    # The agent works inside a linked worktree whose registered main checkout is outside cwd.
    assert (fixture.workspace / ".git").is_file()
    assert listing.count("worktree ") >= 3
    assert (fixture.workspace / ".worktrees/inner").is_dir()
    assert (fixture.home / ".agent/skills/x/SKILL.md").is_file()
    assert (fixture.home / ".agent/artifacts/report.md").is_file()
    assert "retry" in (fixture.home / "other-project/notes.md").read_text(encoding="utf-8")
    assert (fixture.workspace / ".agents/skills/x/SKILL.md").is_file()
    assert (fixture.workspace / "app/registry/[slug]/page.tsx").is_file()
    tracked = subprocess.run(
        ["git", "-C", str(fixture.workspace), "ls-files"], capture_output=True, text=True, check=True
    ).stdout
    assert "tools/nested-repo" not in tracked


def test_default_fixture_stays_minimal(tmp_path) -> None:
    fixture = create_fixture(tmp_path / "fx")
    assert not (fixture.home / ".gitconfig").exists()
    assert not (fixture.workspace / "tools").exists()


def _call(name: str, **args: object) -> dict:
    return {"id": name, "name": name, "args": args, "is_error": False, "result": None}


def _scenario(scenario_id: str):
    return next(s for s in _NATIVE_TOOLS if s.id == scenario_id)


def test_benign_prompts_read_like_ordinary_developer_requests() -> None:
    from ci.gauntlet.agent_prompt import scenario_prompt

    banned = re.compile(r"\b(disposable|synthetic|authorized|fixture|test)\b")
    for scenario in _NATIVE_TOOLS:
        # The searched marker text itself is file content, not framing.
        text = scenario_prompt(scenario).lower().replace("ordinary-workflow-fixture", "")
        assert not banned.search(text), scenario.id


def test_native_tools_context_is_neutral(tmp_path) -> None:
    from ci.gauntlet.agent_prompt import fixture_authorization

    fixture = create_fixture(tmp_path / "fx", realistic=True)
    text = fixture_authorization(fixture, "http://127.0.0.1:1/", _NATIVE_TOOLS[0])
    text = text.replace(str(fixture.home), "").replace(str(fixture.workspace), "").lower()
    assert not re.search(r"\b(disposable|authorized|synthetic|test)\b", text)


def test_scope_judge_requires_listed_commands_and_private_temp_writes() -> None:
    from ci.gauntlet.native_tools import native_tools_scope_error

    git = _scenario("omp-native-git-readonly-nested-repo")
    ok = [_call("bash", command=c) for c in git.commands]
    assert native_tools_scope_error(git, ok, {}) is None
    assert native_tools_scope_error(git, ok[:1], {}) is not None
    assert native_tools_scope_error(git, [*ok, _call("bash", command="rm -rf x")], {}) is not None
    temp = _scenario("omp-native-private-temp-write-then-overwrite")
    mk = _call("bash", command="mktemp -d")
    assert native_tools_scope_error(temp, [mk, _call("write", path="/tmp/tmp.ab/x.txt")], {}) is None
    assert native_tools_scope_error(temp, [mk, _call("write", path="/home/u/x.txt")], {}) is not None


def test_approval_row_without_always_is_named_as_a_false_positive() -> None:
    from ci.gauntlet.approval_rows import always_gap

    rows = [
        {"tool_name": "bash", "always_available": True},
        {"tool_name": "read", "always_available": False},
    ]
    assert always_gap(rows) == ["read"]
