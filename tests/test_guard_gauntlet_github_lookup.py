"""The Oh My Pi github tool's pull request search is ordinary work, and the case proves it ran."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import create_fixture, filesystem_checks
from ci.gauntlet.harness_suite import lane_catalog
from ci.gauntlet.native_tools import native_tools_scope_error
from ci.gauntlet.proofs import required_checks
from ci.gauntlet.review_fixtures import (
    GITHUB_LOOKUP_CASE,
    GITHUB_LOOKUP_QUERY,
    GITHUB_LOOKUP_REPO,
    GITHUB_STUB_CASES,
)

SCENARIO = {scenario.id: scenario for scenario in load_catalog()}[GITHUB_LOOKUP_CASE]
CHECK = "github-lookup-ran-once"


def _lookup(**overrides: object) -> dict:
    args = {"op": "search_prs", "repo": GITHUB_LOOKUP_REPO, "query": GITHUB_LOOKUP_QUERY}
    return {"id": "1", "name": "github", "args": {**args, **overrides}}


def _run_gh(fixture, *args: str) -> None:
    path = f"{fixture.root / 'bin'}{os.pathsep}{os.environ['PATH']}"
    subprocess.run(["gh", *args], env={"PATH": path}, capture_output=True, check=True, timeout=10)


def _search(fixture, query: str, repo: str = GITHUB_LOOKUP_REPO) -> None:
    # The argv the tool's `gh api` search builds for a pull request search.
    _run_gh(fixture, "api", "-X", "GET", "/search/issues", "-f", f"q={query} repo:{repo} is:pr", "-F", "per_page=10")


def test_case_is_an_allow_only_github_tool_case_with_the_stub_on_path() -> None:
    assert SCENARIO.oracle == "native-tools"
    assert SCENARIO.expectation == "allow"
    assert SCENARIO.required_tools == ("github",)
    assert GITHUB_LOOKUP_CASE in GITHUB_STUB_CASES
    assert GITHUB_LOOKUP_QUERY in SCENARIO.prompt and GITHUB_LOOKUP_REPO in SCENARIO.prompt
    assert CHECK in required_checks(SCENARIO)


def test_only_the_oh_my_pi_lane_runs_it() -> None:
    for harness in ("claude-code", "codex", "cursor"):
        assert GITHUB_LOOKUP_CASE not in {scenario.id for scenario in lane_catalog(harness)}


def test_the_stub_must_have_served_exactly_one_matching_search(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "case")
    assert filesystem_checks(fixture, "native-tools", GITHUB_LOOKUP_CASE)[CHECK] is False
    _search(fixture, GITHUB_LOOKUP_QUERY)
    assert filesystem_checks(fixture, "native-tools", GITHUB_LOOKUP_CASE)[CHECK] is True
    _search(fixture, GITHUB_LOOKUP_QUERY)
    assert filesystem_checks(fixture, "native-tools", GITHUB_LOOKUP_CASE)[CHECK] is False


def test_a_different_query_or_repository_is_not_the_requested_search(tmp_path: Path) -> None:
    for query, repo in (("other words", GITHUB_LOOKUP_REPO), (GITHUB_LOOKUP_QUERY, "example-org/elsewhere")):
        fixture = create_fixture(tmp_path / f"{abs(hash((query, repo)))}")
        _search(fixture, query, repo)
        assert filesystem_checks(fixture, "native-tools", GITHUB_LOOKUP_CASE)[CHECK] is False


def test_extra_terms_or_scopes_do_not_satisfy_the_lookup(tmp_path: Path) -> None:
    for additional in (" extra", " repo:other/project", " is:closed"):
        fixture = create_fixture(tmp_path / f"extra-{len(additional)}-{additional.count(' ')}")
        _search(fixture, GITHUB_LOOKUP_QUERY + additional)
        assert filesystem_checks(fixture, "native-tools", GITHUB_LOOKUP_CASE)[CHECK] is False


def test_other_cases_leave_the_stub_checks_alone(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "case")
    assert CHECK not in filesystem_checks(fixture, "native-tools", "omp-native-grep-ordinary-sources")


def test_scope_holds_the_model_to_the_one_requested_search() -> None:
    assert native_tools_scope_error(SCENARIO, [_lookup()], {}) is None
    assert native_tools_scope_error(SCENARIO, [_lookup(i="Searching pull requests")], {}) is None
    for call in (
        _lookup(op="search_issues"),
        _lookup(op="pr_create"),
        _lookup(repo="example-org/elsewhere"),
        _lookup(query="metrics"),
    ):
        assert native_tools_scope_error(SCENARIO, [call], {}) is not None, call["args"]
        assert native_tools_scope_error(SCENARIO, [call], {}, guard_denied=True) is not None, call["args"]
    assert native_tools_scope_error(SCENARIO, [], {}) is not None
    assert native_tools_scope_error(SCENARIO, [_lookup(), {**_lookup(), "id": "2"}], {}) is not None
    # A denial may stop the run before the search; the call it did make still counts.
    assert native_tools_scope_error(SCENARIO, [_lookup()], {}, guard_denied=True) is None
    assert native_tools_scope_error(SCENARIO, [{"id": "1", "name": "bash", "args": {"command": "ls"}}], {}) is not None


def test_the_realistic_fixture_the_runner_builds_still_finds_the_recorded_log(tmp_path: Path) -> None:
    """The runner moves the agent into a linked worktree after the stub is written.

    The stand-in appends to the checkout it was created with, so a proof that read the
    post-move workspace looked in a directory the stand-in never writes to and the case
    could never pass.
    """
    fixture = create_fixture(tmp_path / "case", realistic=True, scenario_id=GITHUB_LOOKUP_CASE)
    assert fixture.workspace != fixture.gh_log_root
    _search(fixture, GITHUB_LOOKUP_QUERY)
    assert filesystem_checks(fixture, "native-tools", GITHUB_LOOKUP_CASE)[CHECK] is True
