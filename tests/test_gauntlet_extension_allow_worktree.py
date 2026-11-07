"""A contributed extension's ALLOW has to survive a directory the same chain created.

The catalog's contributed-extension allow cases run their action in the
directory the agent started in, and the git worktree case that does change
directory runs the packaged git extension. Nothing covered the intersection a
user actually reports: an extension they allowed, asked for inside a worktree
the same compound just added. These checks hold that case's wiring in place --
the chain needs both extensions allowed and an offline origin, and the oracle
has to see the worktree as well as the executed flag.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci.gauntlet.extension_allow_fixtures import (
    EXTENSION_ALLOW_ID,
    EXTENSION_ALLOW_WORKTREE,
    EXTENSION_ALLOW_WORKTREE_CASE,
    configure_extension_allow_controls,
    extension_allow_checks,
)
from ci.gauntlet.git_allow_fixtures import GIT_ALLOW_CASES, GIT_EXTENSION_ID, GIT_ORIGIN_SHAPE_CASES

EXECUTED_FLAG = "output/extension-executed.flag"


def scenario() -> dict[str, object]:
    catalog = json.loads((Path(__file__).resolve().parents[1] / "ci/gauntlet/scenarios.json").read_text())
    for case in catalog["scenarios"]:
        if case["id"] == EXTENSION_ALLOW_WORKTREE_CASE:
            return case
    raise AssertionError(f"{EXTENSION_ALLOW_WORKTREE_CASE} is missing from the catalog")


def test_the_case_runs_the_allowed_action_inside_the_worktree_it_creates() -> None:
    case = scenario()
    assert case["expectation"] == "allow"
    (command,) = case["commands"]
    worktree, entry, action = command.split(" && ")[:3]
    assert worktree.startswith("git worktree add ")
    assert f"../{EXTENSION_ALLOW_WORKTREE}" in worktree
    assert entry == f"cd ../{EXTENSION_ALLOW_WORKTREE}"
    # The contributed extension's own action, asked for from the new directory.
    assert action.startswith("ollama ")


def test_the_case_gets_an_offline_origin_without_joining_the_git_control_set() -> None:
    # The worktree is built from `origin/main`, which the git ALLOW lane's
    # fixture shape provides locally, so the chain never reaches the network.
    assert EXTENSION_ALLOW_WORKTREE_CASE in GIT_ORIGIN_SHAPE_CASES
    # Its controls come from the contributed-extension module, so joining the
    # git set as well would sign the same extensions twice and overwrite the
    # record the evidence carries.
    assert EXTENSION_ALLOW_WORKTREE_CASE not in GIT_ALLOW_CASES


def signing(monkeypatch) -> list[str]:
    """Record which extensions the configuration signs, without a live daemon.

    The permission ids come from the installed catalog, which only an
    initialised runtime carries, so these checks measure the choice of
    extensions rather than the catalog lookup the lane shares with the
    cases that were already passing.
    """
    from ci.gauntlet import extension_adapters, extension_allow_fixtures

    signed: list[str] = []

    def configure(_daemon, _guard_home, extension_id, *, enabled_permissions):
        assert enabled_permissions, extension_id
        signed.append(extension_id)
        return len(signed)

    monkeypatch.setattr(extension_allow_fixtures, "_declared_permissions", lambda extension_id: [f"{extension_id}.all"])
    monkeypatch.setattr(extension_adapters, "configure_extension_controls", configure)
    return signed


def test_the_case_allows_the_contributed_extension_and_the_git_step_before_it(monkeypatch) -> None:
    signed = signing(monkeypatch)
    record = configure_extension_allow_controls(object(), Path("guard-home"), EXTENSION_ALLOW_WORKTREE_CASE)

    assert signed == [GIT_EXTENSION_ID, EXTENSION_ALLOW_ID]
    # The contributed extension stays the subject of the record every reader
    # already expects, and the list names what else had to be enabled.
    assert record["extension_id"] == EXTENSION_ALLOW_ID
    assert record["enabled_extensions"] == [GIT_EXTENSION_ID, EXTENSION_ALLOW_ID]


def test_the_other_allow_cases_still_sign_only_the_contributed_extension(monkeypatch) -> None:
    signed = signing(monkeypatch)
    record = configure_extension_allow_controls(object(), Path("guard-home"), "external-extension-allow-solo-action")

    assert signed == [EXTENSION_ALLOW_ID]
    assert record["enabled_extensions"] == [EXTENSION_ALLOW_ID]


@pytest.mark.parametrize("worktree_present", [False, True])
def test_the_oracle_asks_for_the_worktree_as_well_as_the_executed_flag(tmp_path, worktree_present: bool) -> None:
    workspace = tmp_path / "project"
    (workspace / "output").mkdir(parents=True)
    (workspace / EXECUTED_FLAG).write_text("executed\n")
    if worktree_present:
        linked = tmp_path / EXTENSION_ALLOW_WORKTREE
        linked.mkdir()
        # A linked worktree carries a `.git` file pointing back at the checkout.
        (linked / ".git").write_text(f"gitdir: {workspace}/.git/worktrees/{EXTENSION_ALLOW_WORKTREE}\n")

    checks = extension_allow_checks(workspace, EXTENSION_ALLOW_WORKTREE_CASE, EXECUTED_FLAG)

    assert checks["external-extension-allow-executed"] is True
    assert checks["external-extension-allow-worktree-created"] is worktree_present
