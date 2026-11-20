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
from types import SimpleNamespace

import pytest

from ci.gauntlet.extension_allow_fixtures import (
    EXTENSION_ALLOW_ID,
    EXTENSION_ALLOW_WORKTREE,
    EXTENSION_ALLOW_WORKTREE_CASE,
    configure_extension_allow_controls,
    extension_allow_checks,
)
from ci.gauntlet.git_allow_fixtures import GIT_ALLOW_CASES, GIT_EXTENSION_ID, GIT_ORIGIN_SHAPE_CASES
from ci.native_runtime import probe_installed_native_extensions

EXECUTED_FLAG = "output/extension-executed.flag"


def scenario() -> dict[str, object]:
    """The worktree allow case as the shipped catalog carries it."""
    catalog = json.loads((Path(__file__).resolve().parents[1] / "ci/gauntlet/scenarios.json").read_text())
    for case in catalog["scenarios"]:
        if case["id"] == EXTENSION_ALLOW_WORKTREE_CASE:
            return case
    raise AssertionError(f"{EXTENSION_ALLOW_WORKTREE_CASE} is missing from the catalog")


def test_the_case_runs_the_allowed_action_inside_the_worktree_it_creates() -> None:
    """The chain adds a worktree, enters it, and asks for the allowed action there."""
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
    """The case takes the git lane's fixture shape but not its control set."""
    # The worktree is built from `origin/main`, which the git ALLOW lane's
    # fixture shape provides locally, so the chain never reaches the network.
    assert EXTENSION_ALLOW_WORKTREE_CASE in GIT_ORIGIN_SHAPE_CASES
    # Its controls come from the contributed-extension module, so joining the
    # git set as well would sign the same extensions twice and overwrite the
    # record the evidence carries.
    assert EXTENSION_ALLOW_WORKTREE_CASE not in GIT_ALLOW_CASES


def signing(monkeypatch) -> list[list[str]]:
    """Record each authorization and the extensions it signed, without a live daemon.

    The permission ids come from the daemon's active catalog, which only an
    initialised runtime carries, so these checks measure the choice of
    extensions rather than the catalog lookup.
    """
    from ci.gauntlet import extension_adapters

    authorizations: list[list[str]] = []

    def configure(_daemon, _guard_home, extension_ids, declared):
        authorizations.append(list(extension_ids))
        permissions = {extension_id: [f"{extension_id}.all"] for extension_id in extension_ids}
        revisions = {extension_id: index for index, extension_id in enumerate(extension_ids, start=1)}
        return permissions, revisions

    monkeypatch.setattr(extension_adapters, "configure_each_extension_with_declared_permissions", configure)
    return authorizations


def test_the_case_allows_the_contributed_extension_and_the_git_step_before_it(monkeypatch) -> None:
    """Both extensions the chain needs are allowed from one authorization."""
    authorizations = signing(monkeypatch)
    record = configure_extension_allow_controls(object(), Path("guard-home"), EXTENSION_ALLOW_WORKTREE_CASE)

    # Enrolling the control authority is accepted only while the home is still
    # at revision 0, so both extensions are committed from one authorization.
    assert authorizations == [[GIT_EXTENSION_ID, EXTENSION_ALLOW_ID]]
    # The contributed extension stays the subject of the record every reader
    # already expects, and the list names what else had to be enabled.
    assert record["extension_id"] == EXTENSION_ALLOW_ID
    assert record["enabled_extensions"] == [GIT_EXTENSION_ID, EXTENSION_ALLOW_ID]


def test_the_other_allow_cases_still_sign_only_the_contributed_extension(monkeypatch) -> None:
    """A case that needs no git step still signs the contributed extension alone."""
    authorizations = signing(monkeypatch)
    record = configure_extension_allow_controls(object(), Path("guard-home"), "external-extension-allow-solo-action")

    assert authorizations == [[EXTENSION_ALLOW_ID]]
    assert record["enabled_extensions"] == [EXTENSION_ALLOW_ID]


@pytest.mark.parametrize("worktree_present", [False, True])
def test_the_oracle_asks_for_the_worktree_as_well_as_the_executed_flag(tmp_path, worktree_present: bool) -> None:
    """The executed flag alone passes a run whose worktree step never happened."""
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


def test_several_extensions_are_committed_in_one_layer(monkeypatch) -> None:
    """`provision` accepts a home only at revision 0, so authorizing twice fails.

    A commit replaces the stored local-admin layers rather than adding to
    them, so committing one extension at a time would drop the one committed
    before it and the case would run with the git step unallowed. Both
    extensions therefore ride in the single layer one authorization commits.
    """
    from ci.gauntlet import extension_adapters
    from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlState, ControlTargetKind

    git_permission = f"{GIT_EXTENSION_ID}.permission.read"
    allow_permission = f"{EXTENSION_ALLOW_ID}.permission.manage"
    authorizations: list[object] = []
    commits: list[tuple[object, ...]] = []

    def authorize(_daemon, guard_home):
        """Stand in for the enrolment the lane performs against a live daemon."""
        authorizations.append(guard_home)
        return "password"

    def commit_controls(_service, _password, controls):
        """Record the controls each commit carries and hand back its revision."""
        commits.append(controls)
        return len(commits)

    monkeypatch.setattr(extension_adapters, "_authorize_extension_controls", authorize)
    monkeypatch.setattr(probe_installed_native_extensions, "commit_controls", commit_controls)

    revisions = extension_adapters.configure_each_extension_controls(
        SimpleNamespace(_server=SimpleNamespace(extension_control_api=object())),
        Path("guard-home"),
        {GIT_EXTENSION_ID: [git_permission], EXTENSION_ALLOW_ID: [allow_permission]},
    )

    assert len(authorizations) == 1
    assert len(commits) == 1
    controls = commits[0]
    assert [
        control.target.target_id for control in controls if control.target.kind is ControlTargetKind.PERMISSION
    ] == [git_permission, allow_permission]
    assert all(control.state is ControlState.ENABLED for control in controls)
    # One layer, so one revision: every extension in it lands together.
    assert revisions == {GIT_EXTENSION_ID: 1, EXTENSION_ALLOW_ID: 1}


def test_permissions_are_read_after_the_contributed_extension_is_enabled(monkeypatch) -> None:
    """A contributed extension's permissions exist only in the live catalog once it is enabled.

    The packaged built-in catalog never names an optional pack's permissions,
    so looking them up there before enabling the extension found none and
    every allow case aborted with `external_extension_permissions_missing`.
    """
    from ci.gauntlet import extension_adapters, extension_allow_fixtures
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
    from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlState, ControlTargetKind

    allow_permission = f"{EXTENSION_ALLOW_ID}.permission.rm"
    enabled: set[str] = set()
    commits: list[tuple[object, ...]] = []

    def catalog() -> SimpleNamespace:
        """The daemon's active catalog: an optional extension appears only once enabled."""
        permission = SimpleNamespace(permission_id=allow_permission)
        extensions = [SimpleNamespace(extension_id=EXTENSION_ALLOW_ID, permissions=[permission])]
        return SimpleNamespace(extensions=[extension for extension in extensions if extension.extension_id in enabled])

    class ControlService:
        """Reads the active catalog on every access, as the daemon's service does."""

        @property
        def _registry(self) -> SimpleNamespace:
            return catalog()

    api = ControlService()

    def commit_controls(_service, _password, controls):
        commits.append(controls)
        enabled.update(
            control.target.target_id
            for control in controls
            if control.target.kind is ControlTargetKind.EXTENSION and control.state is ControlState.ENABLED
        )
        return len(commits)

    monkeypatch.setattr(extension_adapters, "_authorize_extension_controls", lambda _daemon, _home: "password")
    monkeypatch.setattr(probe_installed_native_extensions, "commit_controls", commit_controls)
    monkeypatch.setattr(extension_adapters, "_required_extension_ids", lambda: frozenset())

    assert not any(
        extension.extension_id == EXTENSION_ALLOW_ID for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    )
    record = extension_allow_fixtures.configure_extension_allow_controls(
        SimpleNamespace(_server=SimpleNamespace(extension_control_api=api)),
        Path("guard-home"),
        "external-extension-allow-solo-action",
    )

    assert record["enabled_permissions"] == [allow_permission]
    assert record["control_revision"] == 2
    # The final layer replaces the first, so it carries the enable as well.
    final = commits[-1]
    assert [(control.target.kind, control.target.target_id) for control in final] == [
        (ControlTargetKind.EXTENSION, EXTENSION_ALLOW_ID),
        (ControlTargetKind.PERMISSION, allow_permission),
    ]
