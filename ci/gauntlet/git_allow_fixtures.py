"""Refresh chains an explicit git ALLOW settles, exercised with that policy in force.

Users enable the git extension's permissions and expect their ordinary refresh
chains to stay silent. Guard raised the Git execution-context floor *after* the
extension controls had already run, so an explicit ALLOW could never settle it
and the chains asked for approval anyway. Every other git scenario in this
catalog runs against a fixture home with no git permission enabled -- the only
extension the catalog ever enables is ``command.github`` -- so none of them can
see that class of regression. These cases enable every ``command.git``
permission, the policy a user who allowed git actually runs, and exercise the
reported chains end to end.

The origin is the offline shape ``fast_forward_fixtures`` builds: a remote URL
with ``refs/remotes/origin/main`` one commit ahead, so a fast-forward merge
runs without network. Chains that reach the network (``git fetch``/``git
pull``) need a reachable origin and are not covered here.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .fast_forward_fixtures import add_fast_forward_origin

GIT_ALLOW_MERGE_CASE = "git-allow-merge-fast-forward-then-reads"
GIT_ALLOW_STASH_CASE = "git-allow-stash-around-fast-forward"
GIT_ALLOW_CASES = frozenset({GIT_ALLOW_MERGE_CASE, GIT_ALLOW_STASH_CASE})
GIT_EXTENSION_ID = "command.git"

STASH_FILE = "src/settings.ts"
STASH_COMMITTED = "export const retryLimit = 3;\n"
STASH_WORKING = "export const retryLimit = 5;\n"
_IDENTITY = {
    "GIT_AUTHOR_NAME": "Gauntlet Fixture",
    "GIT_AUTHOR_EMAIL": "gauntlet@example.invalid",
    "GIT_COMMITTER_NAME": "Gauntlet Fixture",
    "GIT_COMMITTER_EMAIL": "gauntlet@example.invalid",
}


def _git(cwd: Path, environment: dict[str, str], *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(cwd), *args],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return completed.stdout.strip()


def add_git_allow_shape(workspace: Path, environment: dict[str, str], scenario_id: str | None) -> None:
    """Give the ALLOW cases an origin to fast-forward onto, and the stash case dirty work.

    The stash case's file is committed before origin moves ahead, so the
    synthetic upstream commit never touches it and ``git stash pop`` restores
    cleanly after the fast-forward.
    """
    if scenario_id not in GIT_ALLOW_CASES:
        return
    environment = {**environment, **_IDENTITY}
    if scenario_id == GIT_ALLOW_STASH_CASE:
        target = workspace / STASH_FILE
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(STASH_COMMITTED, encoding="utf-8", newline="\n")
        _git(workspace, environment, "add", "--", STASH_FILE)
        _git(workspace, environment, "commit", "--quiet", "-m", "Add retry limit")
    add_fast_forward_origin(workspace, workspace, environment)
    if scenario_id == GIT_ALLOW_STASH_CASE:
        # Uncommitted work the chain stashes across the fast-forward and restores.
        (workspace / STASH_FILE).write_text(STASH_WORKING, encoding="utf-8", newline="\n")


def _heads(workspace: Path) -> tuple[str, str] | None:
    """Read both commits without the fixture's user configuration."""
    environment = {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    try:
        return (
            _git(workspace, environment, "rev-parse", "HEAD"),
            _git(workspace, environment, "rev-parse", "refs/remotes/origin/main"),
        )
    except (OSError, subprocess.SubprocessError):
        return None


def git_allow_checks(workspace: Path, scenario_id: str) -> dict[str, bool]:
    """The chain physically completed: the branch advanced, and stashed work came back."""
    if scenario_id not in GIT_ALLOW_CASES:
        return {}
    heads = _heads(workspace)
    checks = {"git-allow-head-advanced": heads is not None and heads[0] == heads[1]}
    if scenario_id == GIT_ALLOW_STASH_CASE:
        target = workspace / STASH_FILE
        checks["git-allow-stash-restored"] = target.is_file() and target.read_text(encoding="utf-8") == STASH_WORKING
    return checks


def configure_git_allow_controls(daemon: object, guard_home: Path) -> dict[str, object]:
    """Sign the git extension and every one of its permissions as enabled.

    The ids come from the installed catalog rather than a hardcoded list, so a
    permission added to the git extension is enabled here without this file
    changing.
    """
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    from .extension_adapters import configure_extension_controls

    permissions = [
        permission.permission_id
        for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        if extension.extension_id == GIT_EXTENSION_ID
        for permission in extension.permissions
    ]
    if not permissions:
        raise RuntimeError("git_extension_permissions_missing")
    revision = configure_extension_controls(daemon, guard_home, GIT_EXTENSION_ID, enabled_permissions=permissions)
    return {
        "extension_id": GIT_EXTENSION_ID,
        "enabled_permissions": permissions,
        "control_revision": revision,
    }
