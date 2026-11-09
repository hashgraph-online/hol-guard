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

The unmodelled-read case is the exception: it builds its own origin as a
bare repository beside the checkout, so ``git ls-remote`` answers from the
filesystem with no network and no credential.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .extension_allow_fixtures import EXTENSION_ALLOW_WORKTREE_CASE
from .fast_forward_fixtures import add_fast_forward_origin

GIT_ALLOW_MERGE_CASE = "git-allow-merge-fast-forward-then-reads"
GIT_ALLOW_STASH_CASE = "git-allow-stash-around-fast-forward"
# The same refresh run from outside the checkout, every step carrying `-C`.
GIT_ALLOW_ROUTED_MERGE_CASE = "git-allow-routed-merge-then-reads"
# Reads the git extension has no permission for, after a step it allows.
GIT_ALLOW_REF_READS_CASE = "git-allow-ref-reads-after-checkout"
# A checkout and a pathspec named after Guard are the user's work, not Guard.
GIT_ALLOW_NAMED_CHECKOUT_CASE = "git-allow-guard-named-checkout"
# The worktree permission allows an ordinary sibling checkout...
GIT_ALLOW_WORKTREE_CASE = "git-allow-worktree-sibling-then-status"
# ...but never settles a checkout into a folder Git runs code from.
GIT_ALLOW_HOOKS_WORKTREE_CASE = "git-allow-worktree-into-hooks-folder"
# An allowed step never carries a blocked step in the same compound with it.
GIT_ALLOW_MIXED_WORKTREE_CASE = "git-allow-worktree-then-secret-read"
# Git work the catalog carries no rule for, run under a full git Allow.
GIT_ALLOW_UNMODELLED_CASE = "git-allow-unmodelled-reads-against-origin"
# Git's own plumbing names for work the porcelain above already settles.
GIT_ALLOW_PLUMBING_CASE = "git-allow-plumbing-reads-under-allow"
# The read-only chain a developer runs to see where a checkout stands. It
# writes nothing, and every verb in it is a read the git extension models, so
# a full git Allow has to carry it whatever the configuration probe managed to
# answer for the reads along the way.
GIT_ALLOW_READ_CHAIN_CASE = "git-allow-read-chain-status-log-remote"
# Printing the configured remotes is a read of the configuration file, and its
# ``--get-regexp`` operand is matched against the keys in that file rather than
# expanded over the working tree. A full git Allow has to carry the step beside
# it as well, because a floor raised over one operand is raised over the whole
# command.
GIT_ALLOW_CONFIG_PATTERN_CASE = "git-allow-config-pattern-then-worktree"
# A refresh routed into another checkout with ``-C``, and the reads that follow
# it there. The route is what the allow is proved against, so a read routed to
# the same checkout as the step before it rides that step's allow.
GIT_ALLOW_ROUTED_REFRESH_CASE = "git-allow-routed-refresh-then-reads"
# A checkout whose own ``core.hooksPath`` names a directory inside it, which is
# what husky, lefthook and pre-commit all configure. Guard protects any
# directory that contains the configured hooks directory, and it screened the
# working directory of every checkout subcommand, so such a repository became
# its own protected destination and no git ALLOW could settle the ordinary
# sibling worktree it started.
GIT_ALLOW_RELATIVE_HOOKS_CASE = "git-allow-worktree-from-repo-relative-hooks-path"
GIT_ALLOW_CASES = frozenset(
    {
        GIT_ALLOW_MERGE_CASE,
        GIT_ALLOW_STASH_CASE,
        GIT_ALLOW_ROUTED_MERGE_CASE,
        GIT_ALLOW_REF_READS_CASE,
        GIT_ALLOW_NAMED_CHECKOUT_CASE,
        GIT_ALLOW_WORKTREE_CASE,
        GIT_ALLOW_HOOKS_WORKTREE_CASE,
        GIT_ALLOW_MIXED_WORKTREE_CASE,
        GIT_ALLOW_UNMODELLED_CASE,
        GIT_ALLOW_PLUMBING_CASE,
        GIT_ALLOW_READ_CHAIN_CASE,
        GIT_ALLOW_CONFIG_PATTERN_CASE,
        GIT_ALLOW_ROUTED_REFRESH_CASE,
        GIT_ALLOW_RELATIVE_HOOKS_CASE,
    }
)
GIT_EXTENSION_ID = "command.git"
# The contributed-extension worktree case builds its worktree from the same
# offline origin, but enables its own controls, so it joins the fixture shape
# without joining the set whose controls this module signs.
GIT_ORIGIN_SHAPE_CASES = GIT_ALLOW_CASES | {EXTENSION_ALLOW_WORKTREE_CASE}

STASH_FILE = "src/settings.ts"
STASH_COMMITTED = "export const retryLimit = 3;\n"
STASH_WORKING = "export const retryLimit = 5;\n"
NAMED_FILE = "scripts/hol-guard.wxs"
NAMED_COMMITTED = "<Wix />\n"
NAMED_WORKTREE = "pr/hol-guard-pr-12"
SIBLING_WORKTREE = "review-wt"
HOOKS_WORKTREE = ".git/hooks/review-wt"
MIXED_WORKTREE = "mixed-wt"
CONFIG_WORKTREE = "cfg-wt"
ROUTED_WORKTREE = "routed-wt"
RELATIVE_HOOKS_WORKTREE = "relhooks-wt"
# Repo-relative, like the value husky and lefthook write.
RELATIVE_HOOKS_DIR = ".githooks"
UNMODELLED_ORIGIN = "origin.git"
UNMODELLED_ARCHIVE = "snapshot.tar"
PLUMBING_ARCHIVE = "plumbing.tar"
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
    if scenario_id not in GIT_ORIGIN_SHAPE_CASES:
        return
    environment = {**environment, **_IDENTITY}
    if scenario_id == GIT_ALLOW_NAMED_CHECKOUT_CASE:
        _add_named_checkout(workspace, environment)
        return
    if scenario_id == GIT_ALLOW_UNMODELLED_CASE:
        _add_local_origin(workspace, environment)
        return
    if scenario_id == GIT_ALLOW_STASH_CASE:
        target = workspace / STASH_FILE
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(STASH_COMMITTED, encoding="utf-8", newline="\n")
        _git(workspace, environment, "add", "--", STASH_FILE)
        _git(workspace, environment, "commit", "--quiet", "-m", "Add retry limit")
    if scenario_id == GIT_ALLOW_RELATIVE_HOOKS_CASE:
        # An empty hooks directory inside the checkout, named by a relative
        # ``core.hooksPath``. Nothing in it runs; the configuration alone is
        # what used to make the checkout its own floor.
        (workspace / RELATIVE_HOOKS_DIR).mkdir(parents=True, exist_ok=True)
        _git(workspace, environment, "config", "core.hooksPath", RELATIVE_HOOKS_DIR)
    add_fast_forward_origin(workspace, workspace, environment)
    if scenario_id == GIT_ALLOW_ROUTED_REFRESH_CASE:
        # The checkout the chain routes into. It shares this repository, so the
        # offline origin above is already reachable from it and the routed
        # refresh needs no network.
        _git(workspace, environment, "worktree", "add", "--quiet", "--detach", ROUTED_WORKTREE)
        return
    if scenario_id == GIT_ALLOW_STASH_CASE:
        # Uncommitted work the chain stashes across the fast-forward and restores.
        (workspace / STASH_FILE).write_text(STASH_WORKING, encoding="utf-8", newline="\n")


def _add_named_checkout(workspace: Path, environment: dict[str, str]) -> None:
    """A linked worktree and a tracked file both named after the project, the file edited."""
    target = workspace / NAMED_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(NAMED_COMMITTED, encoding="utf-8", newline="\n")
    _git(workspace, environment, "add", "--", NAMED_FILE)
    _git(workspace, environment, "commit", "--quiet", "-m", "Add installer source")
    exclude = workspace / ".git/info/exclude"
    exclude.parent.mkdir(parents=True, exist_ok=True)
    with exclude.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write("/pr/\n")
    _git(workspace, environment, "worktree", "add", "--quiet", "-b", "pr", NAMED_WORKTREE)
    target.write_text("<Wix><Broken /></Wix>\n", encoding="utf-8", newline="\n")


def _add_local_origin(workspace: Path, environment: dict[str, str]) -> None:
    """A bare repository beside the checkout, registered as ``origin``.

    ``git ls-remote`` then answers from the filesystem, with no network and no
    credential, so the case measures Guard's answer rather than the host's
    connectivity.
    """
    bare = workspace.parent / UNMODELLED_ORIGIN
    subprocess.run(
        ["git", "init", "--quiet", "--bare", str(bare)],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    _git(workspace, environment, "remote", "add", "origin", str(bare))
    _git(workspace, environment, "push", "--quiet", "origin", "HEAD:refs/heads/main")


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
    if scenario_id == GIT_ALLOW_NAMED_CHECKOUT_CASE:
        target = workspace / NAMED_FILE
        restored = target.is_file() and target.read_text(encoding="utf-8") == NAMED_COMMITTED
        return {"git-allow-named-file-restored": restored}
    if scenario_id == GIT_ALLOW_WORKTREE_CASE:
        sibling = workspace.parent / SIBLING_WORKTREE
        heads = _heads(sibling) if (sibling / ".git").is_file() else None
        return {"git-allow-sibling-worktree-at-origin": heads is not None and heads[0] == heads[1]}
    if scenario_id == GIT_ALLOW_HOOKS_WORKTREE_CASE:
        return {"git-allow-hooks-worktree-absent": not (workspace / HOOKS_WORKTREE).exists()}
    if scenario_id == GIT_ALLOW_PLUMBING_CASE:
        # The archive is the last step, so it exists only if the plumbing
        # reads before it ran rather than waiting for the user.
        archive = workspace / PLUMBING_ARCHIVE
        return {"git-allow-plumbing-reads-ran": archive.is_file() and archive.stat().st_size > 0}
    if scenario_id == GIT_ALLOW_UNMODELLED_CASE:
        # The archive is the second step, so it exists only if the ls-remote
        # before it ran rather than waiting for the user.
        archive = workspace / UNMODELLED_ARCHIVE
        return {"git-allow-unmodelled-reads-ran": archive.is_file() and archive.stat().st_size > 0}
    if scenario_id == GIT_ALLOW_MIXED_WORKTREE_CASE:
        # The whole compound is denied, so the allowed checkout never ran either.
        return {"git-allow-mixed-worktree-absent": not (workspace.parent / MIXED_WORKTREE).exists()}
    if scenario_id == GIT_ALLOW_CONFIG_PATTERN_CASE:
        # The checkout is the second step, so it exists only if the
        # configuration read before it ran rather than waiting for the user.
        sibling = workspace.parent / CONFIG_WORKTREE
        heads = _heads(sibling) if (sibling / ".git").is_file() else None
        return {"git-allow-config-pattern-checkout-at-origin": heads is not None and heads[0] == heads[1]}
    if scenario_id == GIT_ALLOW_ROUTED_REFRESH_CASE:
        # The refresh and the reads after it all route into the same checkout,
        # so that checkout, not this one, is where the chain landed.
        routed = workspace / ROUTED_WORKTREE
        heads = _heads(routed) if (routed / ".git").is_file() else None
        return {"git-allow-routed-checkout-at-origin": heads is not None and heads[0] == heads[1]}
    if scenario_id == GIT_ALLOW_RELATIVE_HOOKS_CASE:
        sibling = workspace.parent / RELATIVE_HOOKS_WORKTREE
        heads = _heads(sibling) if (sibling / ".git").is_file() else None
        return {"git-allow-relative-hooks-worktree-at-origin": heads is not None and heads[0] == heads[1]}
    if scenario_id == GIT_ALLOW_READ_CHAIN_CASE:
        # Every step reads, so the checkout is still where the fixture left
        # it: one commit behind the origin this lane builds.
        heads = _heads(workspace)
        return {"git-allow-read-chain-left-checkout-alone": heads is not None and heads[0] != heads[1]}
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
