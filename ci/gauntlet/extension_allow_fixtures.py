"""A contributed extension set to ALLOW must settle its own action, alone and in a chain.

Guard ships the first-party extensions and a much larger set of contributed ones,
and a user who turns one on expects it to behave exactly like the built-ins they
already allowed. The catalog's only contributed-extension cases run the opposite
policy -- the extension enabled with one permission explicitly denied -- so they
prove the deny path and say nothing about the allow path. A contributed extension
whose permissions sit at ``baseline_floor: "review"`` could keep asking after the
user allowed it and no case would notice.

``command.ollama`` is the subject because the fixture already installs a recording
stand-in for its executable and its trust binding is the ordinary ``external``
class every contributed extension carries, so these cases measure the class rather
than one extension's wiring. The stand-in records that the chain physically ran,
which separates "Guard stayed silent" from "the command never happened".
"""

from __future__ import annotations

from pathlib import Path

EXTENSION_ALLOW_SOLO_CASE = "external-extension-allow-solo-action"
# The same allowed action carrying ordinary reads after it in one compound.
EXTENSION_ALLOW_COMPOUND_CASE = "external-extension-allow-action-in-compound"
# The same allowed action run inside a worktree the same compound just created.
EXTENSION_ALLOW_WORKTREE_CASE = "external-extension-allow-inside-new-worktree"
EXTENSION_ALLOW_CASES = frozenset(
    {EXTENSION_ALLOW_SOLO_CASE, EXTENSION_ALLOW_COMPOUND_CASE, EXTENSION_ALLOW_WORKTREE_CASE}
)
EXTENSION_ALLOW_ID = "command.ollama"
# Sibling of the checkout, so the chain needs no ignore entry to keep it untracked.
EXTENSION_ALLOW_WORKTREE = "ext-wt"


def extension_allow_checks(workspace: Path, scenario_id: str, executed_flag: str) -> dict[str, bool]:
    """The allowed action reached its executable instead of being stopped before it."""
    if scenario_id not in EXTENSION_ALLOW_CASES:
        return {}
    checks = {"external-extension-allow-executed": (workspace / executed_flag).is_file()}
    if scenario_id == EXTENSION_ALLOW_WORKTREE_CASE:
        # A linked worktree keeps its administrative data in the checkout and
        # carries a `.git` file, not a directory, so this also proves the
        # first step of the chain ran rather than a bare folder appearing.
        worktree = workspace.parent / EXTENSION_ALLOW_WORKTREE
        checks["external-extension-allow-worktree-created"] = (worktree / ".git").is_file()
    return checks


def _declared_permissions(extension_id: str) -> list[str]:
    """Every permission the installed catalog declares for one extension.

    The ids come from the catalog, so a permission added to the extension is
    enabled here without this file changing -- and a case that silently
    stopped covering one of them would show up as a review instead.
    """
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    permissions = [
        permission.permission_id
        for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        if extension.extension_id == extension_id
        for permission in extension.permissions
    ]
    if not permissions:
        raise RuntimeError("external_extension_permissions_missing")
    return permissions


def configure_extension_allow_controls(
    daemon: object, guard_home: Path, scenario_id: str | None = None
) -> dict[str, object]:
    """Sign the contributed extension and every permission it declares as enabled."""
    from .extension_adapters import configure_each_extension_controls

    extension_ids = [EXTENSION_ALLOW_ID]
    if scenario_id == EXTENSION_ALLOW_WORKTREE_CASE:
        # The first step of that chain creates the worktree the allowed action
        # then runs inside. Without git allowed as well the case would measure
        # git's own floor rather than whether a contributed extension's ALLOW
        # survives a working directory the same compound created.
        from .git_allow_fixtures import GIT_EXTENSION_ID

        extension_ids.insert(0, GIT_EXTENSION_ID)
    permissions = {extension_id: _declared_permissions(extension_id) for extension_id in extension_ids}
    # One authorization for the whole case: enrolling the control authority a
    # second time is refused once a layer is committed.
    revisions = configure_each_extension_controls(daemon, guard_home, permissions)
    subject = extension_ids[-1]
    # The contributed extension is the subject, so its own record stays the
    # shape every reader already expects; the list names whatever else the
    # case had to enable to reach it.
    return {
        "extension_id": subject,
        "enabled_permissions": permissions[subject],
        "control_revision": revisions[subject],
        "enabled_extensions": extension_ids,
    }
