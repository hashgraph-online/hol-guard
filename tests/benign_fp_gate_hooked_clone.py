"""A linked worktree of an ``app-portal`` clone whose hooks directory holds a ``post-merge`` hook.

A fast-forward merge of ``origin/main`` runs ``post-merge``, so the same merge
that runs quietly in ``app-portal-fix`` must stay reviewed here. Both are
linked worktrees, which the workspace sandbox cannot take, and both name the
same GitHub ``origin``. The clone points ``core.hooksPath`` at its own hooks
directory, so the hook runs even under a global ``core.hooksPath``.

A second clone points ``core.hooksPath`` at an empty directory under home and
answers Git's credential prompt from a shell function, two settings a
developer keeps in a long-lived checkout's own configuration. Neither reaches
into its worktree, so an ordinary edit there is contained as in
``app-portal-fix``.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

ORIGIN_URL = "https://github.com/example-org/app-portal.git"
CREDENTIAL_HELPER = (
    '!f() { echo "username=x-access-token"; echo "password=$(gh auth token --hostname github.com)"; }; f'
)


def hooked_clone_path(org: Path) -> Path:
    return org.parent / "app-portal-hooked"


def hooked_worktree_path(org: Path) -> Path:
    return org.parent / "app-portal-hooked-fix"


def hooked_cwds(org: Path) -> dict[str, Path]:
    return {"org_hooked": hooked_worktree_path(org), "org_home_hooks": org.parent / "app-portal-home-hooks-fix"}


def write_hooked_clone(org: Path, home: Path, git: Callable[..., str]) -> None:
    clone = hooked_clone_path(org)
    git(home, "clone", "--quiet", str(org / "app-portal"), str(clone), home=home)
    git(clone, "remote", "set-url", "origin", ORIGIN_URL, home=home)
    hooks = clone / ".git" / "hooks"
    hook = hooks / "post-merge"
    hook.write_text("#!/bin/sh\necho merged\n", encoding="utf-8")
    os.chmod(hook, 0o755)
    git(clone, "config", "core.hooksPath", str(hooks), home=home)
    git(clone, "worktree", "add", "--quiet", "-b", "fix/hooked-lane", str(hooked_worktree_path(org)), home=home)
    home_hooks = org.parent / "app-portal-home-hooks"
    git(home, "clone", "--quiet", str(org / "app-portal"), str(home_hooks), home=home)
    git(home_hooks, "remote", "set-url", "origin", ORIGIN_URL, home=home)
    (home / ".app-hooks" / "empty").mkdir(parents=True, exist_ok=True)
    git(home_hooks, "config", "core.hooksPath", "~/.app-hooks/empty", home=home)
    git(home_hooks, "config", "credential.helper", CREDENTIAL_HELPER, home=home)
    worktree = hooked_cwds(org)["org_home_hooks"]
    git(home_hooks, "worktree", "add", "--quiet", "-b", "fix/home-hooks", str(worktree), home=home)
    # `origin/main` moves one commit past the worktree's branch, so the
    # `--ff-only` merge case has something to fast-forward and would run
    # `post-merge` if the hooks folder held one.
    (home_hooks / "CHANGELOG.md").write_text("Upstream entry.\n", encoding="utf-8")
    git(home_hooks, "add", "CHANGELOG.md", home=home)
    git(home_hooks, "commit", "--quiet", "-m", "upstream entry", home=home)
    git(home_hooks, "update-ref", "refs/remotes/origin/main", "HEAD", home=home)
    (worktree / "docs").mkdir()
    (worktree / "docs" / "release-notes.md").write_text("Draft release notes.\n", encoding="utf-8")
