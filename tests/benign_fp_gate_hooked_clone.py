"""A linked worktree of an ``app-portal`` clone whose hooks directory holds a ``post-merge`` hook.

A fast-forward merge of ``origin/main`` runs ``post-merge``, so the same merge
that runs quietly in ``app-portal-fix`` must stay reviewed here. Both are
linked worktrees, which the workspace sandbox cannot take, and both name the
same GitHub ``origin``. The clone points ``core.hooksPath`` at its own hooks
directory, so the hook runs even under a global ``core.hooksPath``.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

ORIGIN_URL = "https://github.com/example-org/app-portal.git"


def hooked_clone_path(org: Path) -> Path:
    return org.parent / "app-portal-hooked"


def hooked_worktree_path(org: Path) -> Path:
    return org.parent / "app-portal-hooked-fix"


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
