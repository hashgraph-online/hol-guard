"""A years-old ``project`` clone in the gate's home, and a twin with a ``post-checkout`` hook.

Both share the live Gauntlet's long-lived clone configuration: thousands of
retired ``branch.*`` entries and default signing, a listing past a quarter
megabyte. Adding a sibling worktree runs nothing in the plain clone, so it is
allowed. The twin's executable ``post-checkout`` hook would run in the new
checkout, so the same add stays reviewed. The plain clone also has a tracked
``dashboard`` package whose ignored install a new worktree links to. Every
value is synthetic.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from ci.gauntlet.clone_fixtures import LONG_LIVED_EXISTING_BRANCH, long_lived_clone_config


def write_long_lived_clones(home: Path, git: Callable[..., str]) -> None:
    for name, hooked in (("project", False), ("project-hooked", True)):
        clone = home / name
        clone.mkdir(parents=True)
        git(clone, "init", "--quiet", "--initial-branch=main", home=home)
        (clone / "README.md").write_text(f"# {name}\n", encoding="utf-8")
        tracked = ["README.md"]
        if not hooked:
            # A tracked package with its install behind `.gitignore`, which a new
            # worktree borrows with `ln -s` instead of installing again.
            (clone / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
            (clone / "dashboard").mkdir()
            (clone / "dashboard/package.json").write_text('{"name": "dashboard"}\n', encoding="utf-8")
            modules = clone / "dashboard/node_modules/vite"
            modules.mkdir(parents=True)
            (modules / "package.json").write_text('{"name": "vite"}\n', encoding="utf-8")
            (modules / "bin").mkdir()
            (modules / "bin/vite").write_text("#!/bin/sh\necho vite\n", encoding="utf-8")
            # npm links each bin relative to node_modules/.bin.
            shims = clone / "dashboard/node_modules/.bin"
            shims.mkdir()
            (shims / "vite").symlink_to(Path("../vite/bin/vite"))
            tracked += [".gitignore", "dashboard/package.json"]
        git(clone, "add", *tracked, home=home)
        git(clone, "commit", "--quiet", "-m", "long-lived base", home=home)
        git(clone, "branch", LONG_LIVED_EXISTING_BRANCH, home=home)
        git(clone, "update-ref", "refs/remotes/origin/main", "HEAD", home=home)
        with (clone / ".git" / "config").open("a", encoding="utf-8", newline="\n") as config:
            config.write(long_lived_clone_config())
        if hooked:
            hook = clone / ".git" / "hooks" / "post-checkout"
            hook.write_text("#!/bin/sh\necho checked out\n", encoding="utf-8")
            os.chmod(hook, 0o755)
