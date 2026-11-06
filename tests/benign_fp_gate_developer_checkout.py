"""A developer's own checkout: SSH remote, pruning fetch and a Husky hooks directory.

Ordinary application checkouts carry what a bare ``git init`` fixture does not. The remote is
spelled for SSH, the global configuration prunes on fetch and a hook manager points
``core.hooksPath`` at a directory of the repository. Husky 9 fills that directory with shims
that stop at once unless the project defines the hook of the same name, so a fetch, a branch
or a worktree add starts nothing even though every shim is executable.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from functools import cache
from pathlib import Path

DEVELOPER_CHECKOUT = "portal-web"

# The hooks Husky 9 writes a shim for.
_HUSKY_HOOKS = (
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "pre-commit",
    "pre-merge-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "pre-push",
    "pre-auto-gc",
    "post-rewrite",
    "sendemail-validate",
    "post-index-change",
)
_SHIM = '#!/usr/bin/env sh\n. "$(dirname "$0")/h"\n'
_RUNNER = """#!/usr/bin/env sh
[ "$HUSKY" = "2" ] && set -x
n=$(basename "$0")
s=$(dirname "$(dirname "$0")")/$n

[ ! -f "$s" ] && exit 0

if [ -f "$HOME/.huskyrc" ]; then
\techo "husky - '~/.huskyrc' is DEPRECATED, please move your code to ~/.config/husky/init.sh"
fi
i="${XDG_CONFIG_HOME:-$HOME/.config}/husky/init.sh"
[ -f "$i" ] && . "$i"

[ "${HUSKY-}" = "0" ] && exit 0

export PATH="node_modules/.bin:$PATH"
sh -e "$s" "$@"
c=$?

[ $c != 0 ] && echo "husky - $n script failed (code $c)"
[ $c = 127 ] && echo "husky - command not found in PATH=$PATH"
exit $c
"""


def write_developer_checkout(
    org: Path, home: Path, git: Callable[..., str], write: Callable[[Path, str], None]
) -> None:
    """Create ``org/portal-web`` the way ``npm install`` with Husky 9 and a clone over SSH leave it."""
    repository = org / DEVELOPER_CHECKOUT
    repository.mkdir(parents=True)
    git(repository, "init", "--quiet", "--initial-branch=main", home=home)
    write(repository / ".gitignore", "node_modules/\n")
    write(repository / "package.json", '{\n  "name": "portal-web",\n  "scripts": {"prepare": "husky"}\n}\n')
    write(repository / "src" / "index.ts", "export const name = 'portal-web';\n")
    write(repository / ".husky" / "pre-commit", "npx lint-staged\n")
    git(repository, "add", "-A", home=home)
    git(repository, "commit", "--quiet", "-m", "portal-web base", home=home)
    # An existing branch no worktree has checked out, for `git worktree add <path> <branch>`.
    git(repository, "branch", "fix/report-defects", home=home)
    git(repository, "remote", "add", "origin", "git@github.com:example-org/portal-web.git", home=home)
    git(repository, "update-ref", "refs/remotes/origin/main", "HEAD", home=home)
    git(repository, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main", home=home)
    git(repository, "config", "fetch.prune", "true", home=home)
    shims = repository / ".husky" / "_"
    write(shims / ".gitignore", "*\n")
    write(shims / "h", _RUNNER)
    (shims / "h").chmod(0o644)
    for hook in _HUSKY_HOOKS:
        write(shims / hook, _SHIM)
        (shims / hook).chmod(0o755)
    # Last, so Husky's shims never run for the fixture's own commits.
    git(repository, "config", "core.hooksPath", ".husky/_", home=home)


@cache
def head_commit(org: Path) -> str:
    """The commit ``portal-web`` is at, for a command that names it as a 40-hex start point."""
    return subprocess.run(
        ["git", "-C", str(org / DEVELOPER_CHECKOUT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    ).stdout.strip()
