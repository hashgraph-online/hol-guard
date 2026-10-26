"""Git shapes the benign fixture builds: the checkouts and the stopped rebase.

The fixture's git state is a thing of its own - identities, a session's feature
worktree and clone, and a rebase stopped mid-conflict - so it lives beside the
project trees in :mod:`tests.benign_fp_gate_projects` rather than inside
:mod:`tests.benign_fp_gate_fixture`, which assembles them.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from tests.benign_fp_gate_projects import (
    _NODE_PACKAGES,
    _bun_lockfile,
    _node_package,
    _write,
)


_GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "Fixture Author",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "Fixture Author",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
}


def _git(cwd: Path, *args: str, home: Path, check: bool = True) -> str:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        **_GIT_IDENTITY,
    }
    completed = subprocess.run(["git", *args], cwd=cwd, env=environment, check=check, capture_output=True, text=True)
    return completed.stdout.strip()


def _session_worktree(org: Path, home: Path) -> None:
    """Feature worktree of ``app-portal`` outside ``org``, plus the plan notes a session reads first."""
    portal = org / "app-portal"
    _write(portal / "deploy.sh", "#!/bin/sh\n# cronjob rollout\necho deploy\n")
    _write(portal / "scripts" / "report.ts", "console.log(process.env.REPORT_WINDOW ?? '24h');\n")
    _write(portal / ".gitignore", "node_modules/\n.deploy-production.lock.d/\n")
    _write(
        portal / "src" / "app" / "page.tsx", "export default function Page() {\n  return <a href={OLD}>Home</a>;\n}\n"
    )
    _git(portal, "add", "-A", home=home)
    _git(portal, "commit", "--quiet", "-m", "report script", home=home)
    _git(portal, "remote", "add", "origin", "https://github.com/example-org/app-portal.git", home=home)
    # A clone records the remote's default branch; `remote add` alone does not.
    _git(portal, "update-ref", "refs/remotes/origin/main", "HEAD", home=home)
    _git(portal, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main", home=home)
    # An existing branch no worktree has checked out, for `git worktree add <path> <branch>`.
    _git(portal, "branch", "feat/discovery-review", home=home)
    # A branch fetched from origin but never checked out, which `git worktree add
    # <path> <name>` creates locally tracking origin.
    _git(portal, "update-ref", "refs/remotes/origin/feat/remote-only-review", "HEAD", home=home)
    (portal / ".deploy-production.lock.d").mkdir()
    # Installed, gitignored test runner whose `.bin` shim agents list from another checkout.
    _node_package(portal, "vitest", _NODE_PACKAGES["vitest"])
    worktree = org.parent / "app-portal-fix"
    _git(portal, "worktree", "add", "--quiet", "-b", "fix/report-lane", str(worktree), home=home)
    _git(home, "clone", "--quiet", str(portal), str(org.parent / "app-portal-clone"), home=home)
    _write(worktree / "scripts" / "report.ts", "console.log(process.env.REPORT_WINDOW ?? '7d');\n")
    _git(worktree, "commit", "--quiet", "-am", "widen report window", home=home)
    portal_manifest = {"name": "app-portal", "private": True, "devDependencies": {"vite": "^7.1.5"}}
    _write(worktree / "package.json", json.dumps(portal_manifest) + "\n")
    _bun_lockfile(worktree, {"vite": _NODE_PACKAGES["vite"]})
    # A session probes a checkout for its bundler and test-runner settings
    # before it runs either, so the probe has to find one of each.
    _write(worktree / "vite.config.ts", "export default { build: { outDir: 'dist' } };\n")
    _write(worktree / "vitest.config.ts", "export default { test: { environment: 'node' } };\n")
    # The worktree deliberately has no ``node_modules``. Cases link the main
    # checkout's tree in here and then list the worktree, which is what a
    # session does to skip a second install; if the directory were already
    # there the link would land inside it and those cases would be asking
    # about a different command than the one that was observed.
    for name in ("findings", "prd", "todo"):
        _write(home / ".codex" / "plans" / f"remediation-{name}.md", f"# Remediation {name}\nSynthetic plan notes.\n")
    _write(home / ".codex" / "plans" / "remediation-evidence.json", '{"cases": []}\n')
    _write(home / ".codex" / "plans" / "todo.md", "# Todo\n- Synthetic plan item.\n")
    _write(
        home / ".codex" / "plans" / "acme-plan-findings.md", "# Findings\n- 541 retry window\n- 1367 report window\n"
    )
    _write(home / ".codex" / "plans" / "acme-plan-todo.md", "# Todo\n- [ ] 541 retry window\n")
    _write(home / ".codex" / "plans" / "evidence" / "run-1" / "summary.json", '{"cases": []}\n')
    _write(home / ".claude" / "plans" / "acme-plan.md", "# Plan\nSynthetic plan notes.\n")
    _write(home / ".codex" / "auth.json", '{"tokens": "synthetic-not-a-secret"}\n')
    # Claude Code home: a memory note agents read, beside a login and a settings file that must stay guarded.
    _write(home / ".claude" / "projects" / "p" / "memory" / "note.md", "# Note\nSynthetic memory note.\n")
    _write(home / ".claude" / ".credentials.json", '{"token": "synthetic-not-a-secret"}\n')
    _write(home / ".claude" / "settings.json", '{"env": {"SYNTHETIC": "not-a-secret"}}\n')


def _stopped_rebase(org: Path, home: Path, name: str, *options: str) -> None:
    """Linked ``app-portal`` worktree whose ``git rebase`` stopped on a conflict the agent resolved and staged."""
    worktree, onto = org.parent / name, f"{name}-onto"
    _git(org / "app-portal", "worktree", "add", "--quiet", "-b", onto, str(worktree), "main", home=home)
    _write(worktree / "README.md", "# onto\n")
    _git(worktree, "commit", "--quiet", "-am", "onto change", home=home)
    _git(worktree, "checkout", "--quiet", "-b", name, "main", home=home)
    _write(worktree / "README.md", "# lane\n")
    _git(worktree, "commit", "--quiet", "-am", "lane change", home=home)
    _write(worktree / "later.txt", "later\n")
    _git(worktree, "add", "later.txt", home=home)
    _git(worktree, "commit", "--quiet", "-m", "later change", home=home)
    _git(worktree, "rebase", *options, onto, home=home, check=False)
    _git(worktree, "rev-parse", "--verify", "--quiet", "REBASE_HEAD", home=home)
    _write(worktree / "README.md", "# resolved\n")
    _git(worktree, "add", "README.md", home=home)


def signed_checkout_include(home: Path) -> str:
    """The conditional include that makes the signed checkout's own signing settings a restatement.

    A lane that rewrites the fixture's global config has to keep this line, or
    the repository's `gpg.program` stops matching the user's own choice and
    the checkout stands for a different shape than the one it was built for.
    """
    repository = home / "Code" / "signed" / "app-signed"
    user_signing = home / ".config" / "git" / "signed-lane.cfg"
    return f'[includeIf "gitdir:{repository}/"]\n\tpath = {user_signing}\n'


def _signed_checkout(home: Path) -> None:
    """A checkout whose own config file carries the signing and pager settings a team hook writes.

    Repository-scoped `gpg.*`, `commit.gpgsign` and display pager keys are what
    an identity or signing hook drops into every checkout it touches, so a
    fast-forward pull and a `worktree add` have to stay quiet with them set.
    """
    repository = home / "Code" / "signed" / "app-signed"
    _write(repository / "README.md", "# app-signed\n")
    _write(repository / "src" / "index.ts", "export const name = 'app-signed';\n")
    _git(repository, "init", "--quiet", "--initial-branch=main", home=home)
    _git(repository, "add", "-A", home=home)
    _git(repository, "commit", "--quiet", "-m", "app-signed base", home=home)
    _git(repository, "remote", "add", "origin", "https://github.com/example-org/app-signed.git", home=home)
    # `origin/main` is one commit ahead, so a `--ff-only` pull or merge has
    # something to fast-forward to. With it equal to `HEAD` every such case
    # would be already up to date and prove nothing.
    base = _git(repository, "rev-parse", "HEAD", home=home).strip()
    _write(repository / "src" / "report.ts", "export const report = 'signed';\n")
    _git(repository, "add", "-A", home=home)
    _git(repository, "commit", "--quiet", "-m", "app-signed upstream", home=home)
    _git(repository, "update-ref", "refs/remotes/origin/main", "HEAD", home=home)
    _git(repository, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main", home=home)
    _git(repository, "reset", "--quiet", "--hard", base, home=home)
    _git(repository, "branch", "feat/signed-lane", home=home)
    signing_program = home / ".git-hooks" / "sign-commit.sh"
    _write(signing_program, '#!/bin/sh\nexec gpg "$@"\n')
    signing_program.chmod(0o755)
    # The user's own global copy of the signing settings, beside the
    # repository's. An identity hook writes the same program into both, and a
    # repository copy that only restates the user's own choice changes nothing
    # Git would do. `includeIf` keeps it to this checkout so the other fixture
    # repositories keep the configuration they were built with.
    user_signing = home / ".config" / "git" / "signed-lane.cfg"
    _write(user_signing, f"[gpg]\n\tformat = openpgp\n\tprogram = {signing_program}\n[commit]\n\tgpgsign = true\n")
    with (home / ".gitconfig").open("a", encoding="utf-8") as handle:
        handle.write(signed_checkout_include(home))
    for key, value in (
        ("commit.gpgsign", "true"),
        ("tag.gpgsign", "true"),
        ("gpg.format", "openpgp"),
        ("gpg.program", str(signing_program)),
        ("core.pager", "cat"),
        ("pager.log", "false"),
        ("pull.rebase", "false"),
    ):
        _git(repository, "config", "--local", key, value, home=home)
