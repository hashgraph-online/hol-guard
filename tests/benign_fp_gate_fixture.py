"""Synthetic, sanitized workspace for the per-PR benign false-positive gate.

Everything lives under one temporary root. Nothing here references a real user
path, private repository, or network host. The layout deliberately mirrors the
shapes that real agent sessions run in and that a bare ``git init`` fixture
never exercises:

* a parent repository that contains an untracked nested child repository;
* a linked worktree of the parent, used as the working directory;
* a global gitconfig with ``filter.lfs.*`` in the fixture HOME;
* a project skill document, a ``[slug]`` route directory and a file whose name
  resembles a credential workflow but is ordinary source;
* a second repository with a tracked gitlink plus a filter attribute, the one
  git shape that must keep requiring review;
* repositories below HOME in a parent directory that is not itself a
  repository (``~/Code/org/app-portal`` and ``~/Code/org/service-api``), each
  with ``.github`` metadata, the layout agents use when they search a child
  repository by absolute path or inspect a sibling with ``git -C``;
* a linked worktree of ``app-portal`` beside the ``org`` directory on a feature branch whose
  ``origin`` is a hosted remote, and plan notes under a HOME dot directory: the shape of a session
  started in a non-repository parent directory that works in an external worktree;
* an installed, gitignored ``node_modules`` in the working directory with the
  project's locked CLI packages, so a runner such as ``npx`` resolves to a
  content-hashed local binary instead of a registry fetch.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

_GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "Fixture Author",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "Fixture Author",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
}

_LFS_GITCONFIG = """[filter "lfs"]
\tclean = git-lfs clean -- %f
\tsmudge = git-lfs smudge -- %f
\tprocess = git-lfs filter-process
\trequired = true
[user]
\tname = Fixture Author
\temail = fixture@example.invalid
"""


@dataclass(frozen=True)
class BenignFixture:
    root: Path
    home: Path
    parent: Path
    worktree: Path
    nested: Path
    gitlink_repo: Path
    guard_home: Path
    private_tmp: Path
    tmp_worktree: Path
    org: Path

    def cleanup(self) -> None:
        """Remove the directories this fixture created outside its own root."""
        shutil.rmtree(self.private_tmp, ignore_errors=True)
        shutil.rmtree(self.tmp_worktree.parent, ignore_errors=True)

    def tokens(self) -> dict[str, str]:
        return {
            "${HOME}": str(self.home),
            "${PARENT}": str(self.parent),
            "${WORKTREE}": str(self.worktree),
            "${NESTED}": str(self.nested),
            "${GITLINK_REPO}": str(self.gitlink_repo),
            "${PRIVATE_TMP}": str(self.private_tmp),
            "${ORG}": str(self.org),
            "${ORG_WT}": str(self.org.parent / "app-portal-fix"),
        }

    def cwd(self, name: str) -> Path:
        return {
            "worktree": self.worktree,
            "worktree_app": self.worktree / "app",
            "parent": self.parent,
            "nested": self.nested,
            "tmp_worktree": self.tmp_worktree,
            "gitlink_repo": self.gitlink_repo,
            "org": self.org,
            "org_app": self.org / "app-portal",
        }[name]


def _git(cwd: Path, *args: str, home: Path) -> str:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        **_GIT_IDENTITY,
    }
    completed = subprocess.run(["git", *args], cwd=cwd, env=environment, check=True, capture_output=True, text=True)
    return completed.stdout.strip()


def _system_tmp() -> str:
    """Use /tmp itself where it exists, the place real agents create scratch directories."""
    return "/tmp" if Path("/tmp").is_dir() else tempfile.gettempdir()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


_NODE_PACKAGES = {"vitest": "3.2.4", "wrangler": "4.20.0"}


def _node_toolchain(workspace: Path) -> None:
    dependencies = {name: f"^{version}" for name, version in _NODE_PACKAGES.items()}
    locked = {
        f"node_modules/{name}": {"version": version, "integrity": "sha512-fixture"}
        for name, version in _NODE_PACKAGES.items()
    }
    _write(workspace / "package.json", json.dumps({"private": True, "devDependencies": dependencies}) + "\n")
    _write(workspace / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": locked}) + "\n")
    _write(workspace / "tests" / "sample.test.ts", "export const sample = 1;\n")
    for name, version in _NODE_PACKAGES.items():
        package = workspace / "node_modules" / name
        manifest = {"name": name, "version": version, "bin": {name: f"./bin/{name}.js"}}
        _write(package / "package.json", json.dumps(manifest) + "\n")
        script = package / "bin" / f"{name}.js"
        _write(script, f"#!/usr/bin/env node\nconsole.log('{name} {version}');\n")
        script.chmod(0o755)
        shim = workspace / "node_modules" / ".bin" / name
        shim.parent.mkdir(parents=True, exist_ok=True)
        shim.symlink_to(Path("..") / name / "bin" / f"{name}.js")


def _session_worktree(org: Path, home: Path) -> None:
    """Feature worktree of ``app-portal`` outside ``org``, plus the plan notes a session reads first."""
    portal = org / "app-portal"
    _write(portal / "deploy.sh", "#!/bin/sh\n# cronjob rollout\necho deploy\n")
    _write(portal / "scripts" / "report.ts", "console.log(process.env.REPORT_WINDOW ?? '24h');\n")
    _write(portal / ".gitignore", "node_modules/\n.deploy-production.lock.d/\n")
    _git(portal, "add", "-A", home=home)
    _git(portal, "commit", "--quiet", "-m", "report script", home=home)
    _git(portal, "remote", "add", "origin", "https://github.com/example-org/app-portal.git", home=home)
    # A clone records the remote's default branch; `remote add` alone does not.
    _git(portal, "update-ref", "refs/remotes/origin/main", "HEAD", home=home)
    _git(portal, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main", home=home)
    (portal / ".deploy-production.lock.d").mkdir()
    (portal / "node_modules").mkdir()
    worktree = org.parent / "app-portal-fix"
    _git(portal, "worktree", "add", "--quiet", "-b", "fix/report-lane", str(worktree), home=home)
    _write(worktree / "scripts" / "report.ts", "console.log(process.env.REPORT_WINDOW ?? '7d');\n")
    _git(worktree, "commit", "--quiet", "-am", "widen report window", home=home)
    for name in ("findings", "prd", "todo"):
        _write(home / ".codex" / "plans" / f"remediation-{name}.md", f"# Remediation {name}\nSynthetic plan notes.\n")
    _write(home / ".codex" / "plans" / "remediation-evidence.json", '{"cases": []}\n')
    _write(home / ".codex" / "auth.json", '{"tokens": "synthetic-not-a-secret"}\n')


def build_fixture(root: Path) -> BenignFixture:
    root = root.resolve()
    home = root / "home"
    parent = root / "projects" / "parent-repo"
    nested = parent / "tools" / "nested-repo"
    worktree = root / "projects" / "parent-repo-feature"
    gitlink_repo = root / "projects" / "gitlink-repo"
    guard_home = root / "guard-home"
    for directory in (home, guard_home):
        directory.mkdir(parents=True)
    _write(home / ".gitconfig", _LFS_GITCONFIG)
    # Synthetic credential file so the negative controls have a real target.
    _write(home / ".agent" / "skills" / "x" / "SKILL.md", "---\nname: x\n---\nSynthetic home skill body.\n")
    _write(home / ".agent" / "artifacts" / "report.md", "# Report\nInert build report text.\n")
    _write(home / "other-project" / "notes.md", "Notes kept outside the project.\nretry policy: three attempts.\n")
    _write(home / "other-project" / "src" / "report.ts", "export const reportWindow = 'report-window-marker';\n")
    _write(home / "other-project" / "package.json", '{\n  "name": "@acme/app",\n  "version": "1.0.0"\n}\n')
    _write(home / "other-project" / ".keep", "")
    _write(home / "acme-plain" / "README.txt", "Plain notes directory.\n")
    _write(home / ".ssh" / "id_rsa", "-----BEGIN FIXTURE KEY-----\nnot-a-real-key\n-----END FIXTURE KEY-----\n")
    # Sibling repository outside the workspace, as in the live Gauntlet fixture.
    _git(home / "other-project", "init", "--quiet", "--initial-branch=main", home=home)
    _git(home / "other-project", "add", "-A", home=home)
    _git(home / "other-project", "commit", "--quiet", "-m", "sibling base", home=home)
    _git(
        home / "other-project",
        "worktree",
        "add",
        "--quiet",
        "-b",
        "fix/report-window",
        str(home / "other-project-wt"),
        home=home,
    )

    parent.mkdir(parents=True)
    _git(parent, "init", "--quiet", "--initial-branch=main", home=home)
    _write(parent / "README.md", "# Parent\n")
    _write(parent / "src" / "one.ts", "export const one = 1;\n")
    _write(parent / "src" / "password-reset-email.tsx", "export const Email = () => null;\n")
    _write(parent / "app" / "registry" / "[slug]" / "page.tsx", "export default function Page() { return null; }\n")
    _write(parent / ".agents" / "skills" / "x" / "SKILL.md", "---\nname: x\n---\nSynthetic skill body.\n")
    _write(parent / ".gitignore", "node_modules/\n")
    _git(parent, "add", "-A", home=home)
    _git(parent, "commit", "--quiet", "-m", "fixture base", home=home)
    _git(parent, "worktree", "add", "--quiet", "-b", "feature", str(worktree), home=home)
    _node_toolchain(worktree)
    _write(worktree / "test_calc.py", "assert 1 + 1 == 2\nprint('ok')\n")

    # Untracked child repository nested inside the parent working tree.
    nested.mkdir(parents=True)
    _git(nested, "init", "--quiet", "--initial-branch=main", home=home)
    _write(nested / "tool.py", "print('tool')\n")
    _git(nested, "add", "-A", home=home)
    _git(nested, "commit", "--quiet", "-m", "nested base", home=home)

    # Untracked linked worktree inside the parent tree, another shape agents leave behind.
    _git(parent, "worktree", "add", "--quiet", "-b", "inner", str(parent / ".worktrees" / "inner"), home=home)

    # Private user-owned temp dir (mode 0700, as mktemp -d creates) with one existing file.
    private_tmp = Path(tempfile.mkdtemp(prefix="tmp.", dir=_system_tmp())).resolve()
    _write(private_tmp / "notes.txt", "first draft\n")
    # Workspace as a linked worktree under the system temp area whose registered siblings are outside cwd.
    tmp_worktree = Path(tempfile.mkdtemp(prefix="wt.", dir=_system_tmp())).resolve() / "workspace"
    _git(parent, "worktree", "add", "--quiet", "-b", "tmp-feature", str(tmp_worktree), home=home)

    # Tracked gitlink plus a filter attribute: must remain reviewable.
    gitlink_repo.mkdir(parents=True)
    _git(gitlink_repo, "init", "--quiet", "--initial-branch=main", home=home)
    _write(gitlink_repo / ".gitattributes", "sub filter=lfs\n*.bin filter=lfs\n")
    _write(gitlink_repo / "readme.txt", "gitlink fixture\n")
    _git(gitlink_repo, "add", "-A", home=home)
    _git(
        gitlink_repo,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{_git(nested, 'rev-parse', 'HEAD', home=home)},sub",
        home=home,
    )
    _git(gitlink_repo, "commit", "--quiet", "-m", "gitlink base", home=home)

    # Repositories below HOME whose shared parent is not a repository.
    org = home / "Code" / "org"
    for name in ("app-portal", "service-api"):
        repository = org / name
        repository.mkdir(parents=True)
        _git(repository, "init", "--quiet", "--initial-branch=main", home=home)
        _write(repository / ".github" / "workflows" / "ci.yml", "name: ci\n")
        _write(repository / "src" / "index.ts", f"export const name = '{name}';\n")
        _write(repository / "README.md", f"# {name}\n")
        _git(repository, "add", "-A", home=home)
        _git(repository, "commit", "--quiet", "-m", f"{name} base", home=home)
    _session_worktree(org, home)
    return BenignFixture(root, home, parent, worktree, nested, gitlink_repo, guard_home, private_tmp, tmp_worktree, org)
