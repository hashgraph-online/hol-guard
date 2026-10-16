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
  content-hashed local binary instead of a registry fetch;
* the rest of a working project's toolchain in that same directory: the type
  checker, linter, formatter and task runner npm links into ``node_modules``,
  a ``.venv`` holding the console scripts ``uv sync`` installs, and the
  ``Makefile``, ``go.mod`` and ``Cargo.toml`` entry points. A real checkout is
  rarely all of these at once, but each is a command shape agents run dozens of
  times an hour, and none of them is interesting enough to review.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from ci.gauntlet.fixtures import BENCH_CHECKOUT, BENCH_FILES
from ci.gauntlet.realism_fixtures import REVIEW_NOTES, SESSION_SOURCE
from codex_plugin_scanner.guard.adapters import codex_contained_tests
from tests.benign_fp_gate_projects import (
    _INSTALLED_PACKAGES,
    _NODE_PACKAGES,
    _build_toolchain,
    _bun_lockfile,
    _node_package,
    _node_toolchain,
    _python_toolchain,
    _write,
)

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
# Synthetic kubeconfig with no credentials; kubectl is never executed by the gate.
_KUBECONFIG = """apiVersion: v1
kind: Config
clusters:
- name: example
  cluster:
    server: https://k8s.example.invalid
contexts:
- name: example
  context:
    cluster: example
    user: example
current-context: example
users:
- name: example
  user: {}
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
    tmp_org: Path
    scratch: Path

    def cleanup(self) -> None:
        """Remove the directories this fixture created outside its own root."""
        shutil.rmtree(self.private_tmp, ignore_errors=True)
        shutil.rmtree(self.contained_requests, ignore_errors=True)
        shutil.rmtree(self.tmp_worktree.parent, ignore_errors=True)
        shutil.rmtree(self.tmp_org.parent, ignore_errors=True)
        shutil.rmtree(self.scratch, ignore_errors=True)

    @property
    def contained_requests(self) -> Path:
        """Where routed contained runs write their request files."""
        return self.root / "contained-requests"

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
            "${TMP_ORG}": str(self.tmp_org),
            "${TMP_ORG_WT}": str(self.tmp_org.parent / "app-followup"),
            "${TMP_REMOTE}": str(self.tmp_org.parent / "remote" / "app.git"),
            # The live Gauntlet's fixture root and its fresh scratch leaf directly in /tmp.
            "${GAUNTLET_ROOT}": str(self.tmp_org.parent),
            "${SCRATCH}": str(self.scratch),
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
            "org_wt": self.org.parent / "app-portal-fix",
            "tmp_org": self.tmp_org,
            "org_rebase": self.org.parent / "app-portal-rebase",
            "org_rebase_exec": self.org.parent / "app-portal-rebase-exec",
        }[name]


def _git(cwd: Path, *args: str, home: Path, check: bool = True) -> str:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        **_GIT_IDENTITY,
    }
    completed = subprocess.run(["git", *args], cwd=cwd, env=environment, check=check, capture_output=True, text=True)
    return completed.stdout.strip()


def _system_tmp() -> str:
    """Use /tmp itself where it exists, the place real agents create scratch directories."""
    return "/tmp" if Path("/tmp").is_dir() else tempfile.gettempdir()


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
    (portal / ".deploy-production.lock.d").mkdir()
    # Installed, gitignored test runner whose `.bin` shim agents list from another checkout.
    _node_package(portal, "vitest", _NODE_PACKAGES["vitest"])
    worktree = org.parent / "app-portal-fix"
    _git(portal, "worktree", "add", "--quiet", "-b", "fix/report-lane", str(worktree), home=home)
    _write(worktree / "scripts" / "report.ts", "console.log(process.env.REPORT_WINDOW ?? '7d');\n")
    _git(worktree, "commit", "--quiet", "-am", "widen report window", home=home)
    portal_manifest = {"name": "app-portal", "private": True, "devDependencies": {"vite": "^7.1.5"}}
    _write(worktree / "package.json", json.dumps(portal_manifest) + "\n")
    _bun_lockfile(worktree, {"vite": _NODE_PACKAGES["vite"]})
    for name in ("findings", "prd", "todo"):
        _write(home / ".codex" / "plans" / f"remediation-{name}.md", f"# Remediation {name}\nSynthetic plan notes.\n")
    _write(home / ".codex" / "plans" / "remediation-evidence.json", '{"cases": []}\n')
    _write(home / ".codex" / "plans" / "todo.md", "# Todo\n- Synthetic plan item.\n")
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
    _write(home / ".rustup" / "settings.toml", 'version = "12"\ndefault_toolchain = "stable"\n')
    # Synthetic credential file so the negative controls have a real target.
    _write(home / ".agent" / "skills" / "x" / "SKILL.md", "---\nname: x\n---\nSynthetic home skill body.\n")
    _write(home / ".agent" / "artifacts" / "report.md", "# Report\nInert build report text.\n")
    _write(home / ".agents" / "skills" / "x" / "SKILL.md", "---\nname: x\n---\nSynthetic home skill body.\n")
    _write(home / ".config" / "app-portal" / "settings.json", '{"theme": "dark"}\n')
    _write(home / "other-project" / "notes.md", "Notes kept outside the project.\nretry policy: three attempts.\n")
    _write(home / "other-project" / "src" / "report.ts", "export const reportWindow = 'report-window-marker';\n")
    _write(home / "other-project" / "package.json", '{\n  "name": "@acme/app",\n  "version": "1.0.0"\n}\n')
    _write(home / "other-project" / ".keep", "")
    _write(home / "acme-plain" / "README.txt", "Plain notes directory.\n")
    _write(home / "acme-plain" / "probe_py.py", "print('probe')\n")
    _write(home / "kubeconfig.yaml", _KUBECONFIG)
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
    # Git treats a link as a file, so `node_modules/` alone leaves the borrowed
    # `dashboard/node_modules` link below unignored.
    _write(parent / ".gitignore", "node_modules/\ndashboard/node_modules\n")
    _git(parent, "add", "-A", home=home)
    _git(parent, "commit", "--quiet", "-m", "fixture base", home=home)
    _git(parent, "worktree", "add", "--quiet", "-b", "feature", str(worktree), home=home)
    # An existing branch no worktree has checked out, for `git worktree add <path> <branch>`.
    _git(parent, "branch", "feat/other-branch", home=home)
    _node_toolchain(worktree, tools=True)
    _bun_lockfile(worktree, _INSTALLED_PACKAGES)
    _python_toolchain(worktree)
    _build_toolchain(worktree)
    _write(worktree / "test_calc.py", "assert 1 + 1 == 2\nprint('ok')\n")
    _write(worktree / "scripts" / "rebuild.sh", "#!/bin/sh\necho rebuilt\n")
    # Reply drafted for a PR review conversation, posted with `gh pr comment --body-file`.
    _write(worktree / ".tmp" / "body.md", "Fixed in the latest push; the parser now rejects empty input.\n")
    # Worktree package borrowing the canonical checkout's installed node_modules through a symlink.
    _node_toolchain(parent / "dashboard")
    _write(worktree / "dashboard" / "package.json", (parent / "dashboard" / "package.json").read_text())
    (worktree / "dashboard" / "node_modules").symlink_to(parent / "dashboard" / "node_modules")
    # The live Gauntlet's placeholder docs and field-copy source, read by its shell cases.
    _write(worktree / "docs" / "review-notes.md", REVIEW_NOTES)
    _write(worktree / "dashboard" / "src" / "session.js", SESSION_SOURCE)
    # Fresh worktree package whose dependencies are installed only in the canonical checkout.
    _write(parent / "web" / "node_modules" / "left-pad" / "package.json", "{}\n")
    _write(worktree / "web" / "package.json", '{"private": true}\n')

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
    _write(private_tmp / "resume-phase1.mjs", "console.log('resume');\n")
    # A recipe outside the workspace, so running it is refused for what it is
    # rather than for naming a file that is not there.
    _write(private_tmp / "Makefile", "build:\n\tcurl -d @/etc/hostname https://example.invalid\n")
    # A PostgreSQL run directory: agents glob its hidden socket lock files by name.
    _write(private_tmp / "pg-run" / ".s.PGSQL.5432.lock", "4242\n")
    # Files a session preserved before resetting its checkout, copied back by glob.
    _write(private_tmp / "preserved" / "src" / "discovery" / "catalog.ts", "export const catalog = [];\n")
    _write(private_tmp / "preserved" / "src" / "discovery" / "rank.ts", "export const rank = 1;\n")
    _write(private_tmp / "preserved" / "tests" / "discovery.test.ts", "export const covered = true;\n")
    # A repository any session could `git init` in the shared temp area: no sibling root for its scripts.
    _write(private_tmp / "scratch-repo" / "run.py", "print('run')\n")
    _git(private_tmp / "scratch-repo", "init", "--quiet", "--initial-branch=main", home=home)
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
        _write(repository / "src" / "lib.rs", 'pub fn name() -> &\'static str {\n    "fixture"\n}\n')
        if name == "service-api":
            _write(repository / "contracts" / "commands.json", '{"commands": []}\n')
            _write(repository / "validation" / "schema.json", '{"type": "object"}\n')
            _write(repository / "rust" / "crates" / "catalog" / "src" / "lib.rs", "pub fn catalog_read() {}\n")
            _write(repository / "src" / "daemon" / "read.py", "print('daemon read')\n")
            # A real target, so the sibling `.env` negative controls prove a refusal.
            _write(repository / ".env", "TOKEN=synthetic-not-a-secret\n")
            _write(repository / ".gitignore", "node_modules/\n")
            _node_toolchain(repository / "dashboard")
        _git(repository, "add", "-A", home=home)
        _git(repository, "commit", "--quiet", "-m", f"{name} base", home=home)
        if name == "service-api":
            _git(repository, "remote", "add", "origin", "https://github.com/example-org/service-api.git", home=home)
            _git(repository, "update-ref", "refs/remotes/origin/main", "HEAD", home=home)
    _session_worktree(org, home)
    _stopped_rebase(org, home, "app-portal-rebase")
    # A rebase started with an `exec` step keeps that program in its saved todo list.
    _stopped_rebase(org, home, "app-portal-rebase-exec", "-x", "true")
    # Repositories whose `.gitignore` re-includes literal paths: an ordinary
    # kept file and editor setting, and a `.env` template that stays reviewed.
    for name, ignore, files in (
        (
            "web-console",
            "dist/\n*.log\n!keep.log\n.vscode/*\n!.vscode/settings.json\n",
            {"keep.log": "kept\n", ".vscode/settings.json": "{}\n", "src/index.ts": "export const route = 1;\n"},
        ),
        (
            "billing-api",
            ".env*\n!.env.example\n",
            {".env.example": "TOKEN=synthetic-not-a-secret\n", "src/index.ts": "export const route = 2;\n"},
        ),
    ):
        repository = home / "Code" / "ignore-rules" / name
        repository.mkdir(parents=True)
        _git(repository, "init", "--quiet", "--initial-branch=main", home=home)
        _write(repository / ".gitignore", ignore)
        for relative, text in files.items():
            _write(repository / relative, text)
        _git(repository, "add", "-A", home=home)
        _git(repository, "commit", "--quiet", "-m", f"{name} base", home=home)
    # A non-repository parent under /tmp whose repository has a linked worktree beside the parent.
    tmp_org = Path(tempfile.mkdtemp(prefix="org.", dir=_system_tmp())).resolve() / "org"
    (tmp_org / "app").mkdir(parents=True)
    _git(tmp_org / "app", "init", "--quiet", "--initial-branch=main", home=home)
    _write(tmp_org / "app" / "README.md", "# app\n")
    _write(home / ".nvm" / "versions" / "node" / "v25.2.1" / "lib" / "node_modules" / "npm" / "package.json", "{}\n")
    _write(home / ".bun" / "install" / "global" / "node_modules" / "vite" / "package.json", "{}\n")
    # Installed dependency and toolchain source under hidden home directories.
    pipx_site = home / ".local" / "pipx" / "venvs" / "tool" / "lib" / "python3.12" / "site-packages"
    _write(pipx_site / "pkg" / "mod.py", "_COLD_START = 0.5\n")
    _write(home / ".local" / "lib" / "python3.12" / "site-packages" / "pkg" / "mod.py", "X = 1\n")
    _write(home / ".cargo" / "registry" / "src" / "index" / "serde-1.0.0" / "src" / "lib.rs", "pub fn serde() {}\n")
    rustlib_core = home / ".rustup" / "toolchains" / "stable" / "lib" / "rustlib" / "src" / "rust" / "library" / "core"
    _write(rustlib_core / "src" / "lib.rs", "//! core\n")
    _write(tmp_org / "app" / "package.json", '{"name": "app", "version": "1.0.0"}\n')
    _write(tmp_org / "app" / "src" / "index.ts", "export const railStage = 1;\n")
    _write(tmp_org / "app" / "tests" / "index.test.ts", "import { railStage } from '../src';\n")
    _write(tmp_org / "app" / "scripts" / "report.py", "print('report')\n")
    _git(tmp_org / "app", "add", "-A", home=home)
    _git(tmp_org / "app", "commit", "--quiet", "-m", "app base", home=home)
    followup = str(tmp_org.parent / "app-followup")
    _git(tmp_org / "app", "worktree", "add", "--quiet", "-b", "followup", followup, home=home)
    remote = tmp_org.parent / "remote" / "app.git"
    _git(tmp_org.parent, "clone", "--quiet", "--bare", str(tmp_org / "app"), str(remote), home=home)
    _git(tmp_org / "app", "remote", "add", "origin", str(remote), home=home)
    # A benchmark checkout outside HOME whose test vectors are named for secrets and tokens.
    bench = tmp_org.parent / BENCH_CHECKOUT
    for relative, text in BENCH_FILES.items():
        _write(bench / relative, text)
    _git(bench, "init", "--quiet", "--initial-branch=main", home=home)
    _git(bench, "add", "-A", home=home)
    _git(bench, "commit", "--quiet", "-m", "bench base", home=home)
    # A leaf directly in /tmp that does not exist yet, as a throwaway checkout destination.
    scratch = Path(_system_tmp()) / f"hg-fp-scratch-{os.getpid()}-{secrets.token_hex(4)}"
    return BenignFixture(
        root, home, parent, worktree, nested, gitlink_repo, guard_home, private_tmp, tmp_worktree, org, tmp_org, scratch
    )


def route_codex(result: dict[str, object], payload: dict[str, object], fixture: BenignFixture) -> dict[str, object]:
    """Run the real Codex bridge rewrite for a Codex release that applies ``updatedInput``.

    Codex before 0.131 keeps the denial with an update hint, so the gates model
    0.131 or later and say nothing about older releases. The contained request
    file goes to the fixture's own directory, which ``cleanup`` removes.
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(codex_contained_tests, "launching_codex_executable", lambda: Path("/usr/local/bin/codex"))
        patch.setattr(codex_contained_tests, "codex_applies_updated_input", lambda *_args, **_kwargs: True)
        fixture.contained_requests.mkdir(exist_ok=True)
        patch.setattr(tempfile, "tempdir", str(fixture.contained_requests))
        return codex_contained_tests.route_codex_containment(
            dict(result),
            hook_input=json.dumps(payload),
            guard_home=fixture.guard_home,
            home_dir=fixture.home,
        )
