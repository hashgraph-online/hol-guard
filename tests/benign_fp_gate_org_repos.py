"""Repositories below the fixture home whose shared parent is not a repository.

``~/Code/org`` holds ``app-portal``, ``service-api`` and ``docs-site``;
``~/Code/ignore-rules`` holds checkouts whose ``.gitignore`` re-includes paths.
"""

from __future__ import annotations

from pathlib import Path

from tests.benign_fp_gate_git import _git
from tests.benign_fp_gate_projects import _NODE_PACKAGES, _node_toolchain, _sibling_test_runner, _write


def write_org_repos(org: Path, home: Path) -> None:
    for name in ("app-portal", "service-api"):
        repository = org / name
        repository.mkdir(parents=True)
        _git(repository, "init", "--quiet", "--initial-branch=main", home=home)
        _write(repository / ".github" / "workflows" / "ci.yml", "name: ci\n")
        # Tracked content a checkout keeps in hidden directories: the manifest
        # a harness is installed from and the card a web client publishes.
        _write(repository / ".codex-plugin" / "plugin.json", f'{{"name": "{name}"}}\n')
        _write(repository / ".well-known" / "agent-card.json", f'{{"name": "{name}"}}\n')
        # A workflow named after a tool, and a published agent card whose name
        # is the vendor word on its own.
        _write(repository / ".github" / "workflows" / "docker.yml", "name: docker\n")
        _write(repository / ".well-known" / "agent.json", f'{{"name": "{name}"}}\n')
        # Targets for the negatives beside them: the repository's own
        # administrative tree, a credential store name and a compiled blob.
        _write(repository / ".git" / "hooks" / "pre-commit.sh", "#!/bin/sh\nexit 0\n")
        _write(repository / ".codex-plugin" / "credentials.json", "{}\n")
        _write(repository / ".codex-plugin" / "runtime.node", "\x00binary\n")
        # A tool's own tree, a config file spelled as a directory and a
        # credential store holding a file named as source.
        # Tooling settings the checkout keeps under its own hidden
        # directories. Their stems name a credential store as often as they
        # name an ordinary project document, so the file is read rather than
        # refused on its name alone.
        _write(repository / ".circleci" / "config.yml", "version: 2.1\njobs: {}\n")
        _write(repository / ".changeset" / "config.json", '{"changelog": "@changesets/cli/changelog"}\n')
        _write(repository / ".storybook" / "settings.json", '{"framework": "react"}\n')
        # A credential written across several lines, and one quoted word that
        # a document writes bare when it means "nothing here".
        _write(
            repository / ".storybook" / "config.toml",
            '[registry]\ntoken = """\nhunter2\n"""\n',
        )
        _write(repository / ".changeset" / "settings.json", '{"npmAuthToken": "null"}\n')
        # A mapping that leaves its value for the next line, indented deeper.
        _write(
            repository / ".storybook" / "config.yml",
            "database:\n  password:\n    hunter2\n",
        )
        # The same stem over a registry credential, for the negative beside it.
        _write(
            repository / ".cargo" / "config.toml",
            '[registries.internal]\ntoken = "' + "AKIA" + "QYLPT3K7" + "R4FXM2WD" + '"\n',
        )
        _write(repository / ".cursor" / "mcp.json", '{"mcpServers": {}}\n')
        _write(repository / ".dockerignore" / "notes.md", "# fixture\n")
        _write(repository / ".secrets" / "read.py", "TOKEN = 'fixture'\n")
        _write(repository / "src" / "index.ts", f"export const name = '{name}';\n")
        # Sign-in helpers kept under a source directory named for the feature.
        _write(repository / "src" / "lib" / "auth" / "session.ts", "export function useAuth() {}\n")
        _write(repository / "src" / "lib" / "session" / "auth" / "button.tsx", "export function SignInButton() {}\n")
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
        if name == "app-portal":
            # Installed with pnpm, so the package store and the build cache sit
            # beside `node_modules/.bin`. The tree itself is written after the
            # commit below, untracked the way a real install is.
            _write(repository / ".gitignore", "node_modules/\n")
        _git(repository, "add", "-A", home=home)
        _git(repository, "commit", "--quiet", "-m", f"{name} base", home=home)
        if name == "service-api":
            _git(repository, "remote", "add", "origin", "https://github.com/example-org/service-api.git", home=home)
            _git(repository, "update-ref", "refs/remotes/origin/main", "HEAD", home=home)
    # The package store and build cache a pnpm install leaves in `app-portal`.
    # Agents list them to see which manager ran and whether a cache is warm.
    # The tree itself is installed with the checkout, so only the store entry
    # and the cache are written here.
    portal = org / "app-portal"
    store_entry = f"vitest@{_NODE_PACKAGES['vitest']}"
    _write(
        portal / "node_modules" / ".pnpm" / store_entry / "node_modules" / "vitest" / "package.json",
        '{"name": "vitest"}\n',
    )
    _write(portal / "node_modules" / ".cache" / "vite" / "deps" / "_metadata.json", "{}\n")
    # A sibling checkout that keeps no workflows, where a probe finds nothing.
    docs_site = org / "docs-site"
    _write(docs_site / "README.md", "# docs-site\n")
    # A design tool's own dot-folder, committed beside the docs it describes.
    _write(docs_site / "docs" / "guide.md", "# Guide\n\nThe palette.\n")
    _write(
        docs_site / "docs" / "design" / ".designtool" / "design.json",
        '{"palette": {"primary": "#1f6feb"}}\n',
    )
    _git(docs_site, "init", "--quiet", "--initial-branch=main", home=home)
    _git(docs_site, "add", "-A", home=home)
    _git(docs_site, "commit", "--quiet", "-m", "docs-site base", home=home)


def write_ignore_rule_repos(home: Path) -> None:
    # Repositories whose `.gitignore` re-includes literal paths: an ordinary
    # kept file and editor setting, and a committed `.env` template. A command
    # that takes the template as an operand is still screened; a plain read of
    # it is ordinary work.
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
        if name == "billing-api":
            # Untracked, gitignored synthetic secret for rg glob override controls.
            # Plain source globs cannot reach it; an explicit -g "**" can.
            _write(repository / ".env", "TOKEN=SYNTHETIC_MARKER_ONLY\n")
