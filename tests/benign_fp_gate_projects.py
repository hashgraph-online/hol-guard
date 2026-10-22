"""Project trees the benign fixture writes: the toolchains a working checkout holds.

A real checkout is rarely Node, Python, Make, Go and Cargo at once, but each of
these entry points is a command shape agents run dozens of times an hour, and
none of them is interesting enough to review. They live beside the fixture's
git shapes rather than inside :mod:`tests.benign_fp_gate_fixture` so that each
file stays about one thing.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
from pathlib import Path

from ci.gauntlet.realism_fixtures import activate_script

# A source file the parent repository commits before any worktree exists, so
# the shapes that read a file's history have history to read. Every other file
# the fixture commits is a line or two, and `git blame -L1,20` on a four-line
# file fails for the range rather than for anything Guard decided, which would
# let a blame case pass while proving nothing.
COMMITTED_SOURCE = """export type ReportWindow = "24h" | "7d" | "30d";

export interface ReportRequest {
  window: ReportWindow;
  workspaceId: string;
  includeDrafts: boolean;
}

const WINDOW_HOURS: Record<ReportWindow, number> = {
  "24h": 24,
  "7d": 24 * 7,
  "30d": 24 * 30,
};

export function windowStart(request: ReportRequest, now: Date): Date {
  const hours = WINDOW_HOURS[request.window];
  return new Date(now.getTime() - hours * 60 * 60 * 1000);
}

export function describe(request: ReportRequest): string {
  const drafts = request.includeDrafts ? "with drafts" : "without drafts";
  return `${request.workspaceId}: ${request.window} ${drafts}`;
}
"""


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


_NODE_PACKAGES = {"vite": "7.1.5", "vitest": "3.2.4", "wrangler": "4.20.0"}
# The rest of the toolchain a working project installs: type checker, linter,
# formatter, second test runner, TypeScript runner and task runner. Each entry
# names the binaries npm links, which for TypeScript is not the package name.
_NODE_TOOLS = {
    "typescript": ("5.9.2", ("tsc",)),
    "eslint": ("9.33.0", ("eslint",)),
    "prettier": ("3.6.2", ("prettier",)),
    "jest": ("30.0.5", ("jest",)),
    "tsx": ("4.20.3", ("tsx",)),
    "turbo": ("2.5.5", ("turbo",)),
}
_TOOL_SCRIPTS = {"lint": "eslint .", "typecheck": "tsc --noEmit", "format": "prettier --check ."}
_INSTALLED_PACKAGES = _NODE_PACKAGES | {name: version for name, (version, _) in _NODE_TOOLS.items()}


def _node_toolchain(workspace: Path, *, tools: bool = False) -> None:
    packages = dict(_NODE_PACKAGES)
    if tools:
        packages |= {name: version for name, (version, _) in _NODE_TOOLS.items()}
    dependencies = {name: f"^{version}" for name, version in packages.items()}
    locked = {
        f"node_modules/{name}": {"version": version, "integrity": "sha512-fixture"}
        for name, version in packages.items()
    }
    scripts = {"build": "vite build", "test": "vitest run"} | (_TOOL_SCRIPTS if tools else {})
    manifest = {"private": True, "scripts": scripts, "devDependencies": dependencies}
    _write(workspace / "package.json", json.dumps(manifest) + "\n")
    _write(workspace / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": locked}) + "\n")
    # Agents reach for `yarn build` in a checkout that carries a yarn lockfile, not only `npm run`.
    _write(workspace / "yarn.lock", _yarn_lockfile(packages))
    _write(workspace / "tests" / "sample.test.ts", "export const sample = 1;\n")
    for name, version in _NODE_PACKAGES.items():
        _node_package(workspace, name, version)
    if not tools:
        return
    for name, (version, binaries) in _NODE_TOOLS.items():
        _node_package(workspace, name, version, binaries)
    _write(workspace / "tsconfig.json", json.dumps({"compilerOptions": {"strict": True, "noEmit": True}}) + "\n")
    _write(workspace / "eslint.config.js", "export default [];\n")
    _write(workspace / ".prettierrc", "{}\n")


def _sibling_test_runner(repository: Path) -> None:
    """Jest installed at a checkout's root: its launcher loads the CLI package, as the real one does."""
    modules = repository / "node_modules"
    _write(modules / "jest" / "package.json", json.dumps({"name": "jest", "version": "30.0.5"}) + "\n")
    _write(
        modules / "jest" / "bin" / "jest.js",
        "#!/usr/bin/env node\nconst importLocal = require('import-local');\n"
        "if (!importLocal(__filename)) {\n  require('jest-cli/bin/jest');\n}\n",
    )
    _write(modules / "import-local" / "index.js", "module.exports = () => false;\n")
    _write(modules / "jest-cli" / "bin" / "jest.js", "console.log('jest-cli 30.0.5');\n")
    _write(repository / "jest.config.js", "module.exports = {};\n")


def _yarn_lockfile(packages: dict[str, str]) -> str:
    """A classic ``yarn.lock``, the file that makes ``yarn build`` the project's spelling."""
    entries = [
        f'"{name}@^{version}":\n  version "{version}"\n  resolved "https://registry.yarnpkg.com/{name}"\n'
        for name, version in packages.items()
    ]
    return "# yarn lockfile v1\n\n" + "\n".join(entries)


def _node_package(workspace: Path, name: str, version: str, binaries: tuple[str, ...] = ()) -> None:
    """One installed package with its ``node_modules/.bin`` shims, as npm links them."""
    binaries = binaries or (name,)
    package = workspace / "node_modules" / name
    manifest = {"name": name, "version": version, "bin": {binary: f"./bin/{binary}.js" for binary in binaries}}
    _write(package / "package.json", json.dumps(manifest) + "\n")
    for binary in binaries:
        script = package / "bin" / f"{binary}.js"
        _write(script, f"#!/usr/bin/env node\nconsole.log('{binary} {version}');\n")
        script.chmod(0o755)
        shim = workspace / "node_modules" / ".bin" / binary
        shim.parent.mkdir(parents=True, exist_ok=True)
        shim.symlink_to(Path("..") / name / "bin" / f"{binary}.js")


def _python_toolchain(workspace: Path) -> None:
    """Project virtualenv with the console scripts ``uv sync`` installs into it."""
    project = {
        "project": {"name": "fixture-app", "version": "0.1.0", "requires-python": ">=3.12"},
        "dependency-groups": {"dev": ["pytest>=8.4", "ruff>=0.12", "mypy>=1.17"]},
    }
    _write(workspace / "pyproject.toml", _toml(project))
    _write(workspace / "src" / "fixture_app" / "__init__.py", "VERSION = '0.1.0'\n")
    _write(workspace / "tests" / "test_fixture_app.py", "def test_version():\n    assert True\n")
    venv = workspace / ".venv"
    base = workspace / ".fixture-python" / "bin" / "python3"
    base.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(sys.executable, base)
    base.chmod(0o755)
    _write(venv / "pyvenv.cfg", f"home = {base.parent}\nversion = 3.12.3\ninclude-system-site-packages = false\n")
    # `pip` and `pip3` come with the environment itself, so a project reads
    # its installed packages through them as readily as it runs its tools.
    for name in ("pytest", "ruff", "mypy", "pip", "pip3"):
        script = venv / "bin" / name
        _write(script, f"#!/bin/sh\nexec echo '{name}'\n")
        script.chmod(0o755)
    packages = venv / "lib" / "python3.12" / "site-packages"
    _write(packages / "pytest" / "__init__.py", "__version__ = '8.4.1'\n")
    # `python -m pytest` is the other spelling agents reach for, and it reads
    # the package's entry module rather than the console script.
    _write(packages / "pytest" / "__main__.py", "raise SystemExit(0)\n")
    # The script `source .venv/bin/activate` reads, which agents run before the
    # tools rather than spelling out `.venv/bin/`. It is the generated script,
    # not a short stand-in: the shapes that made Guard stop the command are the
    # ones a hand-written file does not have - a `deactivate` function body,
    # `unset -f`, an `alias`/`unalias` pair, command substitutions and
    # `hash -r`. A fixture without them proves nothing about a real venv.
    _write(venv / "bin" / "activate", activate_script(venv))
    # Keep the real executable's bytes and the venv's symlink, but place the
    # base in the fixture's executable roots. The gate never runs Python; a
    # link to the host's interpreter otherwise measures the runner's layout.
    (venv / "bin" / "python").symlink_to(base)
    (venv / "bin" / "python3").symlink_to("python")


def _toml(payload: dict[str, object]) -> str:
    """The subset of TOML this fixture writes: tables of scalars and string lists."""
    lines: list[str] = []
    for table, entries in payload.items():
        lines.append(f"[{table}]")
        for key, value in entries.items():  # pyright: ignore[reportAttributeAccessIssue]
            lines.append(f"{key} = {json.dumps(value)}")
        lines.append("")
    return "\n".join(lines)


def _build_toolchain(workspace: Path) -> None:
    """Make, Go and Cargo entry points beside the Node and Python ones."""
    _write(
        workspace / "Makefile",
        "build:\n\tnpm run build\n\ntest:\n\tnpm test\n\nlint:\n\tnpm run lint\n",
    )
    _write(workspace / "go.mod", "module example.invalid/fixture\n\ngo 1.23\n")
    _write(workspace / "main.go", 'package main\n\nfunc main() {\n\tprintln("fixture")\n}\n')
    _write(workspace / "main_test.go", 'package main\n\nimport "testing"\n\nfunc TestMain(t *testing.T) {}\n')
    # Agents move entry points into `cmd/` constantly; the move is only a real
    # shape when the destination directory already exists, because `mv` onto a
    # missing path renames the file instead of moving it into a directory.
    _write(workspace / "cmd" / "README.md", "Command entry points.\n")
    _write(workspace / "Cargo.toml", '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n')
    _write(workspace / "src" / "lib.rs", "pub fn fixture() -> u8 {\n    1\n}\n")
    # `just` and `pre-commit` are the other two task runners agents drive from a checkout root.
    _write(workspace / "justfile", "build:\n    npm run build\n\ntest:\n    npm test\n")
    _write(
        workspace / ".pre-commit-config.yaml",
        "repos:\n  - repo: local\n    hooks:\n      - id: lint\n        name: lint\n"
        "        entry: npm run lint\n        language: system\n",
    )


def _bun_lockfile(project: Path, packages: dict[str, str]) -> None:
    """A text ``bun.lock`` pinning registry packages, as ``bun install`` writes it."""
    manifest = {"devDependencies": {name: f"^{version}" for name, version in packages.items()}}
    locked = {name: [f"{name}@{version}", "", {}, "sha512-fixture"] for name, version in packages.items()}
    lockfile = {"lockfileVersion": 1, "workspaces": {"": manifest}, "packages": locked}
    _write(project / "bun.lock", json.dumps(lockfile, indent=2) + "\n")


def host_tool_path(home: Path, search_path: str) -> str:
    """``search_path`` with the host tools the gates need but a hosted runner cannot offer.

    The native ``bun -e`` proof resolves ``bun`` from PATH, and hosted runners ship no Bun, so a
    stand-in sits where Bun's installer puts it; a real Bun earlier on PATH still wins. Hosted
    runners keep Node in a world-writable ``/usr/local/bin``, which the workspace sandbox refuses
    to execute from, so a package script would stay at review for the host instead of running
    contained. Stand-ins in a version-manager directory the sandbox accepts go first, as a
    developer's own Node does, and the sandbox finds the same file by the same name. Yarn sits beside
    them because a project that runs ``yarn build`` is as ordinary as one that runs ``npm run build``,
    and a runner without Yarn would measure a missing binary rather than Guard. SQLite sits there
    for the same reason from the other direction: every macOS developer has a ``sqlite3``, but where
    a host keeps it differs, and a hosted runner's copy resolves outside the roots the sandbox
    executes from, so the gate would be measuring that host's package layout rather than the command
    a model ran. The synthetic connector CLIs install into ``~/.local/bin``, which a real login
    shell has on PATH; it goes first so the fixture CLI, not a host program, is the one a grant was
    recorded for. ``uv`` is there for the same reason as SQLite: a runner installs it wherever its
    own setup put it, often a directory the sandbox executes nothing from, so a stand-in sits in
    the Cargo bin directory a developer's own ``uv`` resolves from and the gate measures the
    command rather than the runner's layout.
    """
    stand_in = "#!/bin/sh\nexit 0\n"
    bun = home / ".bun" / "bin"
    node = home / ".nvm" / "versions" / "node" / "v25.2.1" / "bin"
    sqlite = home / ".asdf" / "installs" / "sqlite" / "3.46.1" / "bin"
    cargo = home / ".cargo" / "bin"
    tools = (
        (bun, ("bun",)),
        (node, ("node", "npm", "npx", "yarn")),
        (sqlite, ("sqlite3",)),
        (cargo, ("uv",)),
    )
    for directory, names in tools:
        for name in names:
            _write(directory / name, stand_in)
            (directory / name).chmod(0o755)
    local_bin = home / ".local" / "bin"
    return os.pathsep.join(
        [str(local_bin), str(node), str(sqlite), str(cargo), search_path, str(bun)]
    )


def _application_database(path: Path) -> None:
    """A real SQLite file, because an agent's `.tables` and `.schema` run against one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL)")
        connection.execute("CREATE TABLE sessions (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL)")
        connection.commit()
    finally:
        connection.close()
