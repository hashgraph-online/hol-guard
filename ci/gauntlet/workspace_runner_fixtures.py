"""The project's own test runner, installed in the workspace and launched through npx.

An agent that runs a repository's tests types ``npx jest`` or ``npx mocha``: npm
resolves the
runner from the workspace's own ``node_modules`` and runs it once. The install
is the shape npm leaves behind — a manifest that declares the version, a
lockfile that pins it, the package's own manifest and bin, and the
``node_modules/.bin`` link npx resolves through — so a routine local runner is
recognised as local rather than as a package fetched for the occasion.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import NamedTuple

WORKSPACE_JEST_CASE = "omp-native-workspace-npx-jest"
# The same install, launched the way a Node project's own scripts name it: the
# installed entry point relative to the workspace root rather than through
# ``node_modules/.bin``.
WORKSPACE_NODE_ENTRY_CASE = "omp-native-workspace-node-jest-entry"
# The same install, launched through npm's own exec spelling with the install
# prompt already answered. ``--no`` forbids fetching anything, so the run only
# finishes if the workspace's own runner is what npm resolves.
WORKSPACE_NPM_EXEC_CASE = "omp-native-workspace-npm-exec-inert-option"
# The same install, launched with the heap size a large suite needs written in
# front of it. The setting only sizes the engine, so the run has to finish the
# same way the unprefixed launch does.
WORKSPACE_HEAP_PREFIX_CASE = "omp-native-workspace-node-options-heap-prefix"
# The other runner a Node project installs for itself. Mocha runs its suite once
# and exits unless it is told to watch, so the plain launch is the routine one.
WORKSPACE_MOCHA_CASE = "omp-native-workspace-npx-mocha"
# The same install, launched through the project's own name for one part of its
# suite. A project with more than one kind of test names them `test:unit`,
# `test:types` and so on, and npm runs whatever the entry holds, so the named
# entry has to be read the way the plain `test` entry is.
WORKSPACE_NAMED_TEST_SCRIPT_CASE = "omp-native-workspace-named-test-script"
WORKSPACE_RUNNER_CASES = frozenset(
    {
        WORKSPACE_JEST_CASE,
        WORKSPACE_NODE_ENTRY_CASE,
        WORKSPACE_NPM_EXEC_CASE,
        WORKSPACE_HEAP_PREFIX_CASE,
        WORKSPACE_MOCHA_CASE,
        WORKSPACE_NAMED_TEST_SCRIPT_CASE,
    }
)
# The same installed build, launched through the Bun the installer leaves in the
# caller's home, spelled by the path its install instructions print.
HOME_BUN_ENTRY_CASE = "omp-native-shell-home-spelled-bun-entry"
# Where Bun's own installer puts it, and the path its instructions tell you to run.
_BUN_BIN = ".bun/bin"
# Where nvm, the way most developers install Node, keeps each release.
_NODE_VERSIONS = ".nvm/versions/node"
_NODE_VERSION = re.compile(r"v\d+\.\d+\.\d+")
_VERSION = "30.0.5"
# The one line the workspace's own runner prints, which only a real launch produces.
RUNNER_MARKER = f"jest-cli {_VERSION}"
_FILES = {
    "package.json": (
        '{\n  "name": "synthetic-app",\n  "private": true,\n  "version": "0.0.0",\n'
        '  "scripts": {\n    "test:unit": "jest --ci"\n  },\n'
        f'  "devDependencies": {{\n    "jest": "{_VERSION}"\n  }}\n}}\n'
    ),
    "package-lock.json": (
        '{\n  "name": "synthetic-app",\n  "version": "0.0.0",\n  "lockfileVersion": 3,\n'
        '  "requires": true,\n  "packages": {\n    "": {\n      "name": "synthetic-app",\n'
        '      "version": "0.0.0",\n      "devDependencies": {\n'
        f'        "jest": "{_VERSION}"\n      }}\n    }},\n'
        '    "node_modules/jest": {\n'
        f'      "version": "{_VERSION}",\n      "dev": true,\n'
        '      "bin": {\n        "jest": "bin/jest.js"\n      }\n    }\n  }\n}\n'
    ),
    "jest.config.js": "module.exports = {};\n",
    "node_modules/jest/package.json": (
        f'{{"name": "jest", "version": "{_VERSION}", "bin": {{"jest": "bin/jest.js"}}}}\n'
    ),
    "node_modules/jest/bin/jest.js": (
        "#!/usr/bin/env node\nconst importLocal = require('import-local');\n"
        "if (!importLocal(__filename)) {\n  require('jest-cli/bin/jest');\n}\n"
    ),
    "node_modules/import-local/index.js": "module.exports = () => false;\n",
    "node_modules/jest-cli/bin/jest.js": f"console.log('{RUNNER_MARKER}');\n",
}
_MOCHA_VERSION = "11.7.5"
# The one line the workspace's own Mocha prints, which only a real launch produces.
MOCHA_MARKER = f"mocha {_MOCHA_VERSION}"
_MOCHA_FILES = {
    "package.json": (
        '{\n  "name": "synthetic-app",\n  "private": true,\n  "version": "0.0.0",\n'
        f'  "devDependencies": {{\n    "mocha": "{_MOCHA_VERSION}"\n  }}\n}}\n'
    ),
    "package-lock.json": (
        '{\n  "name": "synthetic-app",\n  "version": "0.0.0",\n  "lockfileVersion": 3,\n'
        '  "requires": true,\n  "packages": {\n    "": {\n      "name": "synthetic-app",\n'
        '      "version": "0.0.0",\n      "devDependencies": {\n'
        f'        "mocha": "{_MOCHA_VERSION}"\n      }}\n    }},\n'
        '    "node_modules/mocha": {\n'
        f'      "version": "{_MOCHA_VERSION}",\n      "dev": true,\n'
        '      "bin": {\n        "mocha": "bin/mocha.js",\n'
        '        "_mocha": "bin/_mocha.js"\n      }\n    }\n  }\n}\n'
    ),
    ".mocharc.json": '{\n  "spec": "test/**/*.spec.js"\n}\n',
    "test/sample.spec.js": (
        "const assert = require('node:assert');\n\n"
        "describe('settings', () => {\n"
        "  it('reads its own defaults', () => {\n    assert.ok(true);\n  });\n});\n"
    ),
    "node_modules/mocha/package.json": (
        f'{{"name": "mocha", "version": "{_MOCHA_VERSION}", "bin": '
        '{"mocha": "bin/mocha.js", "_mocha": "bin/_mocha.js"}}\n'
    ),
    # Mocha's launcher hands the run to the worker beside it, the way the real
    # package does once it has settled on the options the run needs.
    "node_modules/mocha/bin/mocha.js": ("#!/usr/bin/env node\nrequire('./_mocha.js');\n"),
    "node_modules/mocha/bin/_mocha.js": (f"#!/usr/bin/env node\nconsole.log('{MOCHA_MARKER}');\n"),
}


class _Install(NamedTuple):
    """One runner's install: the package npm links, its files and its own line."""

    name: str
    files: dict[str, str]
    marker: str


_JEST_INSTALL = _Install("jest", _FILES, RUNNER_MARKER)
_INSTALLS = {WORKSPACE_MOCHA_CASE: _Install("mocha", _MOCHA_FILES, MOCHA_MARKER)}


def runner_marker(scenario_id: str | None) -> str:
    """The line the runner this case installs prints when it really launches."""
    return _INSTALLS.get(scenario_id or "", _JEST_INSTALL).marker


def add_workspace_test_runner(workspace: Path, scenario_id: str | None) -> None:
    """Install the runner inside the workspace, untracked as ``npm install`` leaves it."""
    if scenario_id not in WORKSPACE_RUNNER_CASES:
        return
    installed = _INSTALLS.get(scenario_id or "", _JEST_INSTALL)
    for relative, text in installed.files.items():
        target = workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
    entry = Path(f"node_modules/{installed.name}/bin/{installed.name}.js")
    (workspace / entry).chmod(0o755)
    link = workspace / "node_modules/.bin"
    link.mkdir(parents=True, exist_ok=True)
    # npm links each bin relative to node_modules/.bin.
    (link / installed.name).symlink_to(Path("..") / entry.relative_to("node_modules"))


def workspace_node_bin(home: Path) -> Path | None:
    """The fixture's own Node directory, once a case has planted one."""
    root = home / _NODE_VERSIONS
    if not root.is_dir():
        return None
    for version in sorted(root.iterdir()):
        if (version / "bin" / "node").is_file():
            return version / "bin"
    return None


def add_workspace_node_runtime(home: Path, scenario_id: str | None) -> None:
    """Give the fixture home the nvm Node install the contained runner trusts.

    The read-only runner profile runs the workspace's entry point under Node,
    and it accepts only a Node that the request's own home or a system prefix
    owns. The host's Node is copied, not linked, so nothing the fixture does
    can reach the file the host runs.
    """
    if scenario_id not in WORKSPACE_RUNNER_CASES:
        return
    located = shutil.which("node")
    if located is None:
        raise RuntimeError("Gauntlet prerequisite is missing: node")
    source = Path(os.path.realpath(located))
    version = subprocess.run(
        [str(source), "--version"], capture_output=True, text=True, timeout=30, check=True
    ).stdout.strip()
    if not _NODE_VERSION.fullmatch(version):
        raise RuntimeError(f"Node reported an unexpected version for the fixture toolchain: {version}")
    target = home / _NODE_VERSIONS / version / "bin" / "node"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def home_bun_bin(home: Path) -> Path | None:
    """The fixture's own Bun directory, once a case has planted one.

    Bun's installer adds this directory to the login shell's PATH, so a
    developer shell that runs ``~/.bun/bin/bun`` also has it on PATH.
    """
    directory = home / _BUN_BIN
    return directory if (directory / "bun").is_file() else None


def _host_bun() -> str | None:
    """The host's Bun, skipping a Guard package shim that stands in front of it.

    A shim is a script that hands the launch to Guard's own runtime, so a copy
    of it would plant Guard's launcher, not Bun, where the case runs Bun.
    """
    entries = os.environ.get("PATH", "").split(os.pathsep)
    search = [entry for entry in entries if Path(entry).parts[-2:] != ("package-shims", "bin")]
    return shutil.which("bun", path=os.pathsep.join(search))


def add_home_bun_runtime(home: Path, scenario_id: str | None) -> None:
    """Install Bun where its own installer puts it, so a case can name it from home.

    An agent runs the launcher the install instructions give it,
    ``~/.bun/bin/bun``. The host's binary is copied rather than linked, so
    nothing the fixture does can reach the file the host runs.
    """
    if scenario_id != HOME_BUN_ENTRY_CASE:
        return
    located = _host_bun()
    if located is None:
        raise RuntimeError("Gauntlet prerequisite is missing: bun")
    target = home / _BUN_BIN / "bun"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(Path(os.path.realpath(located)), target)
