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

import json
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
# The same install, launched with the flag an ESM suite needs in front of it.
# The setting only turns on Node's module VM classes, so the run has to finish
# the same way the unprefixed launch does.
WORKSPACE_VM_MODULES_PREFIX_CASE = "omp-native-workspace-node-options-vm-modules-prefix"
# The same install, launched with npm's own logging key written in front of
# it. The setting only decides how much npm prints, so the run has to finish
# the same way the unprefixed launch does.
WORKSPACE_NPM_CONFIG_PREFIX_CASE = "omp-native-workspace-npm-config-loglevel-prefix"
# The other runner a Node project installs for itself. Mocha runs its suite once
# and exits unless it is told to watch, so the plain launch is the routine one.
WORKSPACE_MOCHA_CASE = "omp-native-workspace-npx-mocha"
# The runner a Node project reaches for when it wants its tests to run as
# separate processes. AVA runs its suite once and exits unless it is asked to
# watch, so the plain launch is the routine one.
WORKSPACE_AVA_CASE = "omp-native-workspace-npx-ava"
# The runners that take one pass and have nowhere else to go. Jasmine, uvu,
# tape, tsd and cucumber-js have no watch mode at all and QUnit watches only
# when it is asked to, so for each of them the plain launch is the routine one.
WORKSPACE_JASMINE_CASE = "omp-native-workspace-npx-jasmine"
WORKSPACE_QUNIT_CASE = "omp-native-workspace-npx-qunit"
WORKSPACE_UVU_CASE = "omp-native-workspace-npx-uvu"
WORKSPACE_TAPE_CASE = "omp-native-workspace-npx-tape"
WORKSPACE_TSD_CASE = "omp-native-workspace-npx-tsd"
WORKSPACE_CUCUMBER_CASE = "omp-native-workspace-npx-cucumber-js"
# The same install, launched through the project's own name for one part of its
# suite. A project with more than one kind of test names them `test:unit`,
# `test:types` and so on, and npm runs whatever the entry holds, so the named
# entry has to be read the way the plain `test` entry is.
WORKSPACE_NAMED_TEST_SCRIPT_CASE = "omp-native-workspace-named-test-script"
# A checking script run with one more option of its own: the manager hands the
# words after `--` to the script, so the run is the tool the manifest names
# holding them.
WORKSPACE_SCRIPT_PASSED_OPTION_CASE = "omp-native-workspace-script-passed-option"
# The same checking script, asked for quietly. The option names no script and
# only chooses how much the manager prints, so the run has to reach the script
# the plain spelling reaches.
WORKSPACE_QUIET_SCRIPT_RUN_CASE = "omp-native-workspace-quiet-script-run"
# npm's own longer spelling of the same verb. The run it names is the script,
# so it has to reach the same place the short spelling reaches.
WORKSPACE_SCRIPT_RUN_ALIAS_CASE = "omp-native-workspace-script-run-alias"
# The project's own suite, asked for the four ways a developer asks for it
# without the manager's own chatter. Each option names no script and only
# chooses how much npm prints, so every spelling has to reach the suite the
# plain `npm test` reaches.
WORKSPACE_QUIET_PACKAGE_TEST_CASE = "omp-native-workspace-quiet-package-test"
# The type checker a TypeScript project installs for itself. `tsc` is the only
# routine runner whose executable name is not its package name: npm installs it
# inside `typescript`, so the tree, the manifest and the lockfile all say
# `typescript` while `node_modules/.bin` says `tsc`.
WORKSPACE_TSC_CASE = "omp-native-workspace-npx-tsc"
# The same checker run as a repository script runs it: a generated project keeps
# the no-emit mode in the file, so the command line carries no option at all and
# the run is proven read-only from the project it names.
WORKSPACE_TSC_GENERATED_PROJECT_CASE = "omp-native-workspace-tsc-generated-project"
# The same type checker in a workspace pnpm installed. pnpm writes its lockfile
# in YAML rather than JSON, so the pin the verdict reads is the same fact
# written in another dialect.
WORKSPACE_PNPM_TSC_CASE = "omp-native-workspace-pnpm-npx-tsc"
# The other runner a Node project installs for itself, named the way a developer
# narrows a run: the file to run beside the option that stops Vitest watching.
# A filter is not a Vitest command, so the run is the same single pass the bare
# `run` verb names.
WORKSPACE_VITEST_FILTER_CASE = "omp-native-workspace-vitest-filter"
# The same installed Vitest launched by a file its install wrote: Node given the
# link npm puts in `node_modules/.bin`, and Bun given the package's own launcher.
# Both name the workspace's runner, so the run means something only when that
# runner is installed.
WORKSPACE_VITEST_BIN_LINK_CASE = "omp-native-workspace-node-bin-link-runner"
WORKSPACE_VITEST_BUN_ENTRY_CASE = "omp-native-workspace-bun-runner-entry"
# The commit hook a project runs over its staged files. It is declared,
# installed and pinned exactly as the linter it drives is, and it is launched
# through npx the same way, so the verdict has the same evidence to read.
WORKSPACE_LINT_STAGED_CASE = "omp-native-workspace-npx-lint-staged"
# The TypeScript runner a project installs to run Node's own test runner over
# its sources. `--test` puts Node in test-runner mode, so the words behind the
# flags are the files it loads rather than the first file's arguments.
WORKSPACE_TSX_NODE_TEST_CASE = "omp-native-workspace-npx-tsx-node-test"
# The script runner a Node project installs to drive several of its own scripts
# at once. Its own name carries a manager's inside it, and it installs nothing:
# every script it names is already in the project's manifest.
WORKSPACE_RUN_ALL_CASE = "omp-native-workspace-npm-run-all-scripts"
# The same install, launched with the switch that stops a browser dependency
# fetching its own copy of Chrome. The setting carries one of two words and
# names nothing to run, so the launch has to reach the runner the unprefixed
# spelling reaches.
WORKSPACE_SKIP_DOWNLOAD_PREFIX_CASE = "omp-native-workspace-puppeteer-skip-download-prefix"
WORKSPACE_RUNNER_CASES = frozenset(
    {
        WORKSPACE_JEST_CASE,
        WORKSPACE_NODE_ENTRY_CASE,
        WORKSPACE_NPM_EXEC_CASE,
        WORKSPACE_HEAP_PREFIX_CASE,
        WORKSPACE_VM_MODULES_PREFIX_CASE,
        WORKSPACE_NPM_CONFIG_PREFIX_CASE,
        WORKSPACE_MOCHA_CASE,
        WORKSPACE_AVA_CASE,
        WORKSPACE_JASMINE_CASE,
        WORKSPACE_QUNIT_CASE,
        WORKSPACE_UVU_CASE,
        WORKSPACE_TAPE_CASE,
        WORKSPACE_TSD_CASE,
        WORKSPACE_CUCUMBER_CASE,
        WORKSPACE_NAMED_TEST_SCRIPT_CASE,
        WORKSPACE_SCRIPT_PASSED_OPTION_CASE,
        WORKSPACE_QUIET_SCRIPT_RUN_CASE,
        WORKSPACE_SCRIPT_RUN_ALIAS_CASE,
        WORKSPACE_QUIET_PACKAGE_TEST_CASE,
        WORKSPACE_TSC_CASE,
        WORKSPACE_TSC_GENERATED_PROJECT_CASE,
        WORKSPACE_PNPM_TSC_CASE,
        WORKSPACE_LINT_STAGED_CASE,
        WORKSPACE_TSX_NODE_TEST_CASE,
        WORKSPACE_VITEST_FILTER_CASE,
        WORKSPACE_VITEST_BIN_LINK_CASE,
        WORKSPACE_VITEST_BUN_ENTRY_CASE,
        WORKSPACE_RUN_ALL_CASE,
        WORKSPACE_SKIP_DOWNLOAD_PREFIX_CASE,
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
# The one line the quiet package-test case's runner prints. Its manifest
# names the plain `test` entry the command asks for, which the default
# install deliberately does not declare, and its own line keeps the case
# from passing for the plain jest case's reason.
QUIET_PACKAGE_TEST_MARKER = f"jest-cli {_VERSION} ran quietly"
_QUIET_PACKAGE_TEST_FILES = {
    **_FILES,
    "package.json": (
        '{\n  "name": "synthetic-app",\n  "private": true,\n  "version": "0.0.0",\n'
        '  "scripts": {\n    "test": "jest --ci"\n  },\n'
        f'  "devDependencies": {{\n    "jest": "{_VERSION}"\n  }}\n}}\n'
    ),
    "node_modules/jest-cli/bin/jest.js": f"console.log('{QUIET_PACKAGE_TEST_MARKER}');\n",
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


_AVA_VERSION = "6.4.1"
# The one line the workspace's own AVA prints, which only a real launch produces.
AVA_MARKER = f"ava {_AVA_VERSION}"
_AVA_FILES = {
    "package.json": (
        '{\n  "name": "synthetic-app",\n  "private": true,\n  "version": "0.0.0",\n'
        f'  "devDependencies": {{\n    "ava": "{_AVA_VERSION}"\n  }}\n}}\n'
    ),
    "package-lock.json": (
        '{\n  "name": "synthetic-app",\n  "version": "0.0.0",\n  "lockfileVersion": 3,\n'
        '  "requires": true,\n  "packages": {\n    "": {\n      "name": "synthetic-app",\n'
        '      "version": "0.0.0",\n      "devDependencies": {\n'
        f'        "ava": "{_AVA_VERSION}"\n      }}\n    }},\n'
        '    "node_modules/ava": {\n'
        f'      "version": "{_AVA_VERSION}",\n      "dev": true,\n'
        '      "bin": {\n        "ava": "entrypoints/cli.js"\n      }\n    }\n  }\n}\n'
    ),
    # AVA's own configuration file. It can name the files to run and how to
    # compile them; it has no setting that turns watch mode on.
    "ava.config.js": "export default {\n  files: ['test/**/*.js'],\n};\n",
    "test/sample.js": ("const test = require('ava');\n\ntest('reads its own defaults', (t) => {\n  t.pass();\n});\n"),
    "node_modules/ava/package.json": (
        f'{{"name": "ava", "version": "{_AVA_VERSION}", "bin": {{"ava": "entrypoints/cli.js"}}}}\n'
    ),
    # AVA's launcher hands the run to the module beside it, the way the real
    # package does once it has read the configuration the run needs.
    "node_modules/ava/entrypoints/cli.js": ("#!/usr/bin/env node\nrequire('./main.js');\n"),
    "node_modules/ava/entrypoints/main.js": (f"#!/usr/bin/env node\nconsole.log('{AVA_MARKER}');\n"),
}


def _single_pass_project(
    name: str,
    version: str,
    entry: str,
    spec: str,
    marker: str,
    passed: tuple[str, ...] = (),
    executable: str | None = None,
) -> dict[str, str]:
    """A workspace that installed one single-pass runner, and nothing else.

    Jasmine, QUnit, uvu, tape, tsd and cucumber-js install the same way: a dev
    dependency, a lockfile that records it, one spec file, and a package whose
    declared `bin` is the executable npm links into `node_modules/.bin`. Only
    the names and the entry path differ, so one builder plants them all and
    each case keeps its own line to print.

    `executable` names that link where it is not the dependency's own name.
    A scoped package cannot be linked under its scope, so `@cucumber/cucumber`
    installs under its scoped directory and links as `cucumber-js`.

    `passed` names the words the scenario's own command spells after the
    runner. A launch that lost them would still start this executable, so the
    marker is printed only when they all arrive; otherwise the line says which
    run actually happened, and the case fails on the effect rather than on a
    missing file.
    """
    binary = executable or name
    return {
        "package.json": (
            '{\n  "name": "synthetic-app",\n  "private": true,\n  "version": "0.0.0",\n'
            f'  "devDependencies": {{\n    "{name}": "{version}"\n  }}\n}}\n'
        ),
        "package-lock.json": (
            '{\n  "name": "synthetic-app",\n  "version": "0.0.0",\n  "lockfileVersion": 3,\n'
            '  "requires": true,\n  "packages": {\n    "": {\n      "name": "synthetic-app",\n'
            '      "version": "0.0.0",\n      "devDependencies": {\n'
            f'        "{name}": "{version}"\n      }}\n    }},\n'
            f'    "node_modules/{name}": {{\n'
            f'      "version": "{version}",\n      "dev": true,\n'
            f'      "bin": {{\n        "{binary}": "{entry}"\n      }}\n    }}\n  }}\n}}\n'
        ),
        spec: f"// One spec for the workspace's own {name} to find.\n",
        f"node_modules/{name}/package.json": (
            f'{{"name": "{name}", "version": "{version}", "bin": {{"{binary}": "{entry}"}}}}\n'
        ),
        f"node_modules/{name}/{entry}": (
            "#!/usr/bin/env node\n"
            f"const passed = {json.dumps(list(passed))};\n"
            "const seen = process.argv.slice(2);\n"
            "const whole = passed.every((word) => seen.includes(word));\n"
            f"console.log(whole ? '{marker}' : '{binary}: ' + JSON.stringify(seen));\n"
        ),
    }


_JASMINE_VERSION = "5.12.0"
# The one line the workspace's own Jasmine prints, which only a real launch produces.
JASMINE_MARKER = f"jasmine {_JASMINE_VERSION}"
# Jasmine reads this file for the specs to load; nothing in it can turn a watch on.
_JASMINE_FILES = {
    **_single_pass_project(
        "jasmine",
        _JASMINE_VERSION,
        "bin/jasmine.js",
        "spec/sample_spec.js",
        JASMINE_MARKER,
        passed=("--filter=auth",),
    ),
    "spec/support/jasmine.json": ('{\n  "spec_dir": "spec",\n  "spec_files": ["**/*[sS]pec.js"]\n}\n'),
}

_QUNIT_VERSION = "2.24.1"
# The one line the workspace's own QUnit prints, which only a real launch produces.
QUNIT_MARKER = f"qunit {_QUNIT_VERSION}"
_QUNIT_FILES = _single_pass_project(
    "qunit",
    _QUNIT_VERSION,
    "bin/qunit.js",
    "test/sample.js",
    QUNIT_MARKER,
    passed=("test/",),
)

_UVU_VERSION = "0.5.6"
# The one line the workspace's own uvu prints, which only a real launch produces.
UVU_MARKER = f"uvu {_UVU_VERSION}"
# uvu publishes its executable at the package root rather than under `bin`.
_UVU_FILES = _single_pass_project(
    "uvu",
    _UVU_VERSION,
    "bin.js",
    "test/sample.js",
    UVU_MARKER,
    passed=("test",),
)

_TAPE_VERSION = "5.10.3"
# The one line the workspace's own tape prints, which only a real launch produces.
TAPE_MARKER = f"tape {_TAPE_VERSION}"
# tape's declared `bin` is an extensionless file under `bin/`, so the install
# below names it the way npm links it.
_TAPE_FILES = _single_pass_project(
    "tape",
    _TAPE_VERSION,
    "bin/tape",
    "test/a.js",
    TAPE_MARKER,
    passed=("test/a.js",),
)

_TSD_VERSION = "0.33.0"
# The one line the workspace's own tsd prints, which only a real launch produces.
TSD_MARKER = f"tsd {_TSD_VERSION}"
# tsd compiles its own CLI, so the executable npm links is the built file.
_TSD_FILES = _single_pass_project(
    "tsd",
    _TSD_VERSION,
    "dist/cli.js",
    "test/types.test-d.ts",
    TSD_MARKER,
    passed=("--files", "test/types.test-d.ts", "--show-diff"),
)

_CUCUMBER_VERSION = "13.3.0"
# The one line the workspace's own cucumber-js prints, which only a real launch
# produces.
CUCUMBER_MARKER = f"cucumber-js {_CUCUMBER_VERSION}"
# cucumber-js is the one scoped package here: npm installs it under
# `@cucumber/cucumber` and links its executable as `cucumber-js`.
_CUCUMBER_FILES = _single_pass_project(
    "@cucumber/cucumber",
    _CUCUMBER_VERSION,
    "bin/cucumber.js",
    "features/login.feature",
    CUCUMBER_MARKER,
    passed=("features/login.feature",),
    executable="cucumber-js",
)


_ESLINT_VERSION = "9.33.0"
# The option the case's script forwards to the linter. The scenario spells it on
# the command line, and the installed executable below answers only to it.
ESLINT_PASSED_OPTION = "--max-warnings=0"
# The one line the workspace's own ESLint prints, which only a real launch
# carrying the forwarded option produces.
ESLINT_MARKER = f"eslint {_ESLINT_VERSION}"
_ESLINT_FILES = {
    "package.json": (
        '{\n  "name": "synthetic-app",\n  "private": true,\n  "version": "0.0.0",\n'
        '  "scripts": {\n    "lint": "eslint ."\n  },\n'
        f'  "devDependencies": {{\n    "eslint": "{_ESLINT_VERSION}"\n  }}\n}}\n'
    ),
    "package-lock.json": (
        '{\n  "name": "synthetic-app",\n  "version": "0.0.0",\n  "lockfileVersion": 3,\n'
        '  "requires": true,\n  "packages": {\n    "": {\n      "name": "synthetic-app",\n'
        '      "version": "0.0.0",\n      "devDependencies": {\n'
        f'        "eslint": "{_ESLINT_VERSION}"\n      }}\n    }},\n'
        '    "node_modules/eslint": {\n'
        f'      "version": "{_ESLINT_VERSION}",\n      "dev": true,\n'
        '      "bin": {\n        "eslint": "bin/eslint.js"\n      }\n    }\n  }\n}\n'
    ),
    "eslint.config.js": "export default [];\n",
    "src/settings.ts": "export const settings = { retries: 3 };\n",
    "node_modules/eslint/package.json": (
        f'{{"name": "eslint", "version": "{_ESLINT_VERSION}", "bin": {{"eslint": "bin/eslint.js"}}}}\n'
    ),
    # A launch that dropped the forwarded tail would still start this file, so
    # the version line is printed only when the option actually arrives. The
    # oracle reads that line, which makes the case fail when the tail is lost
    # instead of passing on the launch alone.
    "node_modules/eslint/bin/eslint.js": (
        "#!/usr/bin/env node\n"
        f"const strict = process.argv.slice(2).includes('{ESLINT_PASSED_OPTION}');\n"
        f"console.log(strict ? '{ESLINT_MARKER}' : 'eslint: {ESLINT_PASSED_OPTION} was not forwarded');\n"
    ),
}
# The one line the quiet case's ESLint prints. That case forwards no option, so
# its executable answers to the launch itself; a separate line keeps the two
# ESLint cases from passing for each other's reason.
QUIET_LINT_MARKER = f"eslint {_ESLINT_VERSION} ran quietly"
_QUIET_LINT_FILES = {
    **_ESLINT_FILES,
    "node_modules/eslint/bin/eslint.js": (f"#!/usr/bin/env node\nconsole.log('{QUIET_LINT_MARKER}');\n"),
}
# The one line the alias case's ESLint prints. The alias forwards no option
# either, so its executable answers to the launch itself; its own line keeps it
# from passing for the quiet case's reason.
ALIAS_LINT_MARKER = f"eslint {_ESLINT_VERSION} ran through the alias"
_ALIAS_LINT_FILES = {
    **_ESLINT_FILES,
    "node_modules/eslint/bin/eslint.js": (f"#!/usr/bin/env node\nconsole.log('{ALIAS_LINT_MARKER}');\n"),
}


_TYPESCRIPT_VERSION = "5.9.2"
# The option the scenario spells. The installed executable answers only to it,
# so a launch that lost the project tail prints a different line.
TSC_PROJECT_OPTION = "-p"
# The one line the workspace's own type checker prints.
TSC_MARKER = f"tsc {_TYPESCRIPT_VERSION} checked the project"
_TYPESCRIPT_FILES = {
    "package.json": (
        '{\n  "name": "synthetic-app",\n  "private": true,\n  "version": "0.0.0",\n'
        '  "scripts": {\n    "typecheck": "tsc -p tsconfig.json"\n  },\n'
        f'  "devDependencies": {{\n    "typescript": "{_TYPESCRIPT_VERSION}"\n  }}\n}}\n'
    ),
    "package-lock.json": (
        '{\n  "name": "synthetic-app",\n  "version": "0.0.0",\n  "lockfileVersion": 3,\n'
        '  "requires": true,\n  "packages": {\n    "": {\n      "name": "synthetic-app",\n'
        '      "version": "0.0.0",\n      "devDependencies": {\n'
        f'        "typescript": "{_TYPESCRIPT_VERSION}"\n      }}\n    }},\n'
        '    "node_modules/typescript": {\n'
        f'      "version": "{_TYPESCRIPT_VERSION}",\n      "dev": true,\n'
        '      "bin": {\n        "tsc": "bin/tsc",\n        "tsserver": "bin/tsserver"\n'
        '      }\n    }\n  }\n}\n'
    ),
    "tsconfig.json": (
        '{\n  "compilerOptions": {\n    "strict": true,\n    "noEmit": true\n  },\n'
        '  "include": ["src"]\n}\n'
    ),
    "src/settings.ts": "export const settings = { retries: 3 };\n",
    # npm writes the package's own name here, not the executable's, which is
    # the whole point of the case.
    "node_modules/typescript/package.json": (
        f'{{"name": "typescript", "version": "{_TYPESCRIPT_VERSION}", "bin": '
        '{"tsc": "bin/tsc", "tsserver": "bin/tsserver"}}\n'
    ),
    # A launch that dropped the project tail would still start this file, so the
    # line the oracle reads is printed only when the option actually arrives.
    "node_modules/typescript/bin/tsc": (
        "#!/usr/bin/env node\n"
        f"const project = process.argv.slice(2).includes('{TSC_PROJECT_OPTION}');\n"
        f"console.log(project ? '{TSC_MARKER}' : 'tsc: the project option was not forwarded');\n"
    ),
}


# The project a type-check script generates: it names the same sources and keeps
# the no-emit mode in the file, which is the whole reason the run carries no
# `--noEmit` of its own.
_GENERATED_PROJECT_FILES = {
    **_TYPESCRIPT_FILES,
    "tsconfig.check.json": (
        '{\n  "compilerOptions": {\n    "strict": true,\n    "noEmit": true\n  },\n'
        '  "include": ["src"]\n}\n'
    ),
}


# pnpm resolves the same dependency and writes the same pin as YAML: one key
# per release under a top-level `packages` mapping, repeated under `snapshots`.
_PNPM_LOCK = (
    "lockfileVersion: '9.0'\n\n"
    "settings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\n"
    "importers:\n\n  .:\n    devDependencies:\n      typescript:\n"
    f"        specifier: {_TYPESCRIPT_VERSION}\n        version: {_TYPESCRIPT_VERSION}\n\n"
    f"packages:\n\n  typescript@{_TYPESCRIPT_VERSION}:\n"
    "    resolution: {tarball: https://registry.npmjs.org/typescript/-/"
    f"typescript-{_TYPESCRIPT_VERSION}.tgz}}\n"
    "    engines: {node: '>=14.17'}\n    hasBin: true\n\n"
    f"snapshots:\n\n  typescript@{_TYPESCRIPT_VERSION}: {{}}\n"
)
_PNPM_TYPESCRIPT_FILES = {
    name: text for name, text in _TYPESCRIPT_FILES.items() if name != "package-lock.json"
}
_PNPM_TYPESCRIPT_FILES["pnpm-lock.yaml"] = _PNPM_LOCK


_VITEST_VERSION = "3.2.4"
# The test file the scenario names. Vitest resolves a plain operand as a filter
# over the files it has discovered, so the run only means anything when the
# workspace holds a file the filter selects.
VITEST_TEST_FILE = "src/a.test.ts"
# The one line the workspace's own Vitest prints.
VITEST_MARKER = f"vitest {_VITEST_VERSION} ran the named file once"
_VITEST_FILES = {
    "package.json": (
        '{\n  "name": "synthetic-app",\n  "private": true,\n  "version": "0.0.0",\n'
        '  "scripts": {\n    "test": "vitest run"\n  },\n'
        f'  "devDependencies": {{\n    "vitest": "{_VITEST_VERSION}"\n  }}\n}}\n'
    ),
    "package-lock.json": (
        '{\n  "name": "synthetic-app",\n  "version": "0.0.0",\n  "lockfileVersion": 3,\n'
        '  "requires": true,\n  "packages": {\n    "": {\n      "name": "synthetic-app",\n'
        '      "version": "0.0.0",\n      "devDependencies": {\n'
        f'        "vitest": "{_VITEST_VERSION}"\n      }}\n    }},\n'
        '    "node_modules/vitest": {\n'
        f'      "version": "{_VITEST_VERSION}",\n      "dev": true,\n'
        '      "bin": {\n        "vitest": "vitest.mjs"\n      }\n    }\n  }\n}\n'
    ),
    "vitest.config.ts": 'export default { test: { include: ["src/**/*.test.ts"] } };\n',
    VITEST_TEST_FILE: (
        "import { expect, test } from 'vitest';\n\n"
        "test('reads its own defaults', () => {\n  expect(3).toBe(3);\n});\n"
    ),
    # npm puts Vitest's launcher at the package root rather than under `bin`.
    "node_modules/vitest/package.json": (
        f'{{"name": "vitest", "version": "{_VITEST_VERSION}", "bin": {{"vitest": "vitest.mjs"}}}}\n'
    ),
    # A launch that lost the filter would still start this file, and one that
    # lost the watch-off flag would leave Vitest watching rather than finishing
    # a pass, so the line the oracle reads is printed only when both the named
    # file and `--run` arrive. That makes the case fail where either word is
    # dropped instead of passing on the launch alone.
    "node_modules/vitest/vitest.mjs": (
        "#!/usr/bin/env node\n"
        "const argv = process.argv.slice(2);\n"
        f"const once = argv.includes('{VITEST_TEST_FILE}') && argv.includes('--run');\n"
        f"console.log(once ? '{VITEST_MARKER}'"
        " : 'vitest: the named one-pass run was not forwarded');\n"
    ),
}

# The one line the workspace's own Vitest prints for a bare `run`.
VITEST_RUN_MARKER = f"vitest {_VITEST_VERSION} ran one pass"
_VITEST_RUN_FILES = {
    **_VITEST_FILES,
    "node_modules/vitest/vitest.mjs": (
        "#!/usr/bin/env node\n"
        "const argv = process.argv.slice(2);\n"
        f"console.log(argv[0] === 'run' ? '{VITEST_RUN_MARKER}'"
        " : 'vitest: the one-pass run was not forwarded');\n"
    ),
}


_LINT_STAGED_VERSION = "16.1.2"
# The one line the workspace's own commit hook prints.
LINT_STAGED_MARKER = f"lint-staged {_LINT_STAGED_VERSION} checked the staged files"
_LINT_STAGED_FILES = {
    "package.json": (
        '{\n  "name": "synthetic-app",\n  "private": true,\n  "version": "0.0.0",\n'
        '  "lint-staged": {\n    "*.ts": "eslint --fix"\n  },\n'
        f'  "devDependencies": {{\n    "lint-staged": "{_LINT_STAGED_VERSION}"\n  }}\n}}\n'
    ),
    "package-lock.json": (
        '{\n  "name": "synthetic-app",\n  "version": "0.0.0",\n  "lockfileVersion": 3,\n'
        '  "requires": true,\n  "packages": {\n    "": {\n      "name": "synthetic-app",\n'
        '      "version": "0.0.0",\n      "devDependencies": {\n'
        f'        "lint-staged": "{_LINT_STAGED_VERSION}"\n      }}\n    }},\n'
        '    "node_modules/lint-staged": {\n'
        f'      "version": "{_LINT_STAGED_VERSION}",\n      "dev": true,\n'
        '      "bin": {\n        "lint-staged": "bin/lint-staged.js"\n      }\n    }\n  }\n}\n'
    ),
    "src/settings.ts": "export const settings = { retries: 3 };\n",
    "node_modules/lint-staged/package.json": (
        f'{{"name": "lint-staged", "version": "{_LINT_STAGED_VERSION}", "bin": '
        '{"lint-staged": "bin/lint-staged.js"}}\n'
    ),
    "node_modules/lint-staged/bin/lint-staged.js": (
        f"#!/usr/bin/env node\nconsole.log('{LINT_STAGED_MARKER}');\n"
    ),
}


_TSX_VERSION = "4.20.6"
# The one line the workspace's own test prints. The contained run replaces the
# installed launcher with `node --import <loader> --test <file>`, so the line
# the oracle reads has to come from the test file Node loads rather than from
# the launcher, which that run never starts.
TSX_MARKER = f"tsx {_TSX_VERSION} ran the node test runner"
_TSX_FILES = {
    "package.json": (
        '{\n  "name": "synthetic-app",\n  "private": true,\n  "version": "0.0.0",\n'
        '  "type": "module",\n'
        '  "scripts": {\n    "test": "tsx --test __tests__/media.test.ts"\n  },\n'
        f'  "devDependencies": {{\n    "tsx": "{_TSX_VERSION}"\n  }}\n}}\n'
    ),
    "package-lock.json": (
        '{\n  "name": "synthetic-app",\n  "version": "0.0.0",\n  "lockfileVersion": 3,\n'
        '  "requires": true,\n  "packages": {\n    "": {\n      "name": "synthetic-app",\n'
        '      "version": "0.0.0",\n      "devDependencies": {\n'
        f'        "tsx": "{_TSX_VERSION}"\n      }}\n    }},\n'
        '    "node_modules/tsx": {\n'
        f'      "version": "{_TSX_VERSION}",\n      "dev": true,\n'
        '      "bin": {\n        "tsx": "dist/cli.mjs"\n      }\n    }\n  }\n}\n'
    ),
    "__tests__/media.test.ts": (
        'import { test } from "node:test";\n'
        'import assert from "node:assert/strict";\n\n'
        'test("media urls keep their path", () => {\n'
        '  assert.equal(new URL("https://cdn.example.test/a.png").pathname, "/a.png");\n'
        f"  console.log('{TSX_MARKER}');\n"
        "});\n"
    ),
    "node_modules/tsx/package.json": (
        f'{{"name": "tsx", "version": "{_TSX_VERSION}", "type": "module", "bin": '
        '{"tsx": "dist/cli.mjs"}}\n'
    ),
    # The launcher npm links into `node_modules/.bin`. A contained run never
    # starts it, so its line says so: reading it means the launch escaped the
    # rewritten command rather than that the run worked.
    "node_modules/tsx/dist/cli.mjs": (
        "#!/usr/bin/env node\nconsole.log('tsx: the run was not contained');\n"
    ),
    # What the rewritten command imports. The real loader registers tsx's
    # transform; the fixture's sources need none, so it only has to be a module
    # Node can import.
    "node_modules/tsx/dist/loader.mjs": "export {};\n",
}


_RUN_ALL_VERSION = "4.1.5"
# The one line the workspace's own script runner prints.
RUN_ALL_MARKER = f"npm-run-all {_RUN_ALL_VERSION} ran the named scripts"
_RUN_ALL_FILES = {
    "package.json": (
        '{\n  "name": "synthetic-app",\n  "private": true,\n  "version": "0.0.0",\n'
        '  "scripts": {\n    "test:unit": "node --test __tests__",\n'
        '    "test:types": "tsc --noEmit"\n  },\n'
        f'  "devDependencies": {{\n    "npm-run-all": "{_RUN_ALL_VERSION}"\n  }}\n}}\n'
    ),
    "package-lock.json": (
        '{\n  "name": "synthetic-app",\n  "version": "0.0.0",\n  "lockfileVersion": 3,\n'
        '  "requires": true,\n  "packages": {\n    "": {\n      "name": "synthetic-app",\n'
        '      "version": "0.0.0",\n      "devDependencies": {\n'
        f'        "npm-run-all": "{_RUN_ALL_VERSION}"\n      }}\n    }},\n'
        '    "node_modules/npm-run-all": {\n'
        f'      "version": "{_RUN_ALL_VERSION}",\n      "dev": true,\n'
        '      "bin": {\n        "npm-run-all": "bin/npm-run-all.js"\n      }\n    }\n  }\n}\n'
    ),
    "src/settings.ts": "export const settings = { retries: 3 };\n",
    "node_modules/npm-run-all/package.json": (
        f'{{"name": "npm-run-all", "version": "{_RUN_ALL_VERSION}", "bin": '
        '{"npm-run-all": "bin/npm-run-all.js"}}\n'
    ),
    "node_modules/npm-run-all/bin/npm-run-all.js": (
        f"#!/usr/bin/env node\nconsole.log('{RUN_ALL_MARKER}');\n"
    ),
}


class _Install(NamedTuple):
    """One runner's install: the package npm links, its files and its own line."""

    name: str
    files: dict[str, str]
    marker: str
    # The package the executable ships inside, when npm's name for it differs
    # from the name it links into `node_modules/.bin`.
    package: str | None = None
    # The executable's path inside that package, when it is not `bin/<name>.js`.
    entry: str | None = None

    @property
    def entry_path(self) -> Path:
        """The installed executable, relative to the workspace root."""
        package = self.package or self.name
        return Path("node_modules") / package / (self.entry or f"bin/{self.name}.js")


_JEST_INSTALL = _Install("jest", _FILES, RUNNER_MARKER)
_INSTALLS = {
    WORKSPACE_MOCHA_CASE: _Install("mocha", _MOCHA_FILES, MOCHA_MARKER),
    WORKSPACE_AVA_CASE: _Install("ava", _AVA_FILES, AVA_MARKER, entry="entrypoints/cli.js"),
    WORKSPACE_JASMINE_CASE: _Install("jasmine", _JASMINE_FILES, JASMINE_MARKER),
    WORKSPACE_QUNIT_CASE: _Install("qunit", _QUNIT_FILES, QUNIT_MARKER),
    WORKSPACE_UVU_CASE: _Install("uvu", _UVU_FILES, UVU_MARKER, entry="bin.js"),
    WORKSPACE_TAPE_CASE: _Install("tape", _TAPE_FILES, TAPE_MARKER, entry="bin/tape"),
    WORKSPACE_TSD_CASE: _Install("tsd", _TSD_FILES, TSD_MARKER, entry="dist/cli.js"),
    WORKSPACE_CUCUMBER_CASE: _Install(
        "cucumber-js",
        _CUCUMBER_FILES,
        CUCUMBER_MARKER,
        package="@cucumber/cucumber",
        entry="bin/cucumber.js",
    ),
    WORKSPACE_SCRIPT_PASSED_OPTION_CASE: _Install("eslint", _ESLINT_FILES, ESLINT_MARKER),
    WORKSPACE_QUIET_SCRIPT_RUN_CASE: _Install("eslint", _QUIET_LINT_FILES, QUIET_LINT_MARKER),
    WORKSPACE_SCRIPT_RUN_ALIAS_CASE: _Install("eslint", _ALIAS_LINT_FILES, ALIAS_LINT_MARKER),
    WORKSPACE_QUIET_PACKAGE_TEST_CASE: _Install("jest", _QUIET_PACKAGE_TEST_FILES, QUIET_PACKAGE_TEST_MARKER),
    WORKSPACE_TSC_CASE: _Install(
        "tsc",
        _TYPESCRIPT_FILES,
        TSC_MARKER,
        package="typescript",
        entry="bin/tsc",
    ),
    WORKSPACE_TSC_GENERATED_PROJECT_CASE: _Install(
        "tsc",
        _GENERATED_PROJECT_FILES,
        TSC_MARKER,
        package="typescript",
        entry="bin/tsc",
    ),
    WORKSPACE_LINT_STAGED_CASE: _Install("lint-staged", _LINT_STAGED_FILES, LINT_STAGED_MARKER),
    WORKSPACE_RUN_ALL_CASE: _Install("npm-run-all", _RUN_ALL_FILES, RUN_ALL_MARKER),
    WORKSPACE_PNPM_TSC_CASE: _Install(
        "tsc",
        _PNPM_TYPESCRIPT_FILES,
        TSC_MARKER,
        package="typescript",
        entry="bin/tsc",
    ),
    WORKSPACE_TSX_NODE_TEST_CASE: _Install(
        "tsx",
        _TSX_FILES,
        TSX_MARKER,
        entry="dist/cli.mjs",
    ),
    WORKSPACE_VITEST_FILTER_CASE: _Install(
        "vitest",
        _VITEST_FILES,
        VITEST_MARKER,
        entry="vitest.mjs",
    ),
    WORKSPACE_VITEST_BIN_LINK_CASE: _Install(
        "vitest",
        _VITEST_RUN_FILES,
        VITEST_RUN_MARKER,
        entry="vitest.mjs",
    ),
    WORKSPACE_VITEST_BUN_ENTRY_CASE: _Install(
        "vitest",
        _VITEST_RUN_FILES,
        VITEST_RUN_MARKER,
        entry="vitest.mjs",
    ),
}


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
    entry = installed.entry_path
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
    and it accepts only a Node a caller's home or a system prefix owns. The
    host's Node is copied, not linked, so nothing the fixture does can reach
    the file the host runs.

    The release's own ``npm`` prefix is copied beside it. A real install keeps
    ``lib/node_modules/npm`` next to ``bin/node``, and the wrappers an agent
    reaches ``npx`` through read ``npx-cli.js`` out of that prefix, relative
    to whichever Node they resolved. A fixture that plants the binary alone is
    not the layout it claims to be, and an ``npx`` run inside containment
    failed with "Unable to locate npx-cli.js" rather than running the
    workspace's tool.
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
    prefix = home / _NODE_VERSIONS / version
    target = prefix / "bin" / "node"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    _add_node_package_manager(source.parent.parent, prefix)


def _add_node_package_manager(source_prefix: Path, prefix: Path) -> None:
    """Copy the host release's own ``npm`` into the fixture's Node prefix.

    The ``bin`` entries npm installs are links to a CLI file under the same
    prefix. Both relative and absolute spellings are rewritten against the
    fixture's own prefix, so a case never reaches back into the host's npm
    tree. A host without a bundled npm leaves the prefix as it is: the cases
    that need one fail on their own evidence rather than on a fixture that
    quietly planted the host's.
    """
    package_manager = source_prefix / "lib/node_modules/npm"
    if not package_manager.is_dir():
        return
    installed = prefix / "lib/node_modules/npm"
    installed.parent.mkdir(parents=True, exist_ok=True)
    if not installed.exists():
        shutil.copytree(package_manager, installed, symlinks=True)
    for name in ("npm", "npx"):
        entry = source_prefix / "bin" / name
        target = prefix / "bin" / name
        if not entry.exists() or target.exists():
            continue
        if not entry.is_symlink():
            shutil.copy2(entry, target)
            continue
        resolved = Path(os.readlink(entry))
        if not resolved.is_absolute():
            resolved = (source_prefix / "bin" / resolved).resolve()
        try:
            inside = resolved.relative_to(source_prefix.resolve())
        except ValueError:
            continue
        target.symlink_to(os.path.relpath(prefix / inside, target.parent))


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
