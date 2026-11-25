"""A test runner installed in the sibling project, launched by path.

Agents run a sibling checkout's own Jest by path, giving Node a larger heap
first (``node --max-old-space-size=4096 <sibling>/node_modules/jest/bin/jest.js``)
or handing the same entry to Bun. The launcher loads its CLI package the way the
real one does, so the run has to start from that checkout's root rather than as
a lone granted file.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

SIBLING_HEAP_CASE = "omp-native-sibling-node-heap-jest"
# The same installed runner, launched by Bun rather than Node.
SIBLING_BUN_ENTRY_CASE = "omp-native-sibling-bun-jest-entry"
# The runner launched from the sibling's own root, its output trimmed by a
# filter the sink has no peel grammar for.
SIBLING_CD_FILTER_CASE = "omp-native-sibling-cd-jest-cut"
# The same root-anchored run, its diagnostics dropped before a filter the sink
# does peel, which is why the rejoin rather than the peel has to carry it.
SIBLING_CD_QUIET_CASE = "omp-native-sibling-cd-jest-quiet"
# The same root-anchored run, its output respelled by a `cat` that reads
# standard input and opens nothing.
SIBLING_CD_CAT_CASE = "omp-native-sibling-cd-jest-cat-escapes"
# The same root-anchored run, its output trimmed to a line range by `sed`.
SIBLING_CD_SED_CASE = "omp-native-sibling-cd-jest-sed"
# A status read and the same root-anchored run, each ending in one stage of
# plain words, so the sink has to keep a list of two commands contained.
SIBLING_CD_LIST_GREP_CASE = "omp-native-sibling-cd-status-then-jest-grep"
# The same root-anchored run twice, joined by `;`, each bounded by its own
# `head` or `tail`.
SIBLING_CD_SEQUENCED_CASE = "omp-native-sibling-cd-jest-sequenced-runs"
# A search of a sibling checkout's tests that leaves out the folder holding a
# test TLS key, so the search is proven without reaching the key.
SIBLING_KEY_EXCLUSION_CASE = "omp-native-sibling-rg-tests-excluding-key-folder"
# Cases that link the installed tree into the sibling's linked worktree rather
# than install a second copy there.
SIBLING_LINK_CASES = (
    "omp-native-ln-sibling-modules-then-check",
    "omp-native-ln-sibling-modules-into-source-dir",
)
_FILES = {
    "node_modules/jest/package.json": '{"name": "jest", "version": "30.0.5"}\n',
    "node_modules/jest/bin/jest.js": (
        "#!/usr/bin/env node\nconst importLocal = require('import-local');\n"
        "if (!importLocal(__filename)) {\n  require('jest-cli/bin/jest');\n}\n"
    ),
    "node_modules/import-local/index.js": "module.exports = () => false;\n",
    "node_modules/jest-cli/bin/jest.js": "console.log('jest-cli 30.0.5');\n",
    "jest.config.js": "module.exports = {};\n",
}


def add_sibling_test_runner(home: Path, scenario_id: str | None, environment: dict[str, str]) -> None:
    """Install the runner, untracked as ``npm install`` leaves it, for its case only."""
    if scenario_id == SIBLING_KEY_EXCLUSION_CASE:
        _add_test_key_checkout(home, environment)
    if (
        scenario_id
        not in (
            SIBLING_HEAP_CASE,
            SIBLING_BUN_ENTRY_CASE,
            SIBLING_CD_FILTER_CASE,
            SIBLING_CD_QUIET_CASE,
            SIBLING_CD_CAT_CASE,
            SIBLING_CD_SED_CASE,
            SIBLING_CD_LIST_GREP_CASE,
            SIBLING_CD_SEQUENCED_CASE,
        )
        and scenario_id not in SIBLING_LINK_CASES
    ):
        return
    for relative, text in _FILES.items():
        target = home / "other-project" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")


def _add_test_key_checkout(home: Path, environment: dict[str, str]) -> None:
    """Commit a web client whose tests start a loopback TLS server from a key fixture."""
    checkout = home / "Code" / "ui-kit"
    for relative, text in (
        ("__tests__/scroll.test.ts", "test('scrollTo', () => {});\n"),
        ("app/page.tsx", "export const scrollTo = () => null;\n"),
        ("__tests__/fixtures/tls/loopback-server.key", "synthetic-test-key\n"),
    ):
        target = checkout / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
    for args in (
        ("init", "--quiet"),
        ("config", "user.name", "Gauntlet Fixture"),
        ("config", "user.email", "gauntlet@example.invalid"),
        ("config", "commit.gpgsign", "false"),
        ("add", "-A"),
        ("commit", "--quiet", "-m", "Synthetic ui-kit baseline"),
    ):
        subprocess.run(
            ["git", "-C", str(checkout), *args], env=environment, check=True, capture_output=True, timeout=15
        )
