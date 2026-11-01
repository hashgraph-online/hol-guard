"""A test runner installed in the sibling project, launched by path.

Agents run a sibling checkout's own Jest by path, giving Node a larger heap
first (``node --max-old-space-size=4096 <sibling>/node_modules/jest/bin/jest.js``)
or handing the same entry to Bun. The launcher loads its CLI package the way the
real one does, so the run has to start from that checkout's root rather than as
a lone granted file.
"""

from __future__ import annotations

from pathlib import Path

SIBLING_HEAP_CASE = "omp-native-sibling-node-heap-jest"
# The same installed runner, launched by Bun rather than Node.
SIBLING_BUN_ENTRY_CASE = "omp-native-sibling-bun-jest-entry"
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


def add_sibling_test_runner(home: Path, scenario_id: str | None) -> None:
    """Install the runner, untracked as ``npm install`` leaves it, for its case only."""
    if (
        scenario_id not in (SIBLING_HEAP_CASE, SIBLING_BUN_ENTRY_CASE)
        and scenario_id not in SIBLING_LINK_CASES
    ):
        return
    for relative, text in _FILES.items():
        target = home / "other-project" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
