"""A test runner installed in the sibling project, launched with a heap size.

Agents run a sibling checkout's own Jest by path and give Node a larger heap
first: ``node --max-old-space-size=4096 <sibling>/node_modules/jest/bin/jest.js``.
The launcher loads its CLI package the way the real one does, so the run has to
start from that checkout's root rather than as a lone granted file.
"""

from __future__ import annotations

from pathlib import Path

SIBLING_HEAP_CASE = "omp-native-sibling-node-heap-jest"
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
    if scenario_id != SIBLING_HEAP_CASE:
        return
    for relative, text in _FILES.items():
        target = home / "other-project" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
