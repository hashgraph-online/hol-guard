"""Keep derived bookkeeping out of Git without requiring contributor regeneration.

Authored trust, behavioral fixtures and fixed crypto vectors remain reviewed
source. Generated package data and per-build reports are not source files.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_DERIVED = re.compile(
    r"^(?:contracts/extensions/(?:native-command-program|command-catalog)\.v1\.json"
    r"|contributions/extensions/command\.[^/]+\.json"
    r"|src/codex_plugin_scanner/guard/contracts/data/(?:extensions|mcp_servers)/.*\.json"
    r"|docs/guard/extensions/catalog\.v[12]\.json"
    r"|tests/fixtures/guard-command-corpus/decision-diff-report\.(?:json|framed-sha256)"
    r"|tests/fixtures/extension-controls/catalog-baseline\.v1\.json"
    r"|build/.*)$"
)


def tracked_derived_paths(paths: Iterable[str]) -> list[str]:
    """Inspect the resulting tree, so deleting old generated files is permitted."""
    return sorted(path for path in paths if _DERIVED.fullmatch(path))


def main() -> int:
    result = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True, timeout=30)
    paths = result.stdout.decode("utf-8").split("\0")
    derived = tracked_derived_paths(paths)
    if derived:
        print("Generated build outputs must not be committed:\n" + "\n".join(derived))
        return 1
    print("Canonical inputs are tracked; derived outputs are build-owned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
