"""Detect canonical inputs awaiting maintainer-owned artifact regeneration.

Prints ``{"pending": ..., "pending_ids": [...]}`` (or a bare ``true``/``false``
with ``--flag``) when any canonical contribution under ``contributions/``
declares an extension id that the checked-in ``command-catalog.v1.json`` does
not contain.
That state means the source-only contribution is awaiting maintainer-owned
projection regeneration, so generated-artifact freshness gates should stand
down for that ref. Rust changes also require regeneration: the native compiler
binds its program identity to implementation sources, manifests and Cargo.lock.
Stdlib only; no repository imports.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "contracts/extensions/command-catalog.v1.json"


def contribution_ids() -> set[str]:
    ids = {str(json.loads(path.read_text())["id"]) for path in (ROOT / "contributions/extensions").glob("*.json")}
    ids.update(
        str(json.loads(path.read_text())["extension"]["extension_id"])
        for path in (ROOT / "contributions/command-sources").glob("command.*.json")
    )
    ids.update(
        "command.mcp-" + str(json.loads(path.read_text())["id"]).removeprefix("mcp.")
        for path in (ROOT / "contributions/mcp-servers").glob("*.json")
    )
    return ids


def catalog_ids() -> set[str]:
    catalog = json.loads(CATALOG.read_text())
    return {entry["extension_id"] for entry in catalog["catalog"]}


def _contributions_changed(base_sha: str) -> list[str]:
    import subprocess

    def _diff() -> subprocess.CompletedProcess[str]:
        # Ordinary PRs cannot commit regenerated projections, including Rust
        # identity updates; generated-artifacts-guard enforces that ownership.
        return subprocess.run(
            ["git", "diff", "--name-only", base_sha, "HEAD", "--", "contributions/", "rust/"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    completed = _diff()
    if completed.returncode:
        # Shallow checkouts lack the base commit; fetch it and retry once.
        _ = subprocess.run(
            ["git", "fetch", "--depth=1", "origin", base_sha],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        completed = _diff()
    if completed.returncode:
        return []
    return [line for line in completed.stdout.splitlines() if line.strip()]


def main() -> int:
    pending_ids = sorted(contribution_ids() - catalog_ids())
    changed: list[str] = []
    if "--changed-from" in sys.argv:
        base = sys.argv[sys.argv.index("--changed-from") + 1]
        changed = _contributions_changed(base)
    pending = bool(pending_ids) or bool(changed)
    if "--flag" in sys.argv:
        print("true" if pending else "false")
    else:
        print(
            json.dumps(
                {"pending": pending, "pending_ids": pending_ids, "changed_sources": changed},
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
