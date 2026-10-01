"""Detect contribution sources that are not yet covered by the generated catalog.

Prints ``{"pending": ..., "pending_ids": [...]}`` (or a bare ``true``/``false``
with ``--flag``) when any canonical contribution under ``contributions/``
declares an extension id that the checked-in ``command-catalog.v1.json`` does
not contain.
That state means the source-only contribution is awaiting maintainer-owned
projection regeneration, so generated-artifact freshness gates should stand
down for that ref. Stdlib only; no repository imports.
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


# Paths whose content feeds generated projections.  Contributions are the
# canonical extension sources; ``rust/`` feeds the compiler implementation
# digest (build.rs hashes every crate source, so any Rust change alters
# ``authoring_semantics_digest``); guard runtime/CLI sources, command corpus
# and decision-diff tests, and bound docs feed the decision-diff report's
# ``sources_sha256`` bindings; ``contracts/`` covers authored inputs such as
# the trust map.  A change under any of these legitimately leaves checked-in
# artifacts one maintainer regen behind.
_REGEN_INPUT_PREFIXES = (
    "contributions/",
    "rust/",
    "src/codex_plugin_scanner/guard/",
    "tests/",
    "docs/guard/",
    "contracts/",
)
_REGEN_INPUT_FILES = (
    "scripts/refresh_extension_artifacts.py",
    "scripts/build_native_command_program.py",
    "scripts/render_command_extension_directory.py",
)
_GENERATED_OUTPUTS = frozenset(
    {
        "contracts/extensions/native-command-program.v1.json",
        "tests/fixtures/guard-command-corpus/decision-diff-report.json",
        "tests/fixtures/guard-command-corpus/decision-diff-report.framed-sha256",
    }
)


def _regen_inputs_changed(base_sha: str) -> list[str]:
    import subprocess

    def _diff() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            # Two-dot diff is deliberate: shallow checkouts can fetch the base
            # commit itself but cannot compute a merge base, and over-flagging
            # (treating an input as changed) stands freshness gates down in the
            # safe direction rather than failing them.
            ["git", "diff", "--name-only", base_sha, "HEAD", "--", *_REGEN_INPUT_PREFIXES, *_REGEN_INPUT_FILES],
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
    names = [line for line in completed.stdout.splitlines() if line.strip()]
    return [path for path in names if path not in _GENERATED_OUTPUTS]


def main() -> int:
    pending_ids = sorted(contribution_ids() - catalog_ids())
    changed: list[str] = []
    if "--changed-from" in sys.argv:
        base = sys.argv[sys.argv.index("--changed-from") + 1]
        changed = _regen_inputs_changed(base)
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
