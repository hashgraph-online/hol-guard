"""Refresh the exact Gauntlet source delta after reviewing an upstream merge.

The pinned 420-file Python baseline never changes. New files need an explicit
owner disposition here before this generator admits them to the Rust source map.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[1]
REPOSITORY = WORKSPACE.parents[1]
BASELINE = WORKSPACE / "parity-manifest.v1.json"
DELTA = WORKSPACE / "integration-source-delta.v1.json"
NEW_FILES = {
    "ci/gauntlet/case_retry.py": ("port_to_rust", 5),
    "ci/gauntlet/benchmark/stage_control_adapter.py": ("port_to_rust", 2),
}


def main() -> None:
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    prior = json.loads(DELTA.read_text(encoding="utf-8"))
    if prior["schema"] != "gauntlet-rust-integration-source-delta.v1":
        raise ValueError("unexpected integration delta schema")
    if prior["base_source_commit"] != baseline["source_commit"]:
        raise ValueError("pinned Python baseline changed")
    base = {entry["path"]: entry for entry in baseline["files"]}
    old_added = {entry["path"]: entry for entry in prior["added"]}
    listed = subprocess.run(
        ["git", "ls-files", "--", "ci/gauntlet"],
        cwd=REPOSITORY,
        check=True,
        text=True,
        capture_output=True,
    ).stdout.splitlines()
    if len(listed) != len(set(listed)):
        raise ValueError("duplicate Git index path")
    if not set(base).issubset(listed) or not set(old_added).issubset(listed):
        raise ValueError("a pinned Gauntlet file disappeared")
    changed, added = [], []
    for path in listed:
        digest = hashlib.sha256((REPOSITORY / path).read_bytes()).hexdigest()
        if path in base:
            original = base[path]
            if digest != original["sha256"]:
                changed.append(
                    {
                        "path": path,
                        "base_sha256": original["sha256"],
                        "sha256": digest,
                        "disposition": original["disposition"],
                        "phase": original["phase"],
                    }
                )
            continue
        if path in old_added:
            disposition = old_added[path]["disposition"]
            phase = old_added[path]["phase"]
        elif path in NEW_FILES:
            disposition, phase = NEW_FILES[path]
        else:
            raise ValueError(f"new Gauntlet file needs an explicit disposition: {path}")
        added.append(
            {"path": path, "sha256": digest, "disposition": disposition, "phase": phase}
        )
    refreshed = {
        "schema": prior["schema"],
        "base_source_commit": prior["base_source_commit"],
        "integration_commit": prior["integration_commit"],
        "source_file_count": len(listed),
        "changed": changed,
        "added": added,
    }
    DELTA.write_text(json.dumps(refreshed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"pinned {len(listed)} Gauntlet files: {len(changed)} changed, {len(added)} added")


if __name__ == "__main__":
    main()
