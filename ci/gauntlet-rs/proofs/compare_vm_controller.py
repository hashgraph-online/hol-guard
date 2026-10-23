"""Read-only inventory of an installed VM controller against two reviewed source maps.

This diagnoses provenance gaps; matching a Git map alone is not execution
admission and does not authenticate the installed controller's origin.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def entries(rows: list[dict]) -> dict[str, str]:
    result = {}
    for row in rows:
        name, digest = row["path"], row["sha256"]
        if (
            not name.startswith("ci/gauntlet/")
            or ".." in Path(name).parts
            or Path(name).as_posix() != name
            or name in result
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("invalid source manifest entry")
        result[name] = digest
    return result


def compare(root: Path, expected: dict[str, str]) -> dict:
    absent, different, symlinks = [], [], []
    for name, digest in sorted(expected.items()):
        path = root / name
        if path.is_symlink():
            symlinks.append(name)
        elif not path.is_file():
            absent.append(name)
        elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            different.append(name)
    installed_py = {
        path.relative_to(root).as_posix()
        for path in (root / "ci/gauntlet").rglob("*.py")
        if "__pycache__" not in path.parts
    }
    unlisted_py = sorted(installed_py - expected.keys())
    return {
        "listed": len(expected),
        "matching": len(expected) - len(absent) - len(different) - len(symlinks),
        "absent": len(absent),
        "different": len(different),
        "symlinks": len(symlinks),
        "unlisted_python": len(unlisted_py),
        "absent_sample": absent[:12],
        "different_sample": different[:12],
        "symlink_sample": symlinks[:12],
        "unlisted_python_sample": unlisted_py[:12],
    }


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit("usage: compare_vm_controller.py BASE_MANIFEST DELTA INSTALLED_ROOT")
    baseline_path, delta_path, root_path = map(Path, sys.argv[1:])
    root = root_path.resolve(strict=True)
    if root != root_path or not root.is_dir():
        raise SystemExit("installed controller root must be canonical")
    baseline = json.loads(baseline_path.read_bytes())
    delta = json.loads(delta_path.read_bytes())
    original = entries(baseline["files"])
    if delta["base_source_commit"] != baseline["source_commit"]:
        raise SystemExit("delta does not name the baseline commit")
    integrated = original.copy()
    entries(delta["changed"])
    entries(delta["added"])
    for row in delta["changed"]:
        if original.get(row["path"]) != row["base_sha256"]:
            raise SystemExit("delta base hash mismatch")
        integrated[row["path"]] = row["sha256"]
    for row in delta["added"]:
        if row["path"] in integrated:
            raise SystemExit("added source already exists")
        integrated[row["path"]] = row["sha256"]
    if len(integrated) != delta["source_file_count"]:
        raise SystemExit("integrated source count mismatch")
    print(json.dumps({"baseline": compare(root, original), "integration": compare(root, integrated)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
