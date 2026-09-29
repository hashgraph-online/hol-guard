#!/usr/bin/env python3
"""Fail unless every native platform ran its collected inventory exactly once."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import cast

PLATFORMS = frozenset(
    {
        "x86_64-unknown-linux-musl",
        "x86_64-pc-windows-msvc",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    }
)


def verify_reports(reports: list[dict[str, object]], shard_count: int) -> dict[str, int]:
    if shard_count < 1 or len(reports) != len(PLATFORMS) * shard_count:
        raise ValueError("missing or unexpected native regression reports")
    counts: dict[str, int] = {}
    for platform in sorted(PLATFORMS):
        group = [r for r in reports if r.get("platform") == platform]
        if len(group) != shard_count:
            raise ValueError(f"missing or duplicated platform reports: {platform}")
        indices: set[int] = set()
        selected: list[str] = []
        expected_count = group[0].get("collected_count")
        expected_digest = group[0].get("inventory_sha256")
        if type(expected_count) is not int or expected_count < shard_count:
            raise ValueError("invalid native inventory count")
        for report in group:
            index = report.get("shard_index")
            nodes = report.get("selected")
            if (
                report.get("schema") != "hol-guard.native-regression-shard.v1"
                or type(index) is not int
                or not 0 <= index < shard_count
                or index in indices
                or type(report.get("exit_code")) is not int
                or report.get("exit_code") != 0
                or report.get("shard_count") != shard_count
                or report.get("collected_count") != expected_count
                or report.get("inventory_sha256") != expected_digest
                or not isinstance(nodes, list)
                or not nodes
                or not all(isinstance(node, str) and node for node in nodes)
            ):
                raise ValueError(f"invalid or failed native shard: {platform}")
            indices.add(index)
            selected.extend(cast(list[str], nodes))
        if len(selected) != expected_count or len(set(selected)) != expected_count:
            raise ValueError(f"missing or duplicate native tests: {platform}")
        actual_digest = hashlib.sha256("\n".join(sorted(selected)).encode("utf-8")).hexdigest()
        if actual_digest != expected_digest:
            raise ValueError(f"native shard inventory drift: {platform}")
        counts[platform] = expected_count
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--shard-count", type=int, required=True)
    args = parser.parse_args()
    root = cast(Path, args.root)
    reports: list[dict[str, object]] = []
    for path in sorted(root.rglob("native-regression.json")):
        value: object = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"invalid report: {path}")
        reports.append(cast(dict[str, object], value))
    counts = verify_reports(reports, cast(int, args.shard_count))
    print(json.dumps({"status": "passed", "tests_by_platform": counts}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
