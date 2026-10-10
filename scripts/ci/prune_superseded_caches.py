"""Select GitHub Actions cache entries on main that a newer entry has replaced.

The repository cache is capped at 10 GB and evicts least-recently-used entries.
Each main push saves a fresh CodeQL overlay database, and every lockfile change
saves a new Rust target cache while the previous one stays behind. Those stale
copies push out the caches the next run needs.

A cache family is the key without the suffix that changes between saves: the
commit, run id and attempt for CodeQL overlay databases, and the final lockfile
hash for Rust target caches. Within a family on ``refs/heads/main`` only the newest entry is
kept. Content-addressed compiler cache entries and any key outside the known
families are never selected.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

MAIN_REF = "refs/heads/main"
CODEQL_KEY = re.compile(r"^(codeql-overlay-base-database-.+)-[0-9a-f]{40}-[0-9]+-[0-9]+$")
RUST_PREFIXES = ("v0-rust-", "release-native-")


def cache_family(key: str) -> str | None:
    """Return the family of a prunable key, or None when the key must be kept."""
    codeql = CODEQL_KEY.match(key)
    if codeql:
        return codeql.group(1)
    if not key.startswith(RUST_PREFIXES):
        return None
    family, separator, suffix = key.rpartition("-")
    if not separator or not family or not suffix:
        return None
    return family


def superseded(entries: Iterable[Mapping[str, Any]]) -> list[int]:
    """Return ids of main-branch entries older than the newest of their family."""
    newest: dict[str, Mapping[str, Any]] = {}
    candidates: list[tuple[str, Mapping[str, Any]]] = []
    for entry in entries:
        key, ref, created, entry_id = entry.get("key"), entry.get("ref"), entry.get("createdAt"), entry.get("id")
        if ref != MAIN_REF or not isinstance(key, str) or not isinstance(created, str):
            continue
        if type(entry_id) is not int or entry_id <= 0:
            continue
        family = cache_family(key)
        if family is None:
            continue
        candidates.append((family, entry))
        current = newest.get(family)
        if current is None or (created, entry_id) > (current["createdAt"], current["id"]):
            newest[family] = entry
    return sorted(entry["id"] for family, entry in candidates if entry is not newest[family])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("caches", type=Path, help="JSON from `gh cache list --json id,key,ref,createdAt`")
    args = parser.parse_args(argv)
    entries = json.loads(args.caches.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        print("cache listing must be a JSON array", file=sys.stderr)
        return 2
    for entry_id in superseded(entry for entry in entries if isinstance(entry, dict)):
        print(entry_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
