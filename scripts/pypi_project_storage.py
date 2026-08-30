#!/usr/bin/env python3
"""Report hol-guard PyPI project storage and files that can be reclaimed."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

PYPI_JSON_URL = "https://pypi.org/pypi/hol-guard/json"
PYPI_PROJECT_LIMIT_BYTES = 10_000_000_000


def release_size_bytes(files: object) -> int:
    if not isinstance(files, list):
        return 0
    total = 0
    for item in files:
        if not isinstance(item, dict):
            continue
        size = item.get("size")
        if isinstance(size, int) and size > 0:
            total += size
    return total


def project_size_bytes(payload: Mapping[str, Any]) -> int:
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        return 0
    return sum(release_size_bytes(files) for files in releases.values())


def reclaimable_extras(payload: Mapping[str, Any]) -> list[tuple[str, str, int]]:
    """Return non-pure files from 3.0.0a* releases, oldest first."""

    releases = payload.get("releases")
    if not isinstance(releases, dict):
        return []
    extras: list[tuple[Version, str, str, int]] = []
    for version_text, files in releases.items():
        if not isinstance(version_text, str) or not version_text.startswith("3.0.0a"):
            continue
        try:
            parsed = Version(version_text)
        except InvalidVersion:
            continue
        if not isinstance(files, list):
            continue
        for item in files:
            if not isinstance(item, dict):
                continue
            filename = item.get("filename")
            size = item.get("size")
            if not isinstance(filename, str) or not isinstance(size, int) or size <= 0:
                continue
            if filename.endswith("-py3-none-any.whl"):
                continue
            extras.append((parsed, version_text, filename, size))
    extras.sort(key=lambda item: (item[0], item[2]))
    return [(version, filename, size) for _parsed, version, filename, size in extras]


def pending_dir_size_bytes(path: Path) -> int:
    """Sum regular file sizes in a pending upload directory."""
    if not path.is_dir():
        raise FileNotFoundError(path)
    return sum(item.stat().st_size for item in path.iterdir() if item.is_file())


def over_project_limit(used_bytes: int, pending_bytes: int = 0) -> bool:
    return used_bytes + pending_bytes >= PYPI_PROJECT_LIMIT_BYTES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", help="Optional local PyPI JSON path for offline checks")
    parser.add_argument(
        "--fail-if-over-limit",
        action="store_true",
        help="Exit 1 when used_bytes plus pending-dir size is at or over the project limit",
    )
    parser.add_argument(
        "--pending-dir",
        type=Path,
        help="Local distribution directory whose bytes are counted toward the quota",
    )
    args = parser.parse_args(argv)
    if args.payload:
        payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))
    else:
        from urllib.request import Request, urlopen

        request = Request(PYPI_JSON_URL, headers={"Accept": "application/json"})
        with urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        print("PyPI payload is invalid", file=sys.stderr)
        return 1
    total = project_size_bytes(payload)
    extras = reclaimable_extras(payload)
    reclaimable = sum(size for _version, _filename, size in extras)
    pending_bytes = 0
    if args.pending_dir is not None:
        try:
            pending_bytes = pending_dir_size_bytes(args.pending_dir)
        except OSError:
            print("Pending distribution directory is missing or unreadable.", file=sys.stderr)
            return 1
    over_limit = over_project_limit(total, pending_bytes)
    print(
        json.dumps(
            {
                "project": "hol-guard",
                "limit_bytes": PYPI_PROJECT_LIMIT_BYTES,
                "used_bytes": total,
                "pending_bytes": pending_bytes,
                "over_limit": over_limit,
                "reclaimable_bytes": reclaimable,
                "reclaimable_files": len(extras),
                "reclaimable_sample": [filename for _version, filename, _size in extras[:5]],
            },
            indent=2,
            sort_keys=True,
        )
    )
    if args.fail_if_over_limit and over_limit:
        print("PyPI hol-guard is over the 10 GB project limit.", file=sys.stderr)
        print("Remove old 3.0.0a native wheels and sdists, then rerun publish.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
