#!/usr/bin/env python3
"""Print bounded public source locations without SARIF messages or source data."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

_RULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,127}\Z")
_MAX_LOCATIONS = 500
_MAX_SARIF_BYTES = 64 * 1024 * 1024


def public_locations(payload: object, tracked: set[str]) -> list[dict[str, str | int]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
        return []
    found: set[tuple[str, str, int]] = set()
    for run in payload["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("results"), list):
            continue
        for result in run["results"]:
            if not isinstance(result, dict):
                continue
            rule = result.get("ruleId")
            locations = result.get("locations")
            if not isinstance(rule, str) or not _RULE.fullmatch(rule) or not isinstance(locations, list):
                continue
            for location in locations:
                if not isinstance(location, dict):
                    continue
                physical = location.get("physicalLocation")
                if not isinstance(physical, dict):
                    continue
                artifact, region = physical.get("artifactLocation"), physical.get("region")
                if not isinstance(artifact, dict) or not isinstance(region, dict):
                    continue
                uri, line = artifact.get("uri"), region.get("startLine")
                if not isinstance(uri, str) or type(line) is not int or not 1 <= line <= 10_000_000:
                    continue
                if len(uri) > 512 or "%" in uri or "\\" in uri or any(ord(c) < 32 for c in uri):
                    continue
                try:
                    parsed = urlsplit(uri)
                except ValueError:
                    continue
                path = PurePosixPath(uri)
                if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or path.is_absolute():
                    continue
                if ".." in path.parts or str(path) != uri or uri not in tracked:
                    continue
                found.add((rule, uri, line))
                if len(found) >= _MAX_LOCATIONS:
                    break
            if len(found) >= _MAX_LOCATIONS:
                break
        if len(found) >= _MAX_LOCATIONS:
            break
    return [{"rule_id": rule, "path": path, "start_line": line} for rule, path, line in sorted(found)]


def main(directory: Path) -> None:
    tracked = set(subprocess.check_output(["git", "ls-files", "-z"], text=True).split("\0"))
    for path in sorted(directory.glob("*.sarif"))[:32]:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_SARIF_BYTES:
            raise SystemExit("CodeQL location report is unavailable.")
        try:
            payload = json.loads(path.read_bytes())
        except (OSError, ValueError):
            raise SystemExit("CodeQL location report is invalid.") from None
        print(json.dumps({"codeql_locations": public_locations(payload, tracked)}, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: codeql_result_locations.py <result-directory>")
    main(Path(sys.argv[1]))
