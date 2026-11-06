#!/usr/bin/env python3
"""Generate a sanitized aggregate Gate 11 acceptance report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Final, cast

_ALLOWED_RESULT_FIELDS: Final = (
    "fixture_id",
    "requests",
    "routine_allowed",
    "secrets_denied",
    "capacity_denials",
    "generic_failures",
    "pid_stable",
    "workers_stable",
    "queue_bounded",
    "rss_growth_bytes",
    "p95_ms",
    "p99_ms",
    "browser_launches",
    "inbox_requests",
    "dispatch_counts",
)


def sanitize_report(payload: dict[str, object]) -> dict[str, object]:
    results = cast(list[object], payload.get("results", []))
    sanitized_results: list[dict[str, object]] = []
    for raw_item in results:
        if not isinstance(raw_item, dict):
            continue
        item = cast(dict[str, object], raw_item)
        sanitized = {field: item[field] for field in _ALLOWED_RESULT_FIELDS if field in item}
        dispatch_counts = sanitized.get("dispatch_counts")
        if isinstance(dispatch_counts, dict):
            typed_dispatch_counts = cast(dict[object, object], dispatch_counts)
            if not all(type(key) is str and type(value) is int for key, value in typed_dispatch_counts.items()):
                _ = sanitized.pop("dispatch_counts", None)
        else:
            _ = sanitized.pop("dispatch_counts", None)
        sanitized_results.append(sanitized)

    def string_field(name: str, default: str) -> str:
        value = payload.get(name)
        return value if isinstance(value, str) else default

    return {
        "schema_version": 1,
        "package_version": string_field("package_version", "unknown"),
        "git_sha": string_field("git_sha", "unknown"),
        "profile": string_field("profile", "correctness"),
        "passed": payload.get("passed") is True,
        "results": sanitized_results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("input", type=Path)
    _ = parser.add_argument("output", type=Path)
    args = parser.parse_args()
    loaded = cast(object, json.loads(cast(Path, args.input).read_text(encoding="utf-8")))
    if not isinstance(loaded, dict):
        raise ValueError("acceptance input must be a JSON object")
    report = sanitize_report(cast(dict[str, object], loaded))
    _ = cast(Path, args.output).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
