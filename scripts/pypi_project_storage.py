#!/usr/bin/env python3
"""Report hol-guard PyPI project storage and files that can be reclaimed."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

PYPI_JSON_URL = "https://pypi.org/pypi/hol-guard/json"
PYPI_PROJECT_LIMIT_GIB = 10
PYPI_PROJECT_LIMIT_BYTES = PYPI_PROJECT_LIMIT_GIB * 1024**3
LIMIT_ENV = "HOL_GUARD_PYPI_PROJECT_LIMIT_BYTES"
GROWTH_WINDOW_DAYS = 14
WARN_USAGE_RATIO = 0.8
WARN_DAYS_UNTIL_FULL = 21


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


def over_project_limit(used_bytes: int, pending_bytes: int = 0, limit_bytes: int = PYPI_PROJECT_LIMIT_BYTES) -> bool:
    return used_bytes + pending_bytes >= limit_bytes


def project_limit_bytes(value: str | None) -> int:
    """Return the configured project limit; unset or empty means the PyPI default."""
    if value is None or not value.strip():
        return PYPI_PROJECT_LIMIT_BYTES
    limit = int(value.strip())
    if limit <= 0:
        raise ValueError("project limit must be positive")
    return limit


def _upload_time(item: Mapping[str, Any]) -> datetime | None:
    raw = item.get("upload_time_iso_8601") or item.get("upload_time")
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def recent_growth_bytes_per_day(
    payload: Mapping[str, Any], now: datetime, window_days: int = GROWTH_WINDOW_DAYS
) -> int:
    """Average bytes uploaded per day over the trailing window."""
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        return 0
    since = now - timedelta(days=window_days)
    total = 0
    for files in releases.values():
        if not isinstance(files, list):
            continue
        for item in files:
            if not isinstance(item, dict):
                continue
            size = item.get("size")
            uploaded = _upload_time(item)
            if isinstance(size, int) and size > 0 and uploaded is not None and uploaded >= since:
                total += size
    return total // window_days


def quota_outlook(used_bytes: int, limit_bytes: int, growth_bytes_per_day: int) -> dict[str, Any]:
    """Project when the quota runs out and whether maintainers should act now."""
    remaining = max(limit_bytes - used_bytes, 0)
    days_until_full = remaining / growth_bytes_per_day if growth_bytes_per_day > 0 else None
    usage_ratio = used_bytes / limit_bytes
    reasons = []
    if usage_ratio >= WARN_USAGE_RATIO:
        reasons.append(f"usage is {usage_ratio:.0%} of the project limit")
    if days_until_full is not None and days_until_full < WARN_DAYS_UNTIL_FULL:
        shown_days = round(days_until_full, 1)
        reasons.append(f"about {shown_days:g} days until full at the {GROWTH_WINDOW_DAYS}-day upload rate")
    return {
        "usage_ratio": round(usage_ratio, 4),
        "growth_window_days": GROWTH_WINDOW_DAYS,
        "growth_bytes_per_day": growth_bytes_per_day,
        "days_until_full": None if days_until_full is None else round(days_until_full, 1),
        "near_limit": bool(reasons),
        "near_limit_reasons": reasons,
    }


def report_near_limit(outlook: Mapping[str, Any]) -> None:
    """Surface an early quota warning in GitHub Actions without changing stdout JSON."""
    if not outlook["near_limit"]:
        return
    message = "PyPI hol-guard storage needs attention: " + "; ".join(outlook["near_limit_reasons"]) + "."
    print(message, file=sys.stderr)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::warning title=PyPI project quota::{message}", file=sys.stderr)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as summary:
                summary.write(f"### PyPI project quota\n{message}\n")
        except OSError:
            print("Could not write the PyPI quota warning to the step summary.", file=sys.stderr)


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
    parser.add_argument(
        "--limit-bytes",
        help=f"Project limit in bytes; defaults to ${LIMIT_ENV} or {PYPI_PROJECT_LIMIT_GIB} GiB",
    )
    args = parser.parse_args(argv)
    try:
        configured = args.limit_bytes if args.limit_bytes is not None else os.environ.get(LIMIT_ENV)
        limit_bytes = project_limit_bytes(configured)
    except ValueError:
        print("Project limit must be a positive integer byte count.", file=sys.stderr)
        return 1
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
    over_limit = over_project_limit(total, pending_bytes, limit_bytes)
    growth = recent_growth_bytes_per_day(payload, datetime.now(timezone.utc))
    # Assess the warning against post-upload usage so a pending upload that crosses a threshold warns now.
    outlook = quota_outlook(total + pending_bytes, limit_bytes, growth)
    print(
        json.dumps(
            {
                "project": "hol-guard",
                "limit_bytes": limit_bytes,
                "used_bytes": total,
                "pending_bytes": pending_bytes,
                "over_limit": over_limit,
                "reclaimable_bytes": reclaimable,
                "reclaimable_files": len(extras),
                "reclaimable_sample": [filename for _version, filename, _size in extras[:5]],
                **outlook,
            },
            indent=2,
            sort_keys=True,
        )
    )
    report_near_limit(outlook)
    if args.fail_if_over_limit and over_limit:
        print(
            f"PyPI hol-guard is at or over the {limit_bytes / 1024**3:g} GiB project limit.",
            file=sys.stderr,
        )
        if reclaimable:
            print("Remove old 3.0.0a native wheels and sdists, then rerun publish.", file=sys.stderr)
        else:
            print(
                "No reclaimable 3.0.0a native wheels or sdists were found; review PyPI storage before retrying.",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
