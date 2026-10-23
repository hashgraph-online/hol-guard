"""Select GitHub Actions cache entries on main that a newer entry has replaced.

The repository cache is capped at 10 GB and evicts least-recently-used entries.
Each main push saves a fresh CodeQL overlay database, and every lockfile change
saves a new Rust target cache while the previous one stays behind. Those stale
copies push out the caches the next run needs.

A cache family is the key without the suffix that changes between saves: the
commit, run id and attempt for CodeQL overlay databases, and the final lockfile
hash for Rust target caches and the source digest for runtime test archives.
Within a family on ``refs/heads/main`` only the newest entry is
kept. Any key outside the known families is never selected this way.

Rust and release-native keys also carry a compiler-environment hash ahead of
the content suffix. A newer environment replaces that job's older caches, but
those older keys are a different family under the suffix rule, so they stay
until they fill the 10 GB eviction cap and push out caches the next run
restores. The two compiler environments whose newest save is most recent are
kept. A job from an older commit can finish last, more than once, and those
saves must not be treated as the only current environment.

Content-addressed sccache entries have no family: each main push writes objects
for the workspace crates it changed, and the previous objects are never read
again. They are pruned by idleness instead. Each compiler-cache namespace and
target has its own Actions cache version, so entries are grouped by version and
an entry not read within ``IDLE_HOURS`` of the newest read in its group is
selected. Measuring from the newest read in the group rather than the wall clock
means a quiet period, or a namespace that only release builds read, keeps its
warm set until the next build reads it.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

MAIN_REF = "refs/heads/main"
CODEQL_KEY = re.compile(r"^(codeql-overlay-base-database-.+)-[0-9a-f]{40}-[0-9]+-[0-9]+$")
CODEQL_STATUS_PREFIX = "codeql-overlay-status-"
OFFLINE_PREVIOUS_KEY = re.compile(r"^(native-offline-previous-v1-.+)-[0-9a-f]{40}-[0-9a-f]{64}$")
RUNTIME_ARCHIVE_KEY = re.compile(
    r"^((?:runtime-test-archive-v[123]|linux-native-evaluators-v1|macos-hol-guard-runtime-v2|windows-hol-guard-runtime-v2|shipped-runtime-v[12])-.+)-[0-9a-f]{64}$"
)
RUST_PREFIXES = ("v0-rust-", "release-native-")
RUST_GENERATION = re.compile(r"^(?P<job>.+)-[0-9a-f]{8}-[0-9a-f]{8}$")
SCCACHE_PREFIX = "sccache/"
IDLE_HOURS = 2.0


def cache_family(key: str) -> str | None:
    """Return the family of a prunable key, or None when the key must be kept."""
    codeql = CODEQL_KEY.match(key)
    if codeql:
        return codeql.group(1)
    offline_previous = OFFLINE_PREVIOUS_KEY.fullmatch(key)
    if offline_previous:
        return offline_previous.group(1)
    runtime_archive = RUNTIME_ARCHIVE_KEY.fullmatch(key)
    if runtime_archive:
        return runtime_archive.group(1)
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


def rust_job_name(key: str) -> str | None:
    """Return the job identity of a Rust cache key, ignoring environment and content suffixes."""

    if not key.startswith(RUST_PREFIXES):
        return None
    match = RUST_GENERATION.fullmatch(key)
    if match is None:
        return None
    job = match.group("job")
    return job or None


def superseded_compiler_generations(entries: Iterable[Mapping[str, Any]]) -> list[int]:
    """Return ids of main-branch Rust caches outside the two newest environments of their job.

    Save order is not compiler-environment order. An older run can finish after
    a newer one and write its cache last, more than once when the content
    suffix differs, so the newest ``createdAt`` values can all belong to one
    old environment. Environments are ordered by their newest save. The two
    most recently saved environments stay; older environments are pruned.
    """

    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for entry in entries:
        key, ref, created, entry_id = entry.get("key"), entry.get("ref"), entry.get("createdAt"), entry.get("id")
        if ref != MAIN_REF or not isinstance(key, str) or not isinstance(created, str):
            continue
        if type(entry_id) is not int or entry_id <= 0:
            continue
        job = rust_job_name(key)
        if job is None:
            continue
        grouped.setdefault(job, []).append(entry)
    selected: list[int] = []
    for job_entries in grouped.values():
        by_environment: dict[str, list[Mapping[str, Any]]] = {}
        for item in job_entries:
            environment = str(item["key"]).rsplit("-", 2)[-2]
            by_environment.setdefault(environment, []).append(item)
        ranked = sorted(
            by_environment,
            key=lambda environment: max((item["createdAt"], item["id"]) for item in by_environment[environment]),
            reverse=True,
        )
        for environment in ranked[2:]:
            selected.extend(item["id"] for item in by_environment[environment])
    return sorted(selected)


def _accessed(entry: Mapping[str, Any]) -> datetime | None:
    value = entry.get("lastAccessedAt")
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def idle_compiler_entries(entries: Iterable[Mapping[str, Any]], idle_hours: float = IDLE_HOURS) -> list[int]:
    """Return ids of main-branch sccache entries unread for ``idle_hours`` before the newest read of their version."""
    groups: dict[str, list[tuple[int, datetime]]] = {}
    for entry in entries:
        key, ref, entry_id, version = entry.get("key"), entry.get("ref"), entry.get("id"), entry.get("version")
        if ref != MAIN_REF or not isinstance(key, str) or not key.startswith(SCCACHE_PREFIX):
            continue
        if type(entry_id) is not int or entry_id <= 0 or not isinstance(version, str) or not version:
            continue
        accessed = _accessed(entry)
        if accessed is None or accessed.tzinfo is None:
            continue
        groups.setdefault(version, []).append((entry_id, accessed))
    idle: list[int] = []
    window = timedelta(hours=idle_hours)
    for readable in groups.values():
        cutoff = max(accessed for _, accessed in readable) - window
        idle.extend(entry_id for entry_id, accessed in readable if accessed < cutoff)
    return sorted(idle)


def overlay_status_entries(entries: Iterable[Mapping[str, Any]]) -> list[int]:
    """Return ids of main-branch CodeQL overlay status entries that disable incremental analysis."""
    selected: list[int] = []
    for entry in entries:
        key, ref, entry_id = entry.get("key"), entry.get("ref"), entry.get("id")
        if ref != MAIN_REF or not isinstance(key, str) or not key.startswith(CODEQL_STATUS_PREFIX):
            continue
        if type(entry_id) is not int or entry_id <= 0:
            continue
        selected.append(entry_id)
    return sorted(selected)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("caches", type=Path, help="JSON from `gh cache list --json id,key,ref,createdAt`")
    _ = parser.add_argument(
        "--idle-hours",
        type=float,
        default=IDLE_HOURS,
        help="prune sccache entries unread this long before the newest sccache read",
    )
    args = parser.parse_args(argv)
    if not math.isfinite(args.idle_hours) or args.idle_hours <= 0:
        print("--idle-hours must be a positive number", file=sys.stderr)
        return 2
    entries = json.loads(args.caches.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        print("cache listing must be a JSON array", file=sys.stderr)
        return 2
    objects = [entry for entry in entries if isinstance(entry, dict)]
    for entry_id in sorted(
        {
            *superseded(objects),
            *superseded_compiler_generations(objects),
            *idle_compiler_entries(objects, args.idle_hours),
            *overlay_status_entries(objects),
        }
    ):
        print(entry_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
