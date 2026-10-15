"""Aggregate process-tree RSS sampling for the native SLO harness."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

# Sample with the operating system's own ``ps`` rather than a PATH lookup.
# Fixed root-owned locations cannot be shadowed by the caller's PATH, and they
# keep this measurement independent of Guard: the RSS sampler also runs after
# a benchmark session has closed its resident, when the resident-backed
# command-path trust helper has no runtime to answer.
_SYSTEM_PS_PATHS = (Path("/bin/ps"), Path("/usr/bin/ps"))


def _system_ps_path() -> Path | None:
    for candidate in _SYSTEM_PS_PATHS:
        try:
            status = candidate.stat()
        except OSError:
            continue
        if candidate.is_file() and status.st_uid == 0 and not status.st_mode & 0o022:
            return candidate
    return None


def process_tree_rss_bytes(process_ids: tuple[int, ...]) -> int | None:
    root_process_ids = {process_id for process_id in process_ids if process_id > 0}
    if not root_process_ids or os.name == "nt":
        return None
    ps_path = _system_ps_path()
    if ps_path is None:
        return None
    try:
        result = subprocess.run(
            [ps_path, "-axo", "pid=,ppid=,rss="],
            check=False,
            capture_output=True,
            text=True,
            timeout=0.2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    process_rows: list[tuple[int, int, int]] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3:
            continue
        try:
            process_rows.append((int(fields[0]), int(fields[1]), int(fields[2])))
        except ValueError:
            continue
    observed_process_ids = {process_id for process_id, _parent_process_id, _rss_kib in process_rows}
    if not root_process_ids.issubset(observed_process_ids):
        return None
    included_process_ids = set(root_process_ids)
    while True:
        descendants = {
            process_id
            for process_id, parent_process_id, _rss_kib in process_rows
            if parent_process_id in included_process_ids
        }
        expanded = included_process_ids | descendants
        if expanded == included_process_ids:
            break
        included_process_ids = expanded
    rss_kib = sum(
        rss_kib for process_id, _parent_process_id, rss_kib in process_rows if process_id in included_process_ids
    )
    return rss_kib * 1024


__all__ = ["process_tree_rss_bytes"]
