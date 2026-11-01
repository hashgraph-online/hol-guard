"""PyInstaller onefile extraction-dir ownership markers and orphan reclamation.

Onefile launches extract to ``<tempdir>/_MEIxxxxxx``; the bootloader parent
removes that directory on normal exit, but a hard-killed launch leaks it. Each
launch stamps an owner marker recording its pid and bootloader parent pid so the
resident daemon can prove a leaked directory is dead before reclaiming it. The
native runtime's ``onefile-extraction-reclaim`` command runs the sweep: it
deletes marked dirs whose recorded pids are both dead and, when asked to scan
open files, unmarked dirs that are provably Guard extractions no live process
uses. Every other unmarked dir is only counted so operators can see the legacy
leak volume.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

OWNER_MARKER_NAME = ".hol-guard-extraction-owner.json"
_OWNER_MARKER_SCHEMA = "guard.onefile-extraction-owner.v1"

_FEATURE = "native-onefile-extraction-reclaim-v1"
_COMMAND = "onefile-extraction-reclaim"
_SCHEMA = "onefile-extraction-reclaim.v1"
_OUTPUT_LIMIT = 64 * 1024
# The open-files scan waits up to 90 seconds for lsof; marked deletes and the
# bytes walk get the rest.
_SCAN_SECONDS = 90.0
_SLACK_SECONDS = 120.0
_UNBOUNDED_SWEEP_SECONDS = 300.0

# Unmarked dirs have no pid to check, so keep a conservative floor well above a
# slow cold-start extraction.
UNMARKED_MIN_AGE = timedelta(hours=2)
DEFAULT_MIN_AGE = timedelta(minutes=10)
DEFAULT_MAX_UNMARKED_RECLAIMS = 250
DEFAULT_UNMARKED_TIME_BUDGET = timedelta(minutes=2)


class ExtractionReclaimUnavailableError(RuntimeError):
    """The native runtime could not run the sweep."""


@dataclass
class ExtractionReclaimResult:
    reclaimed_count: int = 0
    reclaimed_bytes: int = 0
    killed_launches: int = 0
    unmarked_count: int = 0
    unmarked_bytes_estimate: int = 0
    unmarked_reclaimed_count: int = 0
    unmarked_reclaimed_bytes: int = 0
    partial_reclaimed_count: int = 0
    # "disabled" (no open-files scan asked for), "not_needed", "ok", or
    # "unavailable" (scan failed, so every unmarked dir was skipped).
    unmarked_scan: str = "disabled"
    unmarked_budget_exhausted: bool = False
    errors: list[str] = field(default_factory=list)


_COUNTERS = (
    "reclaimed_count",
    "reclaimed_bytes",
    "killed_launches",
    "unmarked_count",
    "unmarked_bytes_estimate",
    "unmarked_reclaimed_count",
    "unmarked_reclaimed_bytes",
    "partial_reclaimed_count",
)
_SCAN_STATES = frozenset({"disabled", "not_needed", "ok", "unavailable"})


def reclaim_orphaned_extraction_dirs(
    *,
    temp_root: Path,
    current_meipass: str | None,
    now: datetime,
    min_age: timedelta = DEFAULT_MIN_AGE,
    scan_open_paths: bool = False,
    unmarked_min_age: timedelta = UNMARKED_MIN_AGE,
    max_unmarked_reclaims: int = DEFAULT_MAX_UNMARKED_RECLAIMS,
    unmarked_time_budget: timedelta | None = DEFAULT_UNMARKED_TIME_BUDGET,
    dry_run: bool = False,
    stop_event: threading.Event | None = None,
) -> ExtractionReclaimResult:
    """Reclaim ``_MEI*`` dirs under ``temp_root`` that are provably dead.

    Setting ``stop_event`` kills the sweep. A directory it was deleting is
    left partial, which the next sweep reclaims. Raises
    ``ExtractionReclaimUnavailableError`` when the runtime gives no answer.
    """

    from .mdm.runtime_request import runtime_answer

    budget = unmarked_time_budget.total_seconds() if unmarked_time_budget is not None else None
    sweep_seconds = budget if budget is not None else _UNBOUNDED_SWEEP_SECONDS
    answer = runtime_answer(
        _FEATURE,
        _COMMAND,
        {
            "schema": _SCHEMA,
            "temp_root": str(temp_root),
            "current_meipass": current_meipass if isinstance(current_meipass, str) else None,
            "now": now.timestamp(),
            "min_age_seconds": min_age.total_seconds(),
            "unmarked_min_age_seconds": unmarked_min_age.total_seconds(),
            "max_unmarked_reclaims": max(0, max_unmarked_reclaims),
            "unmarked_time_budget_seconds": budget,
            "scan_open_paths": scan_open_paths,
            "dry_run": dry_run,
        },
        output_limit=_OUTPUT_LIMIT,
        timeout_seconds=_SCAN_SECONDS + sweep_seconds + _SLACK_SECONDS,
        stop_event=stop_event,
    )
    result = _result(answer)
    if result is None:
        raise ExtractionReclaimUnavailableError("onefile_extraction_reclaim_unavailable")
    return result


def _result(answer: dict[str, object] | None) -> ExtractionReclaimResult | None:
    if answer is None:
        return None
    counters = {name: answer.get(name) for name in _COUNTERS}
    scan = answer.get("unmarked_scan")
    exhausted = answer.get("unmarked_budget_exhausted")
    errors = answer.get("errors")
    entries = cast("list[object]", errors) if isinstance(errors, list) else None
    texts = [entry for entry in entries if isinstance(entry, str)] if entries is not None else None
    if (
        not all(type(value) is int and value >= 0 for value in counters.values())
        or scan not in _SCAN_STATES
        or type(exhausted) is not bool
        or entries is None
        or texts is None
        or len(texts) != len(entries)
    ):
        return None
    result = ExtractionReclaimResult(
        unmarked_scan=str(scan),
        unmarked_budget_exhausted=exhausted,
        errors=texts,
    )
    for name, value in counters.items():
        setattr(result, name, value)
    return result
