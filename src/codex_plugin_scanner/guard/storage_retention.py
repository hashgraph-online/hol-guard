"""Guard home retention sweeps, run by the native runtime.

``storage-retention`` keeps quarantined store snapshots and updater staging
from accumulating for the life of an install; this module only builds the
requests and reads the answers. Without a compatible runtime nothing is
deleted and the summary reads as empty.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

_FEATURE = "native-storage-retention-v1"
_COMMAND = "storage-retention"
_SCHEMA = "storage-retention.v1"
_OUTPUT_LIMIT = 4096
_TIMEOUT_SECONDS = 30.0
_STAGING_PRUNE_AGE_SECONDS = 7 * 24 * 60 * 60


def _runtime_answer(guard_home: Path, op: str, **fields: object) -> dict[str, object] | None:
    from .mdm.runtime_request import runtime_answer

    request = {"schema": _SCHEMA, "op": op, "guard_home": str(Path(guard_home).absolute()), **fields}
    return runtime_answer(_FEATURE, _COMMAND, request, output_limit=_OUTPUT_LIMIT, timeout_seconds=_TIMEOUT_SECONDS)


def prune_quarantined_store_snapshots(
    guard_home: Path,
    *,
    now: float | None = None,
    min_keep: int = 2,
    max_age: timedelta = timedelta(days=7),
    max_total_bytes: int = 2 * 1024**3,
) -> int:
    """Delete quarantined store snapshots past the retention policy.

    The newest ``min_keep`` events always stay; older events stay only while
    within ``max_age`` and the running byte budget. Forensic records are never
    deleted. Answers how many files were removed.
    """

    fields: dict[str, object] = {
        "min_keep": max(0, int(min_keep)),
        "max_age_seconds": max_age.total_seconds(),
        "max_total_bytes": int(max_total_bytes),
    }
    if now is not None:
        fields["now"] = float(now)
    answer = _runtime_answer(guard_home, "quarantine-prune", **fields)
    removed = None if answer is None else answer.get("removed")
    return removed if type(removed) is int else 0


def quarantined_store_summary(guard_home: Path) -> dict[str, object]:
    """Compact summary of quarantined store snapshots for diagnostics."""

    answer = _runtime_answer(guard_home, "quarantine-summary")
    if answer is not None and set(answer) == {"count", "total_bytes", "newest_quarantined_at", "forensic_record_count"}:
        return answer
    return {"count": 0, "total_bytes": 0, "newest_quarantined_at": None, "forensic_record_count": 0}


def prune_stale_update_staging(guard_home: Path, *, age_seconds: int = _STAGING_PRUNE_AGE_SECONDS) -> None:
    """Delete update staging older than ``age_seconds``.

    The sweep is skipped while ``update-runtime/active.json`` is fresh and
    when any component of the staging path is a link.
    """

    _runtime_answer(guard_home, "staging-prune", age_seconds=float(age_seconds))
