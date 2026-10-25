"""Workspace assessment summary for the receipts sync context.

Guard Cloud gets one bounded summary per admitted worktree: its status, the
latest assessed run's coverage, and package-coordinate findings. Local keys are
plain digests of absolute paths, so every identifier that leaves the machine is
re-keyed with the per-install secret; roots, commits and file names never do.
The summary is sent again only when it changes or a day has passed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Final

from .fleet_posture_common import keyed_digest, load_hash_key

if TYPE_CHECKING:
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

SCHEMA_VERSION: Final = "guard.workspace-assessment-sync.v1"
DELIVERY_STATE_KEY: Final = "workspace_assessment_sync_delivery"
MAX_WORKTREES: Final = 50
MAX_FINDINGS_PER_WORKTREE: Final = 100
# Receipts share the request; the whole body must stay under 256 KiB.
MAX_SUMMARY_BYTES: Final = 128 * 1024
MAX_REQUEST_BYTES: Final = 256 * 1024
RESEND_AFTER: Final = timedelta(hours=24)

_FINDING_FIELDS: Final = (
    ("source_kind", "sourceKind"),
    ("detector", "detector"),
    ("severity", "severity"),
    ("decision", "decision"),
    ("ecosystem", "ecosystem"),
    ("package_name", "packageName"),
    ("package_version", "packageVersion"),
    ("fix_version", "fixVersion"),
    ("validation_state", "validationState"),
    ("lifecycle_state", "lifecycleState"),
)


@dataclass(frozen=True)
class WorkspaceAssessmentSyncBuild:
    payload: dict[str, object]
    digest: str


def build_workspace_assessment_sync(store: GuardStore, *, now: str) -> WorkspaceAssessmentSyncBuild | None:
    """The summary to send, or ``None`` when nothing changed or nothing is admitted."""

    from .. import workspace_assessment_reads as reads
    from ..workspace_assessment_store import WorktreeKeys

    worktrees = reads.list_worktrees(store)[:MAX_WORKTREES]
    if not worktrees:
        return None
    hash_key = load_hash_key(store, now)
    selected = [WorktreeKeys(str(item["codebase_key"]), str(item["worktree_key"])) for item in worktrees]
    # Only the worktrees in this summary have their findings read and decoded.
    assessed = {
        (str(run["codebase_key"]), str(run["worktree_key"])): run for run in reads.latest_assessed_runs(store, selected)
    }
    entries = []
    for worktree, keys in zip(worktrees, selected, strict=True):
        latest = reads.recent_runs(store, keys, limit=1)
        entries.append(
            _worktree_entry(
                worktree, latest[0] if latest else None, assessed.get((keys.codebase_key, keys.worktree_key)), hash_key
            )
        )
    payload: dict[str, object] = {"schemaVersion": SCHEMA_VERSION, "generatedAt": now, "worktrees": entries}
    _fit_budget(entries, lambda: len(json.dumps(payload).encode("utf-8")), MAX_SUMMARY_BYTES)
    if not entries:
        return None
    digest = _digest(entries)
    if not _due(store, digest, now):
        return None
    return WorkspaceAssessmentSyncBuild(payload=payload, digest=digest)


def fit_workspace_assessment_to_request(
    built: WorkspaceAssessmentSyncBuild, max_bytes: int
) -> WorkspaceAssessmentSyncBuild | None:
    """A copy whose serialized payload fits ``max_bytes``, or ``None`` if it cannot.

    The digest is that of what this request carries. When anything was trimmed it
    no longer matches the full summary, so the next sync sends the full summary
    again instead of treating the trimmed delivery as current for a day.
    """

    payload = copy.deepcopy(built.payload)
    worktrees = payload.get("worktrees")
    # Built payloads hold only dict entries; trimming must shrink the list the payload serializes.
    entries: list[dict[str, object]] = worktrees if isinstance(worktrees, list) else []

    def size() -> int:
        return len(json.dumps(payload).encode("utf-8"))

    _fit_budget(entries, size, max_bytes)
    if not entries or size() > max_bytes:
        return None
    return WorkspaceAssessmentSyncBuild(payload=payload, digest=_digest(entries))


def commit_workspace_assessment_sent(store: GuardStore, built: WorkspaceAssessmentSyncBuild, *, now: str) -> None:
    store.set_sync_payload(DELIVERY_STATE_KEY, {"digest": built.digest, "sent_at": now}, now)


def build_workspace_assessment_sync_safely(store: GuardStore) -> WorkspaceAssessmentSyncBuild | None:
    """Build for one sync request. Never raises: the summary is best-effort."""

    try:
        return build_workspace_assessment_sync(store, now=_utc_now())
    except Exception:
        _LOGGER.debug("Workspace assessment summary could not be built", exc_info=True)
        return None


def record_workspace_assessment_delivery(store: GuardStore, built: WorkspaceAssessmentSyncBuild | None) -> None:
    """Commit a delivered summary, stamped with the local clock that built it."""

    if built is None:
        return
    try:
        commit_workspace_assessment_sent(store, built, now=str(built.payload["generatedAt"]))
    except Exception:
        _LOGGER.debug("Workspace assessment delivery could not be recorded", exc_info=True)


def worktree_status(
    worktree: dict[str, object],
    latest_run: dict[str, object] | None,
    assessed_run: dict[str, object] | None,
) -> str:
    if worktree.get("paused"):
        return "paused"
    latest_state = latest_run.get("state") if latest_run else None
    if latest_state in {"running", "queued"}:
        return str(latest_state)
    if latest_state == "failed":
        return "failed"
    if assessed_run is None:
        return "pending"
    if worktree.get("stale"):
        return "stale"
    return "partial" if assessed_run.get("state") == "partial" else "fresh"


def _worktree_entry(
    worktree: dict[str, object],
    latest_run: dict[str, object] | None,
    assessed_run: dict[str, object] | None,
    hash_key: bytes,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "codebaseKey": keyed_digest(hash_key, "guard.workspace.codebase\0" + str(worktree["codebase_key"])),
        "worktreeKey": keyed_digest(hash_key, "guard.workspace.worktree\0" + str(worktree["worktree_key"])),
        "status": worktree_status(worktree, latest_run, assessed_run),
        "dirtyGeneration": _generation(worktree.get("dirty_generation")),
        "lastCompletedGeneration": _generation(worktree.get("last_completed_generation")),
        "assessment": None,
        "findings": [],
        "findingsTruncated": False,
    }
    if assessed_run is None:
        return entry
    coverage = assessed_run.get("coverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    detectors = coverage.get("detectors")
    detector_items = detectors.items() if isinstance(detectors, dict) else ()
    entry["assessment"] = {
        "runKey": keyed_digest(hash_key, "guard.workspace.run\0" + str(assessed_run["run_id"])),
        "kind": assessed_run.get("kind"),
        "trigger": assessed_run.get("trigger_kind"),
        "state": assessed_run.get("state"),
        # The stored digest mixes in root-derived keys and Git identity; it is re-keyed like the rest.
        # The contract carries this one as bare hex, without the ``sha256:`` prefix.
        "snapshotDigest": keyed_digest(
            hash_key, "guard.workspace.snapshot\0" + str(assessed_run.get("snapshot_digest"))
        ).removeprefix("sha256:"),
        "coverage": {
            "status": "complete" if coverage.get("status") == "complete" else "partial",
            "reasons": [str(item)[:128] for item in _list(coverage.get("reasons"))][:32],
            "detectors": {str(name)[:64]: str(state)[:32] for name, state in detector_items},
        },
        "startedAt": _iso(assessed_run.get("started_at_ms")),
        "finishedAt": _iso(assessed_run.get("finished_at_ms")),
    }
    findings = [item for item in _list(assessed_run.get("findings")) if isinstance(item, dict)]
    entry["findings"] = [_finding(item, hash_key) for item in findings[:MAX_FINDINGS_PER_WORKTREE]]
    entry["findingsTruncated"] = len(findings) > MAX_FINDINGS_PER_WORKTREE or "finding_cap" in _list(
        coverage.get("reasons")
    )
    return entry


def _finding(item: dict[str, object], hash_key: bytes) -> dict[str, object]:
    finding: dict[str, object] = {
        "findingKey": keyed_digest(hash_key, "guard.workspace.finding\0" + str(item.get("finding_id"))),
    }
    for source, target in _FINDING_FIELDS:
        value = item.get(source)
        finding[target] = value[:256] if isinstance(value, str) else None
    finding["ruleIds"] = [str(value)[:128] for value in _list(item.get("rule_ids"))][:32]
    finding["advisoryIds"] = [str(value)[:256] for value in _list(item.get("advisory_ids"))][:32]
    return finding


def _fit_budget(entries: list[dict[str, object]], size: Callable[[], int], limit: int) -> None:
    """Shrink ``entries`` in place until ``size()`` fits the byte budget.

    Findings go first, lowest-ranked first. Coverage reasons and detector states
    follow, and trailing worktrees are dropped last. Any entry that loses findings
    or coverage detail is flagged ``findingsTruncated`` so the receiver never
    closes findings against it. The caller checks the final size: an empty list
    may still not fit.
    """

    while size() > limit:
        largest = max(entries, key=lambda entry: len(_findings(entry)), default=None)
        if largest is not None and (findings := _findings(largest)):
            drop = max(1, len(findings) // 4)
            del findings[-drop:]
            largest["findingsTruncated"] = True
            continue
        if _trim_coverage(entries):
            continue
        if not entries:
            return
        entries.pop()


def _trim_coverage(entries: list[dict[str, object]]) -> bool:
    """Halve the longest reasons list, then the largest detector map. False when both are empty."""

    covered = [(entry, coverage) for entry in entries if (coverage := _coverage(entry)) is not None]
    for field in ("reasons", "detectors"):
        largest = max(covered, key=lambda pair: _length(pair[1][field]), default=None)
        if largest is None:
            continue
        entry, coverage = largest
        values = coverage[field]
        if isinstance(values, list) and values:
            coverage[field] = values[: len(values) // 2]
        elif isinstance(values, dict) and values:
            coverage[field] = dict(list(values.items())[: len(values) // 2])
        else:
            continue
        entry["findingsTruncated"] = True
        return True
    return False


def _digest(entries: list[dict[str, object]]) -> str:
    return hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _length(value: object) -> int:
    return len(value) if isinstance(value, (list, dict)) else 0


def _coverage(entry: dict[str, object]) -> dict[str, object] | None:
    assessment = entry.get("assessment")
    coverage = assessment.get("coverage") if isinstance(assessment, dict) else None
    if not isinstance(coverage, dict):
        return None
    if not isinstance(coverage.get("reasons"), list) or not isinstance(coverage.get("detectors"), dict):
        return None
    return coverage


def _findings(entry: dict[str, object]) -> list[object]:
    findings = entry["findings"]
    return findings if isinstance(findings, list) else []


def _due(store: GuardStore, digest: str, now: str) -> bool:
    state = store.get_sync_payload(DELIVERY_STATE_KEY)
    if not isinstance(state, dict) or state.get("digest") != digest:
        return True
    sent_at = _parse(state.get("sent_at"))
    current = _parse(now)
    return sent_at is None or current is None or current - sent_at >= RESEND_AFTER


def _parse(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(value: object) -> str | None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _generation(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _list(value: object) -> list[object]:
    return list(value) if isinstance(value, (list, tuple)) else []


__all__ = [
    "DELIVERY_STATE_KEY",
    "MAX_REQUEST_BYTES",
    "SCHEMA_VERSION",
    "WorkspaceAssessmentSyncBuild",
    "build_workspace_assessment_sync",
    "build_workspace_assessment_sync_safely",
    "commit_workspace_assessment_sent",
    "fit_workspace_assessment_to_request",
    "record_workspace_assessment_delivery",
    "worktree_status",
]
