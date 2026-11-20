"""Workspace assessment summary for the receipts sync context.

Guard Cloud gets one bounded summary per admitted worktree: its status, the
latest assessed run's coverage, and the package-coordinate findings that run
observed. The native runtime re-keys every identifier, trims the summary to its
byte budget and decides whether it changed (``workspace_assessment_sync.rs``).
This module reads the store and records what was delivered.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Final

from ..native_runner_authority import native_runner_authority
from .fleet_posture_common import load_hash_key

if TYPE_CHECKING:
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

SCHEMA_VERSION: Final = "guard.workspace-assessment-sync.v1"
DELIVERY_STATE_KEY: Final = "workspace_assessment_sync_delivery"
MAX_WORKTREES: Final = 50
# The native runtime caps each worktree's findings at this many.
MAX_FINDINGS_PER_WORKTREE: Final = 100
# Receipts share the request; the whole body must stay under 256 KiB.
MAX_SUMMARY_BYTES: Final = 128 * 1024
MAX_REQUEST_BYTES: Final = 256 * 1024
# The native request parser refuses anything over 4 MiB. Each assessed run's
# findings get an equal share of that; a run cut to fit is flagged truncated,
# so Guard Cloud never closes a finding it was not sent.
_REQUEST_FINDINGS_SHARE: Final = 64 * 1024
_FINDING_TEXT_FIELDS: Final = (
    "source_kind",
    "detector",
    "severity",
    "decision",
    "ecosystem",
    "package_name",
    "package_version",
    "fix_version",
    "validation_state",
    "lifecycle_state",
)

_WORKTREE_FIELDS: Final = (
    "codebase_key",
    "worktree_key",
    "dirty_generation",
    "last_completed_generation",
    "stale",
    "paused",
)
_RUN_FIELDS: Final = (
    "run_id",
    "kind",
    "trigger_kind",
    "state",
    "snapshot_digest",
    "coverage",
    "started_at_ms",
    "finished_at_ms",
)


@dataclass(frozen=True)
class WorkspaceAssessmentSyncBuild:
    payload: dict[str, object]
    digest: str


def build_workspace_assessment_sync(store: GuardStore, *, now: str) -> WorkspaceAssessmentSyncBuild | None:
    """The summary to send, or ``None`` when nothing changed or nothing is admitted."""

    from .. import workspace_assessment_reads as reads
    from ..workspace_assessment_store import WorktreeKeys

    # Worktrees whose install admission ended keep their records, but they never
    # take a summary slot from one Guard still watches.
    worktrees = sorted(reads.list_worktrees(store), key=lambda item: bool(item["ended"]))[:MAX_WORKTREES]
    if not worktrees:
        return None
    hash_key = load_hash_key(store, now)
    selected = [WorktreeKeys(str(item["codebase_key"]), str(item["worktree_key"])) for item in worktrees]
    # Only the worktrees in this summary have their findings read and decoded.
    assessed = {
        (str(run["codebase_key"]), str(run["worktree_key"])): run for run in reads.latest_assessed_runs(store, selected)
    }
    latest_runs: list[object] = []
    assessed_runs: list[object] = []
    for keys in selected:
        latest = reads.recent_runs(store, keys, limit=1)
        latest_runs.append({"state": latest[0].get("state")} if latest else None)
        run = assessed.get((keys.codebase_key, keys.worktree_key))
        assessed_runs.append(None if run is None else _request_run(run))
    answer = native_runner_authority(
        "workspace_assessment_build",
        {
            "worktrees": [_fields(item, _WORKTREE_FIELDS) for item in worktrees],
            "latest_runs": latest_runs,
            "assessed_runs": assessed_runs,
            "hash_key": hash_key.decode("utf-8"),
            "now": now,
            "max_bytes": MAX_SUMMARY_BYTES,
            "delivery": store.get_sync_payload(DELIVERY_STATE_KEY),
        },
        getattr(store, "guard_home", None),
    )
    return _build(answer)


def fit_workspace_assessment_to_request(
    built: WorkspaceAssessmentSyncBuild, max_bytes: int
) -> WorkspaceAssessmentSyncBuild | None:
    """A copy whose serialized payload fits ``max_bytes``, or ``None`` if it cannot.

    The digest is that of what this request carries. When anything was trimmed it
    no longer matches the full summary, so the next sync sends the full summary
    again instead of treating the trimmed delivery as current for a day.
    """

    try:
        answer = native_runner_authority("workspace_assessment_fit", {"payload": built.payload, "max_bytes": max_bytes})
    except Exception:
        # The summary is best-effort: a native failure never blocks receipts.
        _LOGGER.debug("Workspace assessment summary could not be fitted", exc_info=True)
        return None
    return _build(answer)


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


def _fields(row: Mapping[str, object], fields: tuple[str, ...]) -> dict[str, object]:
    return {key: row[key] for key in fields if key in row}


def _request_run(run: Mapping[str, object]) -> dict[str, object]:
    """A run's fields with its findings bounded for the native request.

    Only what the summary reads crosses: findings this run observed, one past
    the per-worktree cap so the runtime still sees the cap was hit, with each
    label already clipped to what the summary keeps.
    """

    row = _fields(run, _RUN_FIELDS)
    stored = run.get("findings")
    findings: list[dict[str, object]] = []
    size = 0
    truncated = False
    for item in stored if isinstance(stored, list) else ():
        if len(findings) > MAX_FINDINGS_PER_WORKTREE:
            break
        if not isinstance(item, Mapping) or item.get("carried_from_run_id"):
            continue
        finding = _request_finding(item)
        size += len(json.dumps(finding))
        if size > _REQUEST_FINDINGS_SHARE:
            truncated = True
            break
        findings.append(finding)
    row["findings"] = findings
    row["findings_truncated"] = truncated
    return row


def _request_finding(item: Mapping[str, object]) -> dict[str, object]:
    finding: dict[str, object] = {"finding_id": item.get("finding_id")}
    for key in _FINDING_TEXT_FIELDS:
        value = item.get(key)
        finding[key] = value[:256] if isinstance(value, str) else None
    path = item.get("path")
    if item.get("source_kind") == "agent_inventory" and isinstance(path, str):
        finding["path"] = path
    finding["rule_ids"] = _request_labels(item.get("rule_ids"), 128)
    finding["advisory_ids"] = _request_labels(item.get("advisory_ids"), 256)
    return finding


def _request_labels(value: object, width: int) -> object:
    if not isinstance(value, list):
        return None
    return [label[:width] if isinstance(label, str) else label for label in value[:32]]


def _build(answer: Mapping[str, object]) -> WorkspaceAssessmentSyncBuild | None:
    payload = answer.get("payload")
    digest = answer.get("digest")
    if not isinstance(payload, dict) or not isinstance(digest, str):
        return None
    return WorkspaceAssessmentSyncBuild(payload=payload, digest=digest)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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
]
