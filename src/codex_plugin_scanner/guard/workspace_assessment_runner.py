"""Run one claimed workspace assessment.

The run is bound to a content snapshot taken before the detectors start and
checked again after they finish. The content detectors read the very bytes
that snapshot hashed. If the two differ the worktree changed under the
detectors, so the run is superseded. The runtime detector reads the
executables the worktree's tools would launch, without running them.
Detectors run locally and the Cloud audit is never used from here. An automatic run is also offline: every network
exchange the local evaluation asks for is answered from cache or refused,
which leaves the run partial. A run the user asked for may look up package
coordinates the way an interactive audit does.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sqlite3
import time
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from . import workspace_assessment_store as assessments
from .native_package_audit_projection import (
    NativePackageAuditProjectionError,
    SupplyChainProjection,
    native_workspace_package_findings,
)
from .native_supply_chain_egress import offline_egress
from .native_workspace_inventory import AuditDeadlineError, audit_deadline
from .native_workspace_snapshot import WorkspaceSnapshot, WorkspaceSnapshotError, workspace_snapshot
from .store_workspace_assessment_schema import FINDINGS_BYTE_BUDGET, MAX_FINDINGS
from .workspace_ci_workflow_findings import (
    CI_WORKFLOW_DETECTOR,
    project_ci_workflow_findings,
    with_ci_workflow_coverage,
)
from .workspace_editor_task_findings import (
    EDITOR_TASK_DETECTOR,
    project_editor_task_findings,
    with_editor_task_coverage,
)
from .workspace_hook_config_findings import (
    HOOK_CONFIG_DETECTOR,
    project_hook_config_findings,
    with_hook_config_coverage,
)
from .workspace_instruction_findings import (
    INSTRUCTION_DETECTOR,
    project_instruction_findings,
    with_instruction_coverage,
)
from .workspace_mcp_config_findings import (
    MCP_CONFIG_DETECTOR,
    assess_workspace_mcp_configs,
    project_mcp_config_findings,
    with_mcp_config_coverage,
)
from .workspace_plugin_manifest_findings import (
    PLUGIN_MANIFEST_DETECTOR,
    project_plugin_manifest_findings,
    with_plugin_manifest_coverage,
)
from .workspace_runtime_findings import (
    RUNTIME_DETECTOR,
    assessment_context_digest,
    log_probe_failure,
    observe_workspace_runtimes,
    project_runtime_findings,
    remember_runtime_posture,
    with_runtime_coverage,
)
from .workspace_secret_findings import SECRET_DETECTOR, load_fingerprint_key, project_secret_findings, secret_coverage
from .workspace_skill_findings import SKILL_DETECTOR, project_skill_findings, with_skill_coverage
from .workspace_supply_chain_findings import SUPPLY_CHAIN_DETECTOR

DETECTOR_SET: Final = (
    SUPPLY_CHAIN_DETECTOR,
    SECRET_DETECTOR,
    RUNTIME_DETECTOR,
    SKILL_DETECTOR,
    MCP_CONFIG_DETECTOR,
    HOOK_CONFIG_DETECTOR,
    PLUGIN_MANIFEST_DETECTOR,
    CI_WORKFLOW_DETECTOR,
    EDITOR_TASK_DETECTOR,
    INSTRUCTION_DETECTOR,
)
# The content scans in the order they reached the native runtime.
_CONTENT_SCANS: Final = ("secrets", "skills", "hooks", "plugins", "workflows", "editor_tasks", "instructions")
DETECTOR_SET_DIGEST: Final = hashlib.sha256(
    ("guard.workspace-detectors.v1\0" + "\0".join(DETECTOR_SET)).encode("utf-8")
).hexdigest()
_SEVERITY_ORDER: Final = ("critical", "high", "medium", "low", "info", "unknown")


# The package audit stops starting resident requests after this long. The one
# already in flight is bounded on its own (about 25 seconds per evaluation), so
# the stage ends well inside the 5 minute lease instead of the lease expiring
# and the run being retried.
AUDIT_STAGE_SECONDS: Final = 3 * 60


# A run that lost its lease (canceled, expired or fenced) records nothing;
# finish refuses it.
_LEASE_LOST: Final = assessments.RunOutcome(state="failed", error_code="lease_lost")


def now_ms() -> int:
    return int(time.time() * 1000)


def run_next(
    store: Any, config: Any, *, owner: str, clock: Callable[[], int] = now_ms, user_only: bool = False
) -> bool:
    """Claim and run one due assessment; return whether one ran."""

    claimed = assessments.claim_next(
        store, owner=owner, now_ms=clock(), detector_set_digest=DETECTOR_SET_DIGEST, user_only=user_only
    )
    if claimed is None:
        return False
    outcome = execute(store, config, claimed, clock=clock)
    try:
        assessments.finish(store, claimed, outcome, now_ms=clock())
    except ValueError:
        # A result over its storage bound is recorded as a failure instead of
        # leaving the lease to expire and the same run to repeat.
        failed = assessments.RunOutcome(state="failed", error_code="assessment_result_too_large")
        assessments.finish(store, claimed, failed, now_ms=clock())
    except NativePackageAuditProjectionError:
        # Package ids could not be carried, so the run fails now instead of
        # holding its lease until it expires and the run repeats.
        failed = assessments.RunOutcome(state="failed", error_code="supply_chain_detector_failed")
        assessments.finish(store, claimed, failed, now_ms=clock())
    return True


def execute(
    store: Any, config: Any, run: assessments.ClaimedRun, *, clock: Callable[[], int] = now_ms
) -> assessments.RunOutcome:
    """Run each stage while ``run`` still holds its lease.

    The lease is renewed between stages, so a slow workspace keeps its run
    instead of being retried, and a canceled run stops before its next stage.
    """

    root = Path(run.private_root)
    try:
        feed_digest = feed_context_digest(store)
        secret_key = load_fingerprint_key(store, datetime.now(timezone.utc).isoformat())
    except sqlite3.Error:
        return assessments.RunOutcome(state="failed", error_code="feed_context_unavailable")
    try:
        before = _detector_snapshot(root, secret_key)
    except WorkspaceSnapshotError as error:
        return assessments.RunOutcome(state="failed", error_code=error.code)
    if before.worktree_key != run.keys.worktree_key or before.codebase_key != run.keys.codebase_key:
        # The path now names a different worktree (moved, re-cloned, replaced).
        return assessments.RunOutcome(state="failed", error_code="workspace_identity_changed")
    if not assessments.renew_lease(store, run, now_ms=clock()):
        return _LEASE_LOST
    automatic = run.trigger_kind not in assessments.USER_TRIGGERS
    try:
        with offline_egress() if automatic else nullcontext(None) as offline, audit_deadline(AUDIT_STAGE_SECONDS):
            payload = _local_audit(store, config, root)
        supply, supply_truncated = project_supply_chain_findings(run.keys.worktree_key, payload, store=store)
    except AuditDeadlineError:
        return assessments.RunOutcome(
            state="failed",
            snapshot_digest=before.snapshot_digest,
            input_manifest_digest=before.input_manifest_digest,
            error_code="supply_chain_audit_timed_out",
        )
    except Exception:
        return assessments.RunOutcome(
            state="failed",
            snapshot_digest=before.snapshot_digest,
            input_manifest_digest=before.input_manifest_digest,
            error_code="supply_chain_detector_failed",
        )
    if not assessments.renew_lease(store, run, now_ms=clock()):
        return _LEASE_LOST
    posture = _runtime_posture(store, root)
    mcp_configs = assess_workspace_mcp_configs(store, root)
    if not assessments.renew_lease(store, run, now_ms=clock()):
        return _LEASE_LOST
    context_digest = assessment_context_digest(
        feed_digest, remember_runtime_posture(store, run.keys.worktree_key, posture, now_ms=clock())
    )
    try:
        after = workspace_snapshot(root, mode="content")
    except WorkspaceSnapshotError as error:
        return assessments.RunOutcome(state="failed", snapshot_digest=before.snapshot_digest, error_code=error.code)
    if after.snapshot_digest != before.snapshot_digest:
        return assessments.RunOutcome(
            state="superseded",
            snapshot_digest=before.snapshot_digest,
            input_manifest_digest=before.input_manifest_digest,
            feed_context_digest=context_digest,
        )
    runtime_findings, runtime_truncated = (
        project_runtime_findings(run.keys.worktree_key, posture) if posture is not None else ([], False)
    )
    findings, merge_truncated = merge_findings(
        supply.findings,
        project_secret_findings(before.secrets),
        runtime_findings,
        project_skill_findings(before.skills),
        project_mcp_config_findings(mcp_configs),
        project_hook_config_findings(before.hooks),
        project_plugin_manifest_findings(before.plugins),
        project_ci_workflow_findings(before.workflows),
        project_editor_task_findings(before.editor_tasks),
        project_instruction_findings(before.instructions),
    )
    truncated = supply_truncated or runtime_truncated or merge_truncated
    refused = offline.refused if offline is not None else 0
    coverage = with_runtime_coverage(
        coverage_summary(before, payload, supply, findings_truncated=truncated, egress_refused=refused), posture
    )
    for add_coverage, result in (
        (with_skill_coverage, before.skills),
        (with_mcp_config_coverage, mcp_configs),
        (with_hook_config_coverage, before.hooks),
        (with_plugin_manifest_coverage, before.plugins),
        (with_ci_workflow_coverage, before.workflows),
        (with_editor_task_coverage, before.editor_tasks),
        (with_instruction_coverage, before.instructions),
    ):
        coverage = add_coverage(coverage, result)
    return assessments.RunOutcome(
        state="completed" if coverage["status"] == "complete" else "partial",
        snapshot_digest=before.snapshot_digest,
        input_manifest_digest=before.input_manifest_digest,
        feed_context_digest=context_digest,
        coverage=coverage,
        findings=findings,
        listed_packages=supply.listed,
    )


def _detector_snapshot(root: Path, secret_key: str) -> WorkspaceSnapshot:
    """Snapshot with every content detector, or fail the run.

    The runtime is the one shipped beside this package and is accepted only at
    the package's own version, so it carries every detector this release asks
    for. A runtime that is missing one is a runtime this release never agreed
    to use: the run fails with that detector's own reason instead of asking
    again without it, which would have reported the check as not run and the
    worktree as covered by the detectors that remained.
    """

    requested: dict[str, Any] = dict.fromkeys(_CONTENT_SCANS, True)
    requested["secret_key"] = secret_key
    return workspace_snapshot(root, mode="content", **requested)


def _runtime_posture(store: Any, root: Path) -> dict[str, object] | None:
    """The runtimes configured tools would launch, or ``None`` when they could not be read."""

    try:
        return observe_workspace_runtimes(store, root)
    except Exception as error:
        # The run keeps its other detectors; coverage reports this one as not run.
        log_probe_failure(error)
        return None


def _local_audit(store: Any, config: Any, root: Path) -> dict[str, object]:
    from .supply_chain_workspace_audit import build_workspace_audit_payload

    payload, _exit_code = build_workspace_audit_payload(
        store=store,
        config=config,
        workspace_dir=root,
        now=datetime.now(timezone.utc).isoformat(),
        command_name="workspace-assessment",
        sbom_paths=(),
        allow_cloud_audit=False,
        record_evidence=False,
    )
    return payload


def feed_context_digest(store: Any) -> str:
    """Digest the cached advisory bundles a local evaluation would read.

    A new bundle or policy changes this digest, which is what queues a
    ``feed_change`` assessment. It reads two hashes per cached bundle, so the
    daemon can afford it on every poll.
    """

    with store._connect() as connection:
        rows = connection.execute(
            "select workspace_id, payload_hash, policy_hash from guard_supply_chain_bundle_cache order by workspace_id"
        ).fetchall()
    encoded = json.dumps([[str(value) for value in row] for row in rows], separators=(",", ":"))
    return hashlib.sha256(("guard.workspace-feed.v1\0" + encoded).encode("utf-8")).hexdigest()


def coverage_summary(
    snapshot: WorkspaceSnapshot,
    payload: Mapping[str, object],
    supply: SupplyChainProjection,
    *,
    findings_truncated: bool,
    egress_refused: int = 0,
) -> dict[str, object]:
    reasons = [f"snapshot_{reason}" for reason in snapshot.partial_reasons]
    supply_chain = "complete"
    if payload.get("audit_status") == "incomplete":
        # A lockfile that yielded no packages is still a dependency file that
        # went unaudited; only a workspace with neither kind has no inputs.
        has_inputs = payload.get("manifest_paths") or payload.get("lockfile_paths")
        supply_chain = "incomplete" if has_inputs else "no_inputs"
    # The audit stopped, or a package needed registry or Cloud data the offline
    # run could not get.
    missing_lookup = supply_chain == "incomplete" or bool(egress_refused or supply.unresolved)
    unchecked = supply.unchecked > 0
    if supply_chain == "complete" and (missing_lookup or unchecked):
        supply_chain = "incomplete"
    if missing_lookup:
        reasons.append("supply_chain_incomplete")
    if unchecked:
        reasons.append("advisory_data_unavailable")
    if payload.get("lockfile_warnings"):
        reasons.append("lockfile_warnings")
    # A detector that did not run, or did not cover every file, leaves its
    # findings unknown, so the run is partial until every detector has covered
    # the whole snapshot.
    secrets: dict[str, object] = {}
    if snapshot.secrets is None:
        secrets_status = "not_run"
        reasons.append(f"detector_not_run:{SECRET_DETECTOR}")
    else:
        secrets_status, secrets, secret_reasons = secret_coverage(snapshot.secrets)
        if secrets_status != "complete":
            reasons.append("secrets_incomplete")
        # A scan that stopped at its own cap lists only some secrets, so the
        # findings list is as truncated as one cut by the merge bounds.
        findings_truncated = findings_truncated or "max_findings" in secret_reasons
    if findings_truncated:
        reasons.append("finding_cap")
    return {
        "status": "partial" if reasons else "complete",
        "reasons": reasons,
        "snapshot": {"coverage": snapshot.coverage, **snapshot.summary},
        "detectors": {"supply_chain": supply_chain, SECRET_DETECTOR: secrets_status},
        **({"secrets": secrets} if secrets else {}),
        "manifest_count": len(_strings(payload.get("manifest_paths"))),
        "lockfile_count": len(_strings(payload.get("lockfile_paths"))),
        "head_commit": snapshot.head_commit,
    }


def project_supply_chain_findings(
    worktree_key: str, payload: Mapping[str, object], *, store: Any | None = None
) -> tuple[SupplyChainProjection, bool]:
    """Project audit packages into workspace findings within the run's bounds."""

    supply = native_workspace_package_findings(worktree_key, payload, store=store)
    kept, truncated = _within_budget(supply.findings)
    return dataclasses.replace(supply, findings=kept), truncated


def merge_findings(*groups: list[dict[str, object]]) -> tuple[list[dict[str, object]], bool]:
    """Order findings from every detector and keep them within the bounds.

    Each group is already bounded on its own; the merge keeps the most severe
    findings first and reports whether any were dropped.
    """

    ordered = sorted(
        (item for group in groups for item in group),
        key=lambda item: (
            _SEVERITY_ORDER.index(str(item["severity"])),
            str(item.get("package_name") or item.get("path") or ""),
            _line(item),
            str(item["finding_id"]),
        ),
    )
    return _within_budget(ordered)


def _within_budget(ordered: list[dict[str, object]]) -> tuple[list[dict[str, object]], bool]:
    kept: list[dict[str, object]] = []
    used = 0
    for finding in ordered[:MAX_FINDINGS]:
        used += len(json.dumps(finding, sort_keys=True, separators=(",", ":")).encode("utf-8")) + 1
        if used > FINDINGS_BYTE_BUDGET:
            break
        kept.append(finding)
    return kept, len(kept) < len(ordered)


def _line(item: Mapping[str, object]) -> int:
    line = item.get("line")
    return line if isinstance(line, int) else 0


def _strings(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [item[:256] for item in value if isinstance(item, str) and item]


__all__ = [
    "DETECTOR_SET_DIGEST",
    "MAX_FINDINGS",
    "coverage_summary",
    "execute",
    "feed_context_digest",
    "merge_findings",
    "now_ms",
    "project_supply_chain_findings",
    "run_next",
]
