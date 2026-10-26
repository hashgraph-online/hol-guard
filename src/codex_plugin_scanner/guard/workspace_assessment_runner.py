"""Run one claimed workspace assessment.

The run is bound to a content snapshot taken before the detectors start and
checked again after they finish. The secret, skill and hook detectors read the very bytes that
snapshot hashed, so their findings are bound to the same content. If the two differ the worktree changed under
the detectors, so the run is superseded rather than reporting findings for
content that no longer exists. The runtime detector reads the executables the
worktree's configured tools would launch, without running them. Detectors run locally and the Cloud audit is
never used from here. An automatic run is also offline: every network
exchange the local evaluation asks for is answered from cache or refused,
which leaves the run partial. A run the user asked for may look up package
coordinates the way an interactive audit does.
"""

from __future__ import annotations

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
from .native_supply_chain_egress import offline_egress
from .native_workspace_snapshot import WorkspaceSnapshot, WorkspaceSnapshotError, workspace_snapshot
from .store_workspace_assessment_schema import MAX_FINDINGS_JSON_BYTES
from .workspace_hook_config_findings import (
    HOOK_CONFIG_DETECTOR,
    project_hook_config_findings,
    with_hook_config_coverage,
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

DETECTOR_SET: Final = (
    "supply_chain_local_v1",
    SECRET_DETECTOR,
    RUNTIME_DETECTOR,
    SKILL_DETECTOR,
    MCP_CONFIG_DETECTOR,
    HOOK_CONFIG_DETECTOR,
    PLUGIN_MANIFEST_DETECTOR,
)
DETECTOR_SET_DIGEST: Final = hashlib.sha256(
    ("guard.workspace-detectors.v1\0" + "\0".join(DETECTOR_SET)).encode("utf-8")
).hexdigest()
MAX_FINDINGS: Final = 500
# Leave room under the column bound for the list brackets and separators.
_FINDINGS_BYTE_BUDGET: Final = MAX_FINDINGS_JSON_BYTES - 1024
_MAX_LIST_ITEMS: Final = 8
_SEVERITY_ORDER: Final = ("critical", "high", "medium", "low", "info", "unknown")
_FINDING_DECISIONS: Final = frozenset({"block", "ask", "warn"})
# An automatic run never asks Cloud, so a package the cached bundle does not
# cover comes back with one of these codes. They mean the answer is unknown,
# which is a coverage gap rather than evidence that the package is risky.
_LOOKUP_UNAVAILABLE: Final = frozenset(
    {"cloud_auth_error", "cloud_http_error", "cloud_timeout", "cloud_validation_error"}
)
# With no advisory bundle cached, a package Guard only recorded was never
# compared with any intelligence: it is unknown, not clean.
_NO_CACHED_MATCH: Final = "no_cached_match"


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
        with offline_egress() if automatic else nullcontext(None) as offline:
            payload = _local_audit(store, config, root)
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
    supply_findings, supply_truncated = project_supply_chain_findings(run.keys.worktree_key, payload)
    runtime_findings, runtime_truncated = (
        project_runtime_findings(run.keys.worktree_key, posture) if posture is not None else ([], False)
    )
    findings, merge_truncated = merge_findings(
        supply_findings,
        project_secret_findings(before.secrets),
        runtime_findings,
        project_skill_findings(before.skills),
        project_mcp_config_findings(mcp_configs),
        project_hook_config_findings(before.hooks),
        project_plugin_manifest_findings(before.plugins),
    )
    truncated = supply_truncated or runtime_truncated or merge_truncated
    refused = offline.refused if offline is not None else 0
    coverage = with_plugin_manifest_coverage(
        with_hook_config_coverage(
            with_mcp_config_coverage(
                with_skill_coverage(
                    with_runtime_coverage(
                        coverage_summary(before, payload, findings_truncated=truncated, egress_refused=refused),
                        posture,
                    ),
                    before.skills,
                ),
                mcp_configs,
            ),
            before.hooks,
        ),
        before.plugins,
    )
    return assessments.RunOutcome(
        state="completed" if coverage["status"] == "complete" else "partial",
        snapshot_digest=before.snapshot_digest,
        input_manifest_digest=before.input_manifest_digest,
        feed_context_digest=context_digest,
        coverage=coverage,
        findings=findings,
    )


def _detector_snapshot(root: Path, secret_key: str) -> WorkspaceSnapshot:
    """Snapshot with the content detectors, dropping each one the runtime lacks.

    The run is then partial: coverage reports a dropped detector as not run.
    """

    # Each scan is newer than the one before it, so a runtime that lacks one
    # lacks every later one too.
    try:
        return workspace_snapshot(
            root, mode="content", secrets=True, secret_key=secret_key, skills=True, hooks=True, plugins=True
        )
    except WorkspaceSnapshotError as error:
        if error.code == "workspace_snapshot_secrets_unavailable":
            return workspace_snapshot(root, mode="content")
        if error.code == "workspace_snapshot_skills_unavailable":
            return workspace_snapshot(root, mode="content", secrets=True, secret_key=secret_key)
        if error.code == "workspace_snapshot_hooks_unavailable":
            return workspace_snapshot(root, mode="content", secrets=True, secret_key=secret_key, skills=True)
        if error.code != "workspace_snapshot_plugins_unavailable":
            raise
    return workspace_snapshot(root, mode="content", secrets=True, secret_key=secret_key, skills=True, hooks=True)


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
    missing_lookup = supply_chain == "incomplete" or bool(egress_refused or _unresolved_packages(payload))
    unchecked = _unchecked_packages(payload) > 0
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
    worktree_key: str,
    payload: Mapping[str, object],
) -> tuple[list[dict[str, object]], bool]:
    """Project audit packages into bounded workspace findings.

    A finding carries package coordinates, reason codes and advisory
    identifiers. It never carries file content, commands or local paths.
    """

    findings: dict[str, dict[str, object]] = {}
    for package in _packages(payload):
        decision = str(package.get("decision") or "")
        if decision not in _FINDING_DECISIONS or _lookup_unavailable(package):
            continue
        ecosystem = _text(package.get("ecosystem")) or "unknown"
        name = _text(package.get("name"))
        if name is None:
            continue
        version = _text(package.get("resolvedVersion")) or _text(package.get("requestedVersion"))
        raw_reasons = package.get("reasons")
        reasons = [item for item in raw_reasons if isinstance(item, Mapping)] if isinstance(raw_reasons, list) else []
        rule_ids = {value[:128] for item in reasons if (value := _text(item.get("code")))}
        if (rule_id := _text(package.get("ruleId"))) is not None:
            rule_ids.add(rule_id[:128])
        advisories = {value for item in reasons if (value := _text(item.get("advisoryId")))}
        advisories.update(_strings(package.get("relatedAdvisoryIds")))
        advisories.update(_strings(package.get("advisoryAliases")))
        rule_list = sorted(rule_ids)[:_MAX_LIST_ITEMS]
        finding_id = hashlib.sha256(
            "\0".join(
                ("guard.workspace-finding.v1", worktree_key, "supply_chain", ecosystem, name, version or "", *rule_list)
            ).encode("utf-8")
        ).hexdigest()[:32]
        findings[finding_id] = {
            "finding_id": finding_id,
            "source_kind": "supply_chain",
            "detector": DETECTOR_SET[0],
            "severity": _max_severity(reasons),
            "decision": decision,
            "ecosystem": ecosystem,
            "package_name": name,
            "package_version": version,
            "fix_version": _text(package.get("recommendedFixVersion")),
            "rule_ids": rule_list,
            "advisory_ids": sorted(advisories)[:_MAX_LIST_ITEMS],
            "validation_state": "confirmed",
            "lifecycle_state": "open",
        }
    ordered = sorted(
        findings.values(),
        key=lambda item: (_SEVERITY_ORDER.index(str(item["severity"])), str(item["package_name"])),
    )
    kept: list[dict[str, object]] = []
    used = 0
    for finding in ordered[:MAX_FINDINGS]:
        size = len(json.dumps(finding, sort_keys=True, separators=(",", ":")).encode("utf-8")) + 1
        if used + size > _FINDINGS_BYTE_BUDGET:
            break
        kept.append(finding)
        used += size
    return kept, len(kept) < len(ordered)


def merge_findings(
    *groups: list[dict[str, object]],
) -> tuple[list[dict[str, object]], bool]:
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
    kept: list[dict[str, object]] = []
    used = 0
    for finding in ordered[:MAX_FINDINGS]:
        size = len(json.dumps(finding, sort_keys=True, separators=(",", ":")).encode("utf-8")) + 1
        if used + size > _FINDINGS_BYTE_BUDGET:
            break
        kept.append(finding)
        used += size
    return kept, len(kept) < len(ordered)


def _line(item: Mapping[str, object]) -> int:
    line = item.get("line")
    return line if isinstance(line, int) else 0


def _packages(payload: Mapping[str, object]) -> list[Mapping[str, object]]:
    evaluation = payload.get("evaluation")
    packages = evaluation.get("packages") if isinstance(evaluation, Mapping) else None
    return [item for item in packages if isinstance(item, Mapping)] if isinstance(packages, list) else []


def _lookup_unavailable(package: Mapping[str, object]) -> bool:
    if package.get("decision") == "block":
        return False
    codes = _reason_codes(package)
    return bool(codes) and codes <= _LOOKUP_UNAVAILABLE


def _reason_codes(package: Mapping[str, object]) -> set[object]:
    reasons = package.get("reasons")
    codes = {item.get("code") for item in reasons if isinstance(item, Mapping)} if isinstance(reasons, list) else set()
    codes.add(package.get("ruleId"))
    codes.discard(None)
    return codes


def _unresolved_packages(payload: Mapping[str, object]) -> int:
    return sum(1 for package in _packages(payload) if _lookup_unavailable(package))


def _unchecked_packages(payload: Mapping[str, object]) -> int:
    """Packages that went unchecked because no advisory bundle is cached."""

    evaluation = payload.get("evaluation")
    if not isinstance(evaluation, Mapping) or evaluation.get("bundle_version") is not None:
        return 0
    # The evaluator can add review reasons (an unidentified package, a lockfile
    # drift) beside the miss; none of them means advisories were consulted.
    return sum(1 for package in _packages(payload) if _NO_CACHED_MATCH in _reason_codes(package))


def _max_severity(reasons: list[Mapping[str, object]]) -> str:
    found = {str(item.get("severity") or "").lower() for item in reasons}
    return next((level for level in _SEVERITY_ORDER if level in found), "unknown")


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped[:256] if stripped else None


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
