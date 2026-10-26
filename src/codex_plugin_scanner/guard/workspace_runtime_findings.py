"""Runtimes a workspace's configured tools would launch, as workspace findings.

Reuses the runtime posture: the native probe describes each executable the
configured MCP servers would launch, without running it, and the native
assessment matches it against the runtime advisories carried in the cached
supply-chain bundle. Nothing here reaches Cloud or feeds hooks or approvals.
Running processes are not enumerated, so a finding says an executable on disk
matches an advisory; it never claims a live process is affected or fixed.

Runtime findings belong to the agent inventory domain, so they are recorded
with that source kind rather than dressed up as packages.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

RUNTIME_DETECTOR: Final = "runtime_identity_v1"
RUNTIME_SOURCE_KIND: Final = "agent_inventory"
# Probing hashes every launched executable, so the background worker looks
# for a changed runtime at most this often per worktree.
RUNTIME_OBSERVE_INTERVAL_MS: Final = 10 * 60 * 1000
MAX_RUNTIME_FINDINGS: Final = 50
_FINDING_VERDICTS: Final = frozenset({"affected", "restart_required", "fix_unverified"})
_SEVERITY_RANK: Final = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_LOGGER = logging.getLogger(__name__)

_lock = threading.Lock()
_observed: dict[tuple[str, str], tuple[int, str | None]] = {}


def observe_workspace_runtimes(store: Any, root: Path, *, home_dir: Path | None = None) -> dict[str, object]:
    """The runtime posture of the tools configured for ``root``, read locally."""

    from .adapters.harness_mcp_discovery import configured_harness_detections
    from .runtime_advisory_bundle import BUNDLE_UNREADABLE, cached_advisory_bundle
    from .runtime_posture import build_runtime_posture

    skipped: list[str] = []
    detections = configured_harness_detections(
        home_dir if home_dir is not None else Path.home(), Path(store.guard_home), root, skipped=skipped
    )
    try:
        bundle, reason = cached_advisory_bundle(store)
    except Exception:
        # A locked or damaged store costs the advisories, not the observation.
        bundle, reason = None, BUNDLE_UNREADABLE
    return build_runtime_posture(
        detections,
        generated_at=datetime.now(timezone.utc).isoformat(),
        workspace_dir=root,
        skipped_harnesses=skipped,
        advisory_bundle=bundle,
        advisory_bundle_reason=reason,
    )


def runtime_identity_digest(posture: Mapping[str, object]) -> str | None:
    """Digest which executables would launch and what they are, or ``None`` when unknown.

    Advisories are left out: they arrive with the cached bundle, whose own
    digest already queues a reassessment when it changes.
    """

    if posture.get("status") == "unavailable":
        return None
    identity = {
        # A launch past the probe's candidate limit, or a harness that became
        # unreadable, changes coverage without changing the retained rows.
        "status": str(posture.get("status")),
        "candidate_limit_reached": posture.get("candidate_limit_reached") is True,
        "runtimes": sorted(
            [
                str(row.get("path")),
                str(row.get("location_state")),
                str(row.get("family")),
                str(row.get("version")),
                str(row.get("executable_sha256")),
            ]
            for row in _rows(posture.get("runtimes"))
        ),
        "unresolved": sorted(
            [str(row.get("harness")), str(row.get("server")), str(row.get("command"))]
            for row in _rows(posture.get("unresolved_launches"))
        ),
        "skipped": sorted(str(item) for item in _list(posture.get("skipped_harnesses"))),
    }
    encoded = json.dumps(identity, separators=(",", ":"))
    return hashlib.sha256(("guard.workspace-runtimes.v1\0" + encoded).encode("utf-8")).hexdigest()


def cached_runtime_digest(store: Any, worktree_key: str, *, now_ms: int) -> tuple[str | None, bool] | None:
    """The last probed digest of one worktree and whether it is still fresh, or ``None`` before any probe."""

    with _lock:
        previous = _observed.get((str(store.guard_home), worktree_key))
    if previous is None:
        return None
    return previous[1], now_ms - previous[0] < RUNTIME_OBSERVE_INTERVAL_MS


def observed_runtime_digest(store: Any, worktree_key: str, root: Path, *, now_ms: int) -> str | None:
    """The runtime digest of one worktree, probed at most once per interval.

    Between probes the last digest is returned unchanged, so a runtime that
    changed is noticed within one interval and an unchanged one costs nothing.
    """

    with _lock:
        previous = _observed.get((str(store.guard_home), worktree_key))
    if previous is not None and now_ms - previous[0] < RUNTIME_OBSERVE_INTERVAL_MS:
        return previous[1]
    try:
        posture: Mapping[str, object] | None = observe_workspace_runtimes(store, root)
    except Exception as error:
        log_probe_failure(error)
        posture = None
    return remember_runtime_posture(store, worktree_key, posture, now_ms=now_ms)


def remember_runtime_posture(
    store: Any, worktree_key: str, posture: Mapping[str, object] | None, *, now_ms: int
) -> str | None:
    """Record a fresh probe of one worktree's runtimes and return its digest.

    A run probes too, and records what it saw here, so the context digest it
    stores matches what the next observation computes.
    """

    key = (str(store.guard_home), worktree_key)
    digest = runtime_identity_digest(posture) if posture is not None else None
    with _lock:
        previous = _observed.get(key)
        if digest is None and previous is not None:
            # A failed probe says nothing about the runtimes; keep the last answer.
            digest = previous[1]
        _observed[key] = (now_ms, digest)
    return digest


def log_probe_failure(error: BaseException) -> None:
    """Record why a runtime probe failed, without paths or configuration contents."""

    code = getattr(error, "code", None)
    _LOGGER.warning(
        "workspace runtime probe failed: %s", code if isinstance(code, str) and code else type(error).__name__
    )


def assessment_context_digest(feed_digest: str, runtime_digest: str | None) -> str:
    """Digest everything outside the files that an assessment's answer depends on.

    The advisory feed and the runtimes the worktree's tools launch both count,
    so a new bundle or a replaced runtime queues a ``feed_change`` run. The
    run trigger has no separate runtime kind, and adding one would rewrite a
    table an older Guard on the same home could no longer open.

    The version moves when a release changes what a run reports for unchanged
    files, so every worktree is reassessed once after the upgrade. v2: coverage
    names lockfiles Guard cannot check. v3: coverage names dependency files
    below audit discovery. v4: a lockfile without packages leaves the
    supply-chain detector incomplete rather than reporting no inputs. v5:
    runs check agent skill content. v6: runs check MCP server configuration.
    v7: runs check project hook commands.
    v8: runs check agent plugin hooks and MCP servers.
    """

    encoded = f"guard.workspace-context.v8\0{feed_digest}\0{runtime_digest or 'unknown'}"
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def project_runtime_findings(worktree_key: str, posture: Mapping[str, object]) -> tuple[list[dict[str, object]], bool]:
    """One finding per advisory and matched executable path, and whether any were dropped.

    Byte-identical runtimes at different paths share one artifact, so every
    path of a matched artifact gets its own finding. The cap keeps the
    known-exploited and most severe findings.
    """

    rows: dict[str, list[Mapping[str, object]]] = {}
    for row in _rows(posture.get("runtimes")):
        artifact_id = row.get("artifact_id")
        if isinstance(artifact_id, str):
            rows.setdefault(artifact_id, []).append(row)
    findings: dict[str, dict[str, object]] = {}
    for advisory in _rows(posture.get("advisories")):
        advisory_id, verdict = _text(advisory.get("advisory_id")), advisory.get("verdict")
        if advisory_id is None or verdict not in _FINDING_VERDICTS:
            continue
        severity = str(advisory.get("severity") or "").lower()
        for artifact_id in _list(advisory.get("affected_artifact_ids")):
            for row in rows.get(str(artifact_id), []):
                path = str(row.get("path"))
                finding_id = hashlib.sha256(
                    "\0".join(("guard.workspace-finding.v1", worktree_key, "runtime", advisory_id, path)).encode(
                        "utf-8"
                    )
                ).hexdigest()[:32]
                findings[finding_id] = {
                    "finding_id": finding_id,
                    "source_kind": RUNTIME_SOURCE_KIND,
                    "detector": RUNTIME_DETECTOR,
                    "severity": severity if severity in _SEVERITY_RANK else "unknown",
                    # Observation only: a runtime finding never blocks anything.
                    "decision": "warn",
                    "ecosystem": None,
                    "package_name": None,
                    "runtime_family": _text(row.get("family")),
                    "runtime_version": _text(row.get("version")),
                    "path": path,
                    "rule_ids": [str(verdict)],
                    "advisory_ids": [advisory_id],
                    "title": _text(advisory.get("title")),
                    "known_exploited": advisory.get("known_exploited") is True,
                    "validation_state": "confirmed",
                    "lifecycle_state": "open",
                }
    ordered = sorted(
        findings.values(),
        key=lambda item: (
            item["known_exploited"] is not True,
            _SEVERITY_RANK.get(str(item["severity"]), len(_SEVERITY_RANK)),
            str(item["advisory_ids"]),
            str(item["path"]),
        ),
    )
    return ordered[:MAX_RUNTIME_FINDINGS], len(ordered) > MAX_RUNTIME_FINDINGS


def with_runtime_coverage(coverage: dict[str, object], posture: Mapping[str, object] | None) -> dict[str, object]:
    """Add the runtime detector to a run's coverage.

    Runtimes the advisories could not be checked against, or a harness whose
    configuration could not be read, leave the detector incomplete and the run
    partial, as does a configured launch Guard could not resolve or identify.
    A workspace whose tools launch nothing has no runtime inputs.
    """

    reasons = list(_list(coverage.get("reasons")))
    if posture is None or posture.get("status") == "unavailable":
        status = "not_run"
        reasons.append(f"detector_not_run:{RUNTIME_DETECTOR}")
    else:
        runtimes = _rows(posture.get("runtimes"))
        unresolved = _rows(posture.get("unresolved_launches"))
        gaps: list[str] = []
        if (
            posture.get("status") != "ok"
            or unresolved
            or any(not isinstance(row.get("artifact_id"), str) or row.get("family") is None for row in runtimes)
            or any(row.get("verdict") == "unknown" for row in _rows(posture.get("advisories")))
        ):
            gaps.append("runtimes_incomplete")
        posture_coverage = posture.get("coverage")
        available = isinstance(posture_coverage, Mapping) and posture_coverage.get("advisories_available") is True
        if runtimes and not available:
            gaps.append("runtime_advisories_unavailable")
        status = "incomplete" if gaps else "complete" if runtimes or unresolved else "no_inputs"
        reasons.extend(gaps)
    detectors = coverage.get("detectors")
    summary = {
        "digest": runtime_identity_digest(posture) if posture is not None else None,
        "runtime_count": len(_rows(posture.get("runtimes"))) if posture is not None else 0,
    }
    return {
        **coverage,
        "status": "partial" if reasons else "complete",
        "reasons": reasons,
        "detectors": {**(detectors if isinstance(detectors, Mapping) else {}), RUNTIME_DETECTOR: status},
        "runtimes": summary,
    }


def _rows(value: object) -> list[Mapping[str, object]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _list(value: object) -> list[object]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped[:256] if stripped else None


__all__ = [
    "MAX_RUNTIME_FINDINGS",
    "RUNTIME_DETECTOR",
    "RUNTIME_OBSERVE_INTERVAL_MS",
    "RUNTIME_SOURCE_KIND",
    "assessment_context_digest",
    "cached_runtime_digest",
    "log_probe_failure",
    "observe_workspace_runtimes",
    "observed_runtime_digest",
    "project_runtime_findings",
    "remember_runtime_posture",
    "runtime_identity_digest",
    "with_runtime_coverage",
]
