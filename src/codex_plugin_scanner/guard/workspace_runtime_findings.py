"""Runtimes a workspace's configured tools would launch, as workspace findings.

Reuses the runtime posture: the native probe describes each executable the
configured MCP servers would launch, without running it, and the native
assessment matches it against the runtime advisories carried in the cached
supply-chain bundle. The native ``workspace_runtime_findings`` kind turns the
posture into findings, coverage and the identity digest; this module probes
and keeps the per-worktree probe cache. Nothing here feeds hooks or approvals.
Cloud receives each finding's identifiers and a keyed digest of its path,
which matches the digest fleet posture reports for the same runtime; the path
itself stays local.
Where the native runtime enumerates running processes, a process that kept
running after its runtime was replaced on disk keeps its finding, as
``restart_required``, until it exits: a new build on disk alone is never the
fix. Only processes this user can see are enumerated, so a finding that goes
away never claims the runtime was verified fixed.

Runtime findings belong to the agent inventory domain, so they are recorded
with that source kind rather than dressed up as packages.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, cast

from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

RUNTIME_DETECTOR: Final = "runtime_identity_v1"
RUNTIME_SOURCE_KIND: Final = "agent_inventory"
# Probing hashes every launched executable, so the background worker looks
# for a changed runtime at most this often per worktree.
RUNTIME_OBSERVE_INTERVAL_MS: Final = 10 * 60 * 1000
# The native projection keeps at most this many findings per run.
MAX_RUNTIME_FINDINGS: Final = 50
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
        instance_home=Path(store.guard_home),
    )


def runtime_identity_digest(posture: Mapping[str, object]) -> str | None:
    """Digest which executables would launch and what they are, or ``None`` when unknown.

    The native runtime computes it. Advisories are left out: they arrive with
    the cached bundle, whose own digest already queues a reassessment when it
    changes. A digest the runtime could not answer is unknown, like a failed
    probe, so the last answer stands.
    """

    try:
        answer = _native("identity_digest", {"posture": dict(posture)})
    except RuntimeError:
        return None
    digest = answer.get("digest")
    return digest if isinstance(digest, str) else None


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
    v9: runs check GitHub Actions workflows.
    v10: runs check editor tasks and dev container commands.
    v11: runs report processes still running a replaced, affected runtime.
    v12: runs check agent instruction files.
    """

    encoded = f"guard.workspace-context.v12\0{feed_digest}\0{runtime_digest or 'unknown'}"
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class WorkspaceRuntimeFindingsError(RuntimeError):
    """The native runtime could not project the runtime findings or coverage."""


def project_runtime_findings(worktree_key: str, posture: Mapping[str, object]) -> tuple[list[dict[str, object]], bool]:
    """One finding per advisory and matched executable path, and whether any were dropped.

    The native runtime projects them; the cap keeps the known-exploited and
    most severe findings.
    """

    answer = _native("findings", {"worktree_key": worktree_key, "posture": dict(posture)})
    findings = answer.get("findings")
    if not isinstance(findings, list):
        raise WorkspaceRuntimeFindingsError("Guard could not project the workspace runtime findings.")
    return cast(list[dict[str, object]], findings), answer.get("truncated") is True


def with_runtime_coverage(coverage: dict[str, object], posture: Mapping[str, object] | None) -> dict[str, object]:
    """Add the runtime detector to a run's coverage, as the native runtime decides it."""

    answer = _native("coverage", {"coverage": coverage, "posture": dict(posture) if posture is not None else None})
    merged = answer.get("coverage")
    if not isinstance(merged, dict):
        raise WorkspaceRuntimeFindingsError("Guard could not summarize the workspace runtime coverage.")
    return cast(dict[str, object], merged)


def _native(op: str, args: Mapping[str, object]) -> dict[str, object]:
    try:
        return native_runner_authority("workspace_runtime_findings", {"op": op, **args})
    except NativeRunnerAuthorityError as error:
        raise WorkspaceRuntimeFindingsError("Guard could not assess the workspace runtimes.") from error


__all__ = [
    "MAX_RUNTIME_FINDINGS",
    "RUNTIME_DETECTOR",
    "RUNTIME_OBSERVE_INTERVAL_MS",
    "RUNTIME_SOURCE_KIND",
    "WorkspaceRuntimeFindingsError",
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
