"""Fail-closed package policy bridge to the running native authority."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .client import GuardSurfaceDaemonClient, load_running_guard_surface_daemon_client


@dataclass(frozen=True)
class DaemonPolicyResolution:
    decision: dict[str, object] | None
    authority: GuardSurfaceDaemonClient | None


def resolve_package_policy(
    *,
    guard_home: Path,
    harness: str,
    artifact_id: str | None,
    artifact_hash: str,
    workspaces: tuple[str, ...],
    publisher: str | None,
) -> DaemonPolicyResolution:
    """Resolve a saved package decision without starting or repairing a daemon."""

    try:
        authority = load_running_guard_surface_daemon_client(guard_home)
        for workspace in workspaces:
            lookup = authority.resolve_policy_decision(
                {
                    "harness": harness,
                    "artifact_id": artifact_id,
                    "artifact_hash": artifact_hash,
                    "workspace": workspace,
                    "publisher": publisher,
                }
            )
            decision = lookup.get("decision")
            if isinstance(decision, dict):
                return DaemonPolicyResolution(decision=dict(decision), authority=authority)
        return DaemonPolicyResolution(decision=None, authority=authority)
    except (OSError, RuntimeError, ValueError):
        return DaemonPolicyResolution(decision=None, authority=None)


def claim_package_policy(
    authority: GuardSurfaceDaemonClient,
    decision: dict[str, object],
) -> bool:
    """Claim reuse through the same native authority that resolved the decision."""

    try:
        return authority.claim_policy_decision({"decision": decision})
    except (OSError, RuntimeError, ValueError):
        return False
