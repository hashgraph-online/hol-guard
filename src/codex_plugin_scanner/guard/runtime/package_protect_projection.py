"""Shared identity and receipt surfaces for local package protect flows."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from ..models import GuardAction, GuardReceipt
from .harness_attribution import resolve_environment_harness
from .package_intent_common import PackageIntentTarget

LOCAL_SUPPLY_CHAIN_HARNESS = "guard-cli"


def _optional_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def resolve_local_supply_chain_harness() -> str:
    """Attribute intercepted package commands to the harness that invoked them.

    Package shims spawn ``hol-guard protect`` inside the environment of the
    shell that ran the command, so an AI harness that executed it leaves its
    runtime env markers there. The resolved slug feeds request identity,
    receipts, and user-facing attribution only; policy scoping stays keyed on
    the synthetic guard-cli artifact harness, which the invoking process
    cannot influence.
    """

    return resolve_environment_harness(os.environ) or LOCAL_SUPPLY_CHAIN_HARNESS


@dataclass(frozen=True, slots=True)
class PackageProtectProjection:
    receipt: GuardReceipt
    receipt_policy_metadata: dict[str, object]
    verdict_action: GuardAction
    risk_signals: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PackageProtectVerdictContext:
    """Verdict presentation plus the stored receipt for one protect projection."""

    matched_advisories: list[dict[str, object]]
    observe_projected: bool
    observed_policy_action: GuardAction
    public_targets: list[dict[str, object]]
    receipt: GuardReceipt
    receipt_policy_metadata: dict[str, object]
    risk_signals: tuple[str, ...]
    verdict_action: GuardAction
    verdict_reason: str


def build_package_guard_receipt(
    *,
    harness: str,
    artifact_id: str,
    artifact_hash: str,
    policy_decision: GuardAction,
    capabilities_summary: str,
    changed_capabilities: list[str],
    provenance_summary: str,
    artifact_name: str | None,
    source_scope: str | None,
    scanner_evidence: tuple[dict[str, object], ...] = (),
) -> GuardReceipt:
    sample = ", ".join(changed_capabilities[:3])
    suffix = " ..." if len(changed_capabilities) > 3 else ""
    diff_summary = f"{len(changed_capabilities)} change(s): {sample}{suffix}" if changed_capabilities else None
    return GuardReceipt(
        receipt_id=f"guard-receipt-{uuid4()}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=policy_decision,
        capabilities_summary=capabilities_summary,
        changed_capabilities=tuple(changed_capabilities),
        provenance_summary=provenance_summary,
        artifact_name=artifact_name,
        source_scope=source_scope,
        diff_summary=diff_summary,
        scanner_evidence=scanner_evidence,
    )


def protect_target_payload(target: PackageIntentTarget, *, harness: str) -> dict[str, object]:
    public_target = target.to_dict()
    raw_spec = str(public_target.get("raw_spec") or "")
    source_url = _optional_string(public_target.get("source_url"))
    return {
        "artifact_id": f"{target.ecosystem}:{target.package_name or raw_spec}",
        "artifact_name": target.package_name or raw_spec,
        "artifact_type": "package_request",
        "ecosystem": target.ecosystem,
        "package_name": target.package_name,
        "package_url": None,
        "raw_spec": raw_spec,
        "version": target.requested_specifier,
        "source_url": source_url,
        "harness": harness,
    }


__all__ = [
    "LOCAL_SUPPLY_CHAIN_HARNESS",
    "PackageProtectProjection",
    "PackageProtectVerdictContext",
    "build_package_guard_receipt",
    "protect_target_payload",
    "resolve_local_supply_chain_harness",
]
