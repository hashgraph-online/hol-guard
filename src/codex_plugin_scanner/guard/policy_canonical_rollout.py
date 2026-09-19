"""Canonical/managed policy enforcement-lane selection for runtime posture."""

from __future__ import annotations

import hashlib
import os
from typing import Literal

from .managed_controls.feature_flags import ManagedControlsFeatureFlags
from .policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT

POLICY_CANONICAL_ENFORCEMENT_ENV = "HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT"
EnforcementLane = Literal["legacy", "canonical", "unverified", "incompatible"]


def canonical_policy_rollout_percentage() -> int:
    raw = os.environ.get(POLICY_CANONICAL_ENFORCEMENT_ENV, "").strip().lower()
    if raw in {"", "0", "false", "off", "legacy"}:
        return 0
    if raw in {"1", "true", "on", "canonical"}:
        return 100
    try:
        percentage = int(raw)
    except ValueError:
        return 0
    return percentage if 1 <= percentage <= 100 else 0


def canonical_policy_enforcement_enabled(*, device_id: str, workspace_id: str | None) -> bool:
    percentage = canonical_policy_rollout_percentage()
    if percentage in {0, 100}:
        return percentage == 100
    cohort_key = f"{workspace_id or 'local'}:{device_id}".encode()
    # This is an in-memory rollout bucket for opaque installation IDs, not a password verifier.
    # codeql[py/weak-sensitive-data-hashing]
    cohort = int.from_bytes(hashlib.sha256(cohort_key).digest()[:8], "big") % 100
    return cohort < percentage


def selected_enforcement_lane(
    *,
    device_id: str,
    workspace_id: str | None,
    protected_authority: bool,
    negotiated_capabilities: frozenset[str],
    required_capability: str | None = None,
    contract_version: str | None = None,
) -> tuple[EnforcementLane, str | None]:
    """Return the live lane and a bounded incompatibility reason."""

    flags = ManagedControlsFeatureFlags.from_environment()
    advertised = flags.runtime_capabilities(protected_authority=protected_authority)
    if contract_version == POLICY_BUNDLE_V2_CONTRACT and required_capability is not None and not protected_authority:
        return "incompatible", "missing_protected_authority"
    if required_capability is not None and (
        required_capability not in advertised or required_capability not in negotiated_capabilities
    ):
        return "incompatible", "missing_negotiated_capability"
    if not canonical_policy_enforcement_enabled(device_id=device_id, workspace_id=workspace_id):
        if contract_version == POLICY_BUNDLE_V2_CONTRACT:
            return "unverified", "canonical_enforcement_disabled"
        return "legacy", None
    if contract_version == POLICY_BUNDLE_V2_CONTRACT:
        return "canonical", None
    return "legacy", None


def canonical_runtime_posture(
    *,
    device_id: str,
    workspace_id: str | None,
    protected_authority: bool = False,
    negotiated_capabilities: frozenset[str] = frozenset(),
    contract_version: str | None = None,
    required_capability: str | None = None,
) -> dict[str, object]:
    """Advertise advertised vs effective canonical/managed capabilities."""

    flags = ManagedControlsFeatureFlags.from_environment()
    advertised = list(flags.runtime_capabilities(protected_authority=True))
    effective = list(flags.runtime_capabilities(protected_authority=protected_authority))
    if required_capability is not None:
        effective = [capability for capability in effective if capability in negotiated_capabilities]
    enabled = canonical_policy_enforcement_enabled(device_id=device_id, workspace_id=workspace_id)
    lane, reason = selected_enforcement_lane(
        device_id=device_id,
        workspace_id=workspace_id,
        protected_authority=protected_authority,
        negotiated_capabilities=negotiated_capabilities,
        contract_version=contract_version,
        required_capability=required_capability,
    )
    session: dict[str, object] = {
        "advertised_canonical_capabilities": advertised,
        "effective_canonical_capabilities": effective,
        "canonical_policy_enforcement_enabled": enabled,
        "selected_enforcement_lane": lane,
        "canonical_rollout_percentage": canonical_policy_rollout_percentage(),
    }
    if reason is not None:
        session["canonical_incompatibility_reason"] = reason
    if enabled:
        session["canonical_policy_enforcement"] = True
    return session
