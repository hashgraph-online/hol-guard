"""Bounded display evidence from Core's existing validated policy authority."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..policy_bundle_ack_contract import generic_ack_matches_bundle, validated_generic_policy_acknowledgement
from ..policy_bundle_delivery import policy_bundle_has_extension_semantics
from ..policy_bundle_rollout import policy_bundle_rollout_state
from ..policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT
from ..policy_canonical_rollout import canonical_policy_enforcement_enabled
from ..synced_policy import synced_policy_bundle_validation

if TYPE_CHECKING:
    from ..store import GuardStore

_SAFE_CODE = re.compile(r"[a-z][a-z0-9_-]{0,95}\Z")


def _revision(value: object) -> str | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 < value <= 2**53 - 1:
        return str(value)
    if isinstance(value, str) and 0 < len(value) <= 128 and value == value.strip():
        return value
    return None


def policy_application_evidence(
    bundle: dict[str, object],
    acknowledgement: object,
    *,
    workspace_id: str | None,
    device_id: str | None,
) -> dict[str, object]:
    """A transport timestamp or an unrelated applied ACK is not this authority."""
    evidence: dict[str, object] = {
        "policyBundleVersion": _revision(bundle.get("bundleVersion")),
        "policyBundleHash": bundle.get("bundleHash"),
    }
    rollout = policy_bundle_rollout_state(bundle)
    if isinstance(rollout, str) and _SAFE_CODE.fullmatch(rollout):
        evidence["policyRolloutState"] = rollout
    if bundle.get("contractVersion") != POLICY_BUNDLE_V2_CONTRACT or not device_id or not workspace_id:
        return evidence
    if not isinstance(acknowledgement, dict):
        return evidence
    payload = bundle.get("payload")
    metadata = payload.get("metadata") if isinstance(payload, dict) else None
    revision = metadata.get("revision") if isinstance(metadata, dict) else None
    if bundle.get("workspaceId") != workspace_id:
        return evidence
    if policy_bundle_has_extension_semantics(bundle):
        # A signed delivery receipt alone does not prove the protected resident
        # projection is still installed. Keep managed application unknown.
        return evidence
    ack, _reason = validated_generic_policy_acknowledgement(acknowledgement)
    matches = ack is not None and generic_ack_matches_bundle(ack, bundle, device_id=device_id)
    if matches and ack is not None and ack.get("status") == "applied" and _revision(revision) is not None:
        evidence["appliedRevision"] = _revision(revision)
        evidence["policyLastAckAt"] = ack.get("observedAt")
    return evidence


def read_policy_application_evidence(store: GuardStore) -> dict[str, object]:
    bundle, reason = synced_policy_bundle_validation(store)
    evidence: dict[str, object] = {}
    if bundle is not None:
        summary = store.get_sync_payload("runtime_session_summary")
        device = summary.get("runtime_device_id") if isinstance(summary, dict) else None
        evidence.update(
            policy_application_evidence(
                bundle,
                store.get_sync_payload("policy_bundle_ack"),
                workspace_id=store.get_cloud_workspace_id(),
                device_id=device if isinstance(device, str) else None,
            )
        )
        with store._connect() as connection:
            row = connection.execute(
                "select installation_id from guard_devices where device_key = 'local-device'",
            ).fetchone()
        installation_id = row["installation_id"] if row is not None else None
        if not isinstance(installation_id, str) or not canonical_policy_enforcement_enabled(
            device_id=installation_id,
            workspace_id=store.get_cloud_workspace_id(),
        ):
            evidence.pop("appliedRevision", None)
            evidence.pop("policyLastAckAt", None)
    last_error = store.get_sync_payload("policy_bundle_last_error")
    error = reason or (last_error.get("reason") if isinstance(last_error, dict) else None)
    if isinstance(error, str):
        evidence["policySyncError"] = error if _SAFE_CODE.fullmatch(error) else "policy_status_unavailable"
    return evidence
