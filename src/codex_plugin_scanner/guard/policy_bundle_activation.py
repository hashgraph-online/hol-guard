"""Atomic Managed Controls delivery helpers for policy activation."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping

from .managed_controls_policy_bundle import signed_cloud_extension_projection_digest
from .managed_controls_policy_fields import ParsedManagedControlsPolicy
from .policy_bundle_delivery import effective_projection_digest, policy_bundle_acknowledgement_payload
from .runtime.extension_control_authority import ExtensionControlAuthorityView
from .runtime.extension_control_contract import ControlLayerKind, ExtensionControlLayer


def managed_delivery_matches_base(
    delivery: Mapping[str, object],
    *,
    policy_bundle: Mapping[str, object],
    policy: ParsedManagedControlsPolicy,
    base_authority: ExtensionControlAuthorityView,
) -> bool:
    return (
        delivery.get("extensionAuthorityRevision") == base_authority.revision
        and delivery.get("effectiveProjectionDigest") == effective_projection_digest(base_authority)
        and delivery.get("payloadHash") == policy_bundle.get("payloadHash")
        and delivery.get("extensionProjectionDigest")
        == signed_cloud_extension_projection_digest(
            policy,
            catalog_digest=str(delivery.get("catalogDigest")),
        )
    )


def published_managed_authority(
    base: ExtensionControlAuthorityView,
    *,
    policy: ParsedManagedControlsPolicy | None,
    managed_revision: int,
) -> ExtensionControlAuthorityView:
    local_layers = tuple(layer for layer in base.layers if layer.kind is ControlLayerKind.LOCAL_ADMIN)
    signed_layers = () if policy is None or policy.signed_cloud_layer is None else (policy.signed_cloud_layer,)
    return ExtensionControlAuthorityView(
        base.health,
        base.revision,
        base.catalog_digest,
        (*local_layers, *signed_layers),
        managed_revision,
    )


def composed_managed_authority(
    base: ExtensionControlAuthorityView,
    *,
    managed_layers: tuple[ExtensionControlLayer, ...],
    managed_revision: int,
) -> ExtensionControlAuthorityView:
    """Compose the exact authoritative runtime view observed under the write lock."""

    local_layers = tuple(layer for layer in base.layers if layer.kind is ControlLayerKind.LOCAL_ADMIN)
    return ExtensionControlAuthorityView(
        base.health,
        base.revision,
        base.catalog_digest,
        (*local_layers, *managed_layers),
        managed_revision,
    )


def encoded_delivery_acknowledgement(
    connection: sqlite3.Connection,
    *,
    delivery: Mapping[str, object],
    policy_bundle: Mapping[str, object],
    published_authority: ExtensionControlAuthorityView,
    observed_at: str,
) -> str:
    row = connection.execute(
        "select payload_json from sync_state where state_key = ?",
        ("policy_bundle_ack",),
    ).fetchone()
    previous = None
    if row is not None:
        value = json.loads(str(row["payload_json"]))
        previous = value if isinstance(value, dict) else None
    acknowledgement = policy_bundle_acknowledgement_payload(
        device_id=str(delivery["deviceId"]),
        device_name="Guard",
        policy_bundle=dict(policy_bundle),
        synced_at=observed_at,
        previous=previous,
        delivery=dict(delivery),
        applied_extension_authority_revision=published_authority.managed_revision,
        applied_effective_projection_digest=effective_projection_digest(published_authority),
    )
    return json.dumps(acknowledgement, allow_nan=False)
