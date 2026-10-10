"""Atomic Managed Controls delivery helpers for policy activation."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Hashable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from .managed_controls_policy_bundle import signed_cloud_extension_projection_digest
from .managed_controls_policy_fields import ParsedManagedControlsPolicy
from .policy_bundle_delivery import effective_projection_digest, policy_bundle_acknowledgement_payload
from .runtime.extension_control_authority import ExtensionControlAuthorityView
from .runtime.extension_control_contract import ControlLayerKind, ExtensionControlLayer


class PolicyBundleActivationRejectionError(RuntimeError):
    """Typed fail-closed policy activation rejection."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class PolicyBundleRejectionStore(Protocol):
    def set_sync_payload(
        self,
        state_key: str,
        payload: Mapping[str, object] | Sequence[object],
        now: str,
    ) -> None: ...

    def add_event(self, event_name: str, payload: dict[str, object], now: str) -> None: ...


def activate_with_reason(
    activate: Callable[..., dict[str, object] | None],
    *args: object,
    **kwargs: object,
) -> tuple[dict[str, object] | None, str]:
    """Run strict activation while preserving its typed rejection reason."""

    kwargs["raise_on_rejection"] = True
    try:
        result = activate(*args, **kwargs)
        return result, "" if result is not None else "policy_bundle_activation_rejected"
    except PolicyBundleActivationRejectionError as error:
        return None, error.reason


def persist_activation_rejection(
    store: PolicyBundleRejectionStore,
    payload: dict[str, object],
    now: str,
) -> None:
    store.set_sync_payload("policy_bundle_last_error", payload, now)
    store.add_event("policy_bundle/rejected", payload, now)


def managed_delivery_matches_base(
    delivery: Mapping[str, object],
    *,
    policy_bundle: Mapping[str, object],
    policy: ParsedManagedControlsPolicy,
    base_authority: ExtensionControlAuthorityView,
) -> bool:
    catalog_digest = delivery.get("catalogDigest")
    return (
        isinstance(catalog_digest, str)
        and bool(catalog_digest)
        and delivery.get("extensionAuthorityRevision") == base_authority.revision
        and delivery.get("effectiveProjectionDigest") == effective_projection_digest(base_authority)
        and delivery.get("payloadHash") == policy_bundle.get("payloadHash")
        and delivery.get("extensionProjectionDigest")
        == signed_cloud_extension_projection_digest(
            policy,
            catalog_digest=catalog_digest,
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


@dataclass(frozen=True)
class DeliveryAcknowledgementInputs:
    """State read under the write lock that the acknowledgement is derived from."""

    previous_json: str | None
    applied_revision: int
    applied_digest: str


class ResidentVerdictRequiredError(Exception):
    """Signal that a resident verdict must be computed outside the authority lock."""

    def __init__(self, key: Hashable, compute: Callable[[], object], invalid_reason: str) -> None:
        super().__init__("resident verdict must be computed before taking the authority lock")
        self.key = key
        self.compute = compute
        self.invalid_reason = invalid_reason


class PrecomputedVerdicts:
    """Resident verdicts computed between attempts, keyed by the exact state they decide.

    The resident can take seconds, so it must not run while the authority lock
    and the SQLite write transaction are held. A locked attempt asks for a
    verdict with the state it just read; a verdict is reused only when it was
    computed for exactly that state, otherwise the attempt is abandoned and
    retried against the re-read state.
    """

    def __init__(self) -> None:
        self._values: dict[Hashable, object] = {}

    def resolve(self, key: Hashable, compute: Callable[[], object], invalid_reason: str) -> object:
        if key in self._values:
            return self._values[key]
        raise ResidentVerdictRequiredError(key, compute, invalid_reason)

    def fill(self, required: ResidentVerdictRequiredError) -> None:
        self._values[required.key] = required.compute()


def _encode_acknowledgement(
    inputs: DeliveryAcknowledgementInputs,
    *,
    device_id: str,
    delivery: Mapping[str, object],
    policy_bundle: Mapping[str, object],
    observed_at: str,
) -> str:
    previous = None
    if inputs.previous_json is not None:
        value = json.loads(inputs.previous_json)
        previous = value if isinstance(value, dict) else None
    acknowledgement = policy_bundle_acknowledgement_payload(
        device_id=device_id,
        device_name="Guard",
        policy_bundle=dict(policy_bundle),
        synced_at=observed_at,
        previous=previous,
        delivery=dict(delivery),
        applied_extension_authority_revision=inputs.applied_revision,
        applied_effective_projection_digest=inputs.applied_digest,
    )
    return json.dumps(acknowledgement, allow_nan=False)


def encoded_delivery_acknowledgement(
    connection: sqlite3.Connection,
    *,
    delivery: Mapping[str, object],
    policy_bundle: Mapping[str, object],
    published_authority: ExtensionControlAuthorityView,
    observed_at: str,
    verdicts: PrecomputedVerdicts | None = None,
) -> str:
    """Return the encoded acknowledgement for the state observed on ``connection``.

    The acknowledgement comes from the resident. With ``verdicts`` the call never
    reaches the resident: it returns the result computed for exactly the state
    observed here, or raises ``ResidentVerdictRequiredError`` so the caller can
    compute it after releasing the lock and retry.
    """

    device_id = delivery.get("deviceId")
    if not isinstance(device_id, str) or not device_id:
        raise ValueError("Managed Controls delivery requires a device identity")
    row = connection.execute(
        "select payload_json from sync_state where state_key = ?",
        ("policy_bundle_ack",),
    ).fetchone()
    inputs = DeliveryAcknowledgementInputs(
        previous_json=None if row is None else str(row["payload_json"]),
        applied_revision=published_authority.managed_revision,
        applied_digest=effective_projection_digest(published_authority),
    )

    def compute() -> str:
        return _encode_acknowledgement(
            inputs,
            device_id=device_id,
            delivery=delivery,
            policy_bundle=policy_bundle,
            observed_at=observed_at,
        )

    if verdicts is None:
        return compute()
    return str(verdicts.resolve(("ack", inputs), compute, "managed_controls_delivery_ack_invalid"))
