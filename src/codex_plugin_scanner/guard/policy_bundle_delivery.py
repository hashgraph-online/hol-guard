"""Managed policy-bundle delivery binding and acknowledgements.

Rust owns delivery validation against signed and local authority, extension
semantics detection and acknowledgement construction. Python keeps the
extension-control projection digest, which reads the live runtime snapshot, and
the transport calls that return the validated records.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from .native_policy_bundle import (
    PolicyBundleNativeError,
    PolicyBundleNativeUnavailableError,
    native_rejection_code,
    policy_bundle_chunks,
    policy_bundle_verdict,
)
from .runtime.extension_control_authority import ExtensionControlAuthorityView
from .runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot

_ACK_BUNDLE_KEYS = ("contractVersion", "bundleHash", "bundleVersion")


def effective_projection_digest(view: ExtensionControlAuthorityView) -> str:
    """Return the Portal wire digest for the exact candidate runtime snapshot."""

    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(view)
    return f"sha256:{snapshot.effective_digest}"


def _chunks(policy_bundle: Mapping[str, object], keys: tuple[str, ...] | None = None) -> list[str]:
    document = (
        dict(policy_bundle) if keys is None else {key: policy_bundle[key] for key in keys if key in policy_bundle}
    )
    return policy_bundle_chunks(document)


def validate_policy_bundle_delivery(
    value: object,
    *,
    policy_bundle: Mapping[str, object],
    workspace_id: str | None,
    device_id: str,
    runtime_summary: object,
) -> tuple[dict[str, object] | None, str | None]:
    """Validate an exact delivery object and bind it to signed/local authority."""

    try:
        policy_bundle_verdict(
            "delivery_validate",
            {
                "delivery": value,
                "bundle_chunks": _chunks(policy_bundle),
                "workspace_id": workspace_id,
                "device_id": device_id,
                "runtime_summary": runtime_summary,
            },
        )
    except PolicyBundleNativeError as error:
        return None, native_rejection_code(error)
    return (dict(value) if isinstance(value, dict) else {}), None


def validated_managed_policy_delivery(
    *,
    policy_bundle: dict[str, object],
    delivery_field_provided: bool,
    delivery_payload: object,
    workspace_id: str | None,
    device_id: str,
    runtime_summary: object,
    expected_extension_projection_digest: str | None,
) -> tuple[dict[str, object] | None, str | None]:
    """Validate delivery metadata only when a V2 bundle carries Extension semantics."""

    try:
        result = policy_bundle_verdict(
            "managed_delivery",
            {
                "bundle_chunks": _chunks(policy_bundle),
                "provided": delivery_field_provided,
                "delivery": delivery_payload,
                "workspace_id": workspace_id,
                "device_id": device_id,
                "runtime_summary": runtime_summary,
                "expected_projection": expected_extension_projection_digest,
            },
        )
    except PolicyBundleNativeError as error:
        return None, native_rejection_code(error)
    if result.get("applicable") is True and isinstance(delivery_payload, dict):
        return dict(delivery_payload), None
    return None, None


def _acknowledgement(result: dict[str, object]) -> dict[str, object]:
    ack = result.get("ack")
    if not isinstance(ack, dict):
        raise PolicyBundleNativeUnavailableError("native_policy_bundle_authority_schema_mismatch")
    return ack


def policy_bundle_acknowledgement_payload(
    *,
    device_id: str,
    device_name: str,
    policy_bundle: dict[str, object],
    synced_at: str,
    status: Literal["validated", "applied"] = "applied",
    previous: dict[str, object] | None = None,
    delivery: dict[str, object] | None = None,
    applied_extension_authority_revision: int | None = None,
    applied_effective_projection_digest: str | None = None,
) -> dict[str, object]:
    """Build a legacy acknowledgement or an exact delivery-bound V2 acknowledgement."""

    return _acknowledgement(
        policy_bundle_verdict(
            "ack_payload",
            {
                "device_id": device_id,
                "device_name": device_name,
                "bundle_chunks": _chunks(policy_bundle, _ACK_BUNDLE_KEYS),
                "synced_at": synced_at,
                "status": status,
                "previous": previous,
                "delivery": delivery,
                "applied_revision": applied_extension_authority_revision,
                "applied_digest": applied_effective_projection_digest,
            },
        )
    )


def effective_policy_bundle_acknowledgement(
    *,
    device_id: str,
    device_name: str,
    effective_policy_bundle: dict[str, object],
    validated_policy_bundle: dict[str, object] | None,
    validated_delivery: dict[str, object] | None,
    stored_acknowledgement: object,
    synced_at: str,
) -> dict[str, object]:
    """Select the exact acknowledgement for a newly activated or retained bundle."""

    validated = None
    if validated_policy_bundle is not None:
        validated = {key: validated_policy_bundle[key] for key in ("bundleHash",) if key in validated_policy_bundle}
    return _acknowledgement(
        policy_bundle_verdict(
            "effective_ack",
            {
                "device_id": device_id,
                "device_name": device_name,
                "effective_chunks": _chunks(effective_policy_bundle, _ACK_BUNDLE_KEYS),
                "validated": validated,
                "delivery": validated_delivery,
                "stored": stored_acknowledgement if isinstance(stored_acknowledgement, dict) else None,
                "synced_at": synced_at,
            },
        )
    )
