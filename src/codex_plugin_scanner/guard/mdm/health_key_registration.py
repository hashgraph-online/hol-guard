"""Proof-of-possession registration for machine health signing keys."""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .contracts import MachinePaths
from .device_key_access import verified_machine_device_key_by_id
from .health_lease_contract import HealthLeaseBinding, canonical_json_bytes, canonical_timestamp

_SCHEMA = "hol-guard-health-key-registration.v1"
_P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def build_machine_health_key_registration(
    paths: MachinePaths,
    binding: HealthLeaseBinding,
    *,
    installation_generation: str,
    machine_installation_id: str,
    key_id: str | None = None,
    now: datetime | None = None,
    system_name: str,
) -> bytes:
    """Build a fresh, canonical registration signed by the non-exportable machine key."""

    from .device_key_native import sign_health_key_registration

    generation = verified_machine_device_key_by_id(paths, key_id, system_name=system_name)
    timestamp = canonical_timestamp((now or datetime.now(timezone.utc)).astimezone(timezone.utc))
    registration: dict[str, object] = {
        "algorithm": "ecdsa-p256-sha256",
        "deviceId": binding.device_id,
        "installationGeneration": installation_generation,
        "keyId": generation.key_id,
        "machineInstallationId": machine_installation_id,
        "previousInstallationGeneration": None,
        "publicKeySpki": generation.public_key_spki,
        "registeredAt": timestamp,
        "schemaVersion": _SCHEMA,
        "workspaceId": binding.workspace_id,
    }
    canonical_registration = canonical_json_bytes(registration)
    signature = _low_s_signature(
        sign_health_key_registration(
            paths,
            generation.generation,
            canonical_registration,
            system_name=system_name,
        ).signature
    )
    return canonical_json_bytes(
        {
            **registration,
            "proof": {
                "algorithm": "ecdsa-p256-sha256",
                "encoding": "asn1-der",
                "value": base64.b64encode(signature).decode("ascii"),
            },
        }
    )


def _low_s_signature(signature: bytes) -> bytes:
    try:
        r, s = decode_dss_signature(signature)
    except ValueError as exc:
        raise OSError("health_key_registration_signature_invalid") from exc
    if not 1 <= r < _P256_ORDER or not 1 <= s < _P256_ORDER:
        raise OSError("health_key_registration_signature_invalid")
    return encode_dss_signature(r, min(s, _P256_ORDER - s))


__all__ = ["build_machine_health_key_registration"]
