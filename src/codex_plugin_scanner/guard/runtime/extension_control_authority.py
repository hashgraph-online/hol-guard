"""Authenticated records for the command-extension control authority."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import Enum
from typing import Final, cast

from .extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlSurface,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)

AUTHORITY_SCHEMA_VERSION: Final = 1
SNAPSHOT_PURPOSE: Final = "extension-control.snapshot"
TRANSITION_PURPOSE: Final = "extension-control.transition"
ANCHOR_PURPOSE: Final = "extension-control.anchor"
_AUTH_DOMAIN: Final = b"hol-guard.extension-control-authority.v1\0"


class ExtensionControlAuthorityError(RuntimeError):
    """An extension-control authority invariant could not be satisfied."""


class AuthorityPhase(str, Enum):
    PREPARED = "prepared"
    ANCHORED = "anchored"
    COMMITTED = "committed"


class AuthorityHealth(str, Enum):
    PROTECTED = "protected"
    DEGRADED_UNACKNOWLEDGED = "degraded-unacknowledged"
    DEGRADED_ACKNOWLEDGED = "degraded-acknowledged"
    TAMPERED = "tampered"
    RECOVERY_REQUIRED = "recovery-required"


@dataclass(frozen=True, slots=True)
class ExtensionControlAuthorityView:
    health: AuthorityHealth
    revision: int
    catalog_digest: str
    layers: tuple[ExtensionControlLayer, ...]

    def layers_for(self, surface: ControlSurface) -> tuple[ExtensionControlLayer, ...]:
        if self.health is AuthorityHealth.PROTECTED:
            return self.layers
        if surface in {ControlSurface.TRUSTED_LOCAL_RECOVERY, ControlSurface.TRUSTED_LOCAL_PROOF}:
            return ()
        return (
            ExtensionControlLayer(
                schema_version=CONTROL_SCHEMA_VERSION,
                kind=ControlLayerKind.LOCAL_ADMIN,
                catalog_digest=self.catalog_digest,
                global_lockdown=True,
                controls=(),
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthorityAnchor:
    revision: int
    snapshot_digest: str
    phase: AuthorityPhase


def layers_to_json(layers: tuple[ExtensionControlLayer, ...]) -> str:
    return _canonical_json([_layer_to_value(layer) for layer in layers])


def layers_from_json(value: str) -> tuple[ExtensionControlLayer, ...]:
    try:
        raw = cast(object, json.loads(value))
    except (TypeError, json.JSONDecodeError) as exc:
        raise ExtensionControlAuthorityError("invalid extension control layers") from exc
    if not isinstance(raw, list):
        raise ExtensionControlAuthorityError("invalid extension control layers")
    return tuple(_layer_from_value(item) for item in cast(list[object], raw))


def authenticated_record(
    payload: dict[str, object],
    *,
    key: bytes,
    purpose: str,
) -> tuple[str, str, str]:
    framed = {"authority_schema_version": AUTHORITY_SCHEMA_VERSION, "purpose": purpose, **payload}
    encoded = _canonical_json(framed)
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    mac = hmac.new(_purpose_key(key, purpose), encoded.encode("utf-8"), hashlib.sha256).hexdigest()
    return encoded, digest, mac


def verify_authenticated_record(
    encoded: str,
    *,
    expected_digest: str,
    expected_mac: str,
    key: bytes,
    purpose: str,
) -> dict[str, object]:
    try:
        raw = cast(object, json.loads(encoded))
    except (TypeError, json.JSONDecodeError) as exc:
        raise ExtensionControlAuthorityError("invalid authenticated authority record") from exc
    if not isinstance(raw, dict):
        raise ExtensionControlAuthorityError("invalid authenticated authority record")
    mapping = cast(dict[object, object], raw)
    if any(not isinstance(name, str) for name in mapping):
        raise ExtensionControlAuthorityError("invalid authenticated authority record")
    payload = cast(dict[str, object], mapping)
    if payload.get("authority_schema_version") != AUTHORITY_SCHEMA_VERSION:
        raise ExtensionControlAuthorityError("unsupported authority schema")
    if payload.get("purpose") != purpose:
        raise ExtensionControlAuthorityError("authority record purpose mismatch")
    canonical = _canonical_json(payload)
    actual_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    actual_mac = hmac.new(_purpose_key(key, purpose), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_digest) or not hmac.compare_digest(actual_mac, expected_mac):
        raise ExtensionControlAuthorityError("authority record authentication failed")
    return payload


def anchor_to_json(anchor: AuthorityAnchor, *, key: bytes) -> str:
    encoded, digest, mac = authenticated_record(
        {
            "revision": anchor.revision,
            "snapshot_digest": anchor.snapshot_digest,
            "phase": anchor.phase.value,
        },
        key=key,
        purpose=ANCHOR_PURPOSE,
    )
    return _canonical_json({"record": encoded, "digest": digest, "mac": mac})


def anchor_from_json(value: str, *, key: bytes) -> AuthorityAnchor:
    try:
        raw_envelope = cast(object, json.loads(value))
    except (TypeError, json.JSONDecodeError) as exc:
        raise ExtensionControlAuthorityError("invalid authority anchor") from exc
    if not isinstance(raw_envelope, dict):
        raise ExtensionControlAuthorityError("invalid authority anchor")
    envelope = cast(dict[object, object], raw_envelope)
    record = envelope.get("record")
    digest = envelope.get("digest")
    mac = envelope.get("mac")
    if not all(isinstance(item, str) for item in (record, digest, mac)):
        raise ExtensionControlAuthorityError("invalid authority anchor")
    payload = verify_authenticated_record(
        cast(str, record),
        expected_digest=cast(str, digest),
        expected_mac=cast(str, mac),
        key=key,
        purpose=ANCHOR_PURPOSE,
    )
    revision = payload.get("revision")
    snapshot_digest = payload.get("snapshot_digest")
    phase = payload.get("phase")
    if type(revision) is not int or revision < 0:
        raise ExtensionControlAuthorityError("invalid authority anchor revision")
    if not isinstance(snapshot_digest, str) or len(snapshot_digest) != 64:
        raise ExtensionControlAuthorityError("invalid authority anchor digest")
    if not isinstance(phase, str):
        raise ExtensionControlAuthorityError("invalid authority anchor phase")
    try:
        parsed_phase = AuthorityPhase(phase)
    except ValueError as exc:
        raise ExtensionControlAuthorityError("invalid authority anchor phase") from exc
    return AuthorityAnchor(revision, snapshot_digest, parsed_phase)


def _layer_to_value(layer: ExtensionControlLayer) -> dict[str, object]:
    return {
        "schema_version": layer.schema_version,
        "kind": layer.kind.value,
        "catalog_digest": layer.catalog_digest,
        "global_lockdown": layer.global_lockdown,
        "controls": [
            {
                "target_kind": control.target.kind.value,
                "target_id": control.target.target_id,
                "state": control.state.value,
            }
            for control in layer.controls
        ],
    }


def _layer_from_value(raw: object) -> ExtensionControlLayer:
    if not isinstance(raw, dict):
        raise ExtensionControlAuthorityError("invalid extension control layer")
    mapping = cast(dict[object, object], raw)
    if any(not isinstance(name, str) for name in mapping):
        raise ExtensionControlAuthorityError("invalid extension control layer")
    value = cast(dict[str, object], mapping)
    controls_raw = value.get("controls")
    if not isinstance(controls_raw, list):
        raise ExtensionControlAuthorityError("invalid extension controls")
    controls: list[ExtensionControl] = []
    try:
        for item_raw in cast(list[object], controls_raw):
            if not isinstance(item_raw, dict):
                raise ExtensionControlAuthorityError("invalid extension control")
            item = cast(dict[str, object], item_raw)
            target_kind = ControlTargetKind(item.get("target_kind"))
            target_id = item.get("target_id")
            if not isinstance(target_id, str):
                raise ExtensionControlAuthorityError("invalid extension control target")
            controls.append(
                ExtensionControl(
                    ControlTarget(target_kind, target_id),
                    ControlState(item.get("state")),
                )
            )
        schema_version = value.get("schema_version")
        catalog_digest = value.get("catalog_digest")
        lockdown = value.get("global_lockdown")
        if not isinstance(schema_version, str) or not isinstance(catalog_digest, str):
            raise ExtensionControlAuthorityError("invalid extension control layer metadata")
        if type(lockdown) is not bool:
            raise ExtensionControlAuthorityError("invalid extension control lockdown")
        return ExtensionControlLayer(
            schema_version=schema_version,
            kind=ControlLayerKind(value.get("kind")),
            catalog_digest=catalog_digest,
            global_lockdown=lockdown,
            controls=tuple(controls),
        )
    except (TypeError, ValueError) as exc:
        raise ExtensionControlAuthorityError("invalid extension control layer") from exc


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _purpose_key(key: bytes, purpose: str) -> bytes:
    return hmac.new(key, _AUTH_DOMAIN + purpose.encode("utf-8"), hashlib.sha256).digest()
