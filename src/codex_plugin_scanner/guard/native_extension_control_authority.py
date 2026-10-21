"""Resident bridge for the ``extension_control_authority`` op.

Rust owns reading and verifying the authenticated extension-control authority:
the snapshot, its anchor, the transition chain behind it, the trusted catalog
manifests and the managed-controls activation composed on top. This module
ships the request with the authority key and the raw vault anchor, binds the
reply by ``request_id`` plus ``request_sha256`` and decodes it.

Nothing is verified in Python and nothing falls back to it. A resident that
cannot answer raises ``NativeExtensionControlAuthorityUnavailableError``, an
outage rather than a verdict, and a fault the resident reports raises the
exception the Python store used to raise for it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from . import native_extension_control_authority_memo as memo
from .native_command_control_authority_io import NativeCommandControlAuthorityUnavailableError
from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_policy_snapshot_constants import NATIVE_POLICY_VERIFIER_KEY_NAME, NATIVE_RUNTIME_STATE_DIRECTORY
from .native_store_policy import _payload, encode_key
from .runtime.extension_control_authority import (
    AuthorityAnchor,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    layers_from_json,
    layers_to_json,
)
from .runtime.extension_control_contract import ExtensionControlLayer

if TYPE_CHECKING:
    from .runtime.extension_control_authority import ExtensionControlAuthorityView
    from .store import GuardStore

EXTENSION_CONTROL_AUTHORITY_FEATURE = "extension-control-authority-v1"
_REQUEST_SCHEMA = "guard-extension-control-authority-request.v1"
_RESULT_SCHEMA = "guard-extension-control-authority-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 16 * 1024 * 1024
_FLAGS = ("migration", "allow_migration", "restore_attempted", "resume_attempted", "rollback_attempted")


class NativeExtensionControlAuthorityUnavailableError(NativeCommandControlAuthorityUnavailableError):
    """The resident did not answer, so the authority was not read."""

    code = "native_extension_control_authority_unavailable"

    def __init__(self) -> None:
        super().__init__(shared=True)
        self.args = ("The native runtime did not answer the extension control authority read.",)


def extension_control_authority(
    *,
    store_path: Path,
    guard_home: Path,
    op: str,
    key: bytes | None,
    store: GuardStore | None = None,
    **fields: object,
) -> dict[str, object]:
    """The resident's answer to ``op``; raises on an outage or a fault.

    Optional fields set to ``None`` are omitted. The resident re-serializes
    the request to bind its reply, and it always writes the flags, so every
    flag is sent even when unset. A settled reply to the same request over an
    unchanged database is served from the memo without asking again.

    With ``store``, the resident's verifier key is provisioned from that store
    rather than from a fresh one, so the read answers to the same integrity
    material as the caller.
    """

    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"extension-control-authority-{uuid4().hex}",
        "store_path": str(store_path),
        "guard_home": str(guard_home),
        "op": op,
        **dict.fromkeys(_FLAGS, False),
    }
    if key is not None:
        wire["key_b64"] = encode_key(key)
    wire.update({name: value for name, value in fields.items() if value is not None})
    memo_key, kept = memo.lookup(wire)
    if kept is not None:
        return kept
    verifier = guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / NATIVE_POLICY_VERIFIER_KEY_NAME
    if store is not None and not verifier.is_file():
        from .native_policy_snapshot_publisher import provision_native_verifier_key_for_store

        try:
            provision_native_verifier_key_for_store(store)
        except Exception as exc:
            raise NativeExtensionControlAuthorityUnavailableError() from exc
    if not ensure_resident_prerequisite(guard_home):
        raise NativeExtensionControlAuthorityUnavailableError()
    try:
        response = _resident_request(
            operation="extension_control_authority",
            request=wire,
            guard_home=guard_home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=EXTENSION_CONTROL_AUTHORITY_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError) as exc:
        raise NativeExtensionControlAuthorityUnavailableError() from exc
    payload = _payload(response, wire, guard_home)
    if payload is None:
        raise NativeExtensionControlAuthorityUnavailableError()
    memo.keep(memo_key, payload)
    return payload


def raise_fault(payload: Mapping[str, object]) -> None:
    """Raise the store exception for a fault reply; return for any other."""

    fault = payload.get("fault")
    if fault is None:
        return
    reason = payload.get("reason")
    message = reason if isinstance(reason, str) and reason else "extension control authority fault"
    if fault == "tampered":
        raise ExtensionControlAuthorityError(message)
    raise RuntimeError(message)


def manifest_sha256(manifest: Mapping[str, str]) -> str:
    """The digest the resident compares a recorded manifest against."""

    encoded = json.dumps(dict(manifest), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def layers_to_wire(layers: tuple[ExtensionControlLayer, ...]) -> list[object]:
    value = json.loads(layers_to_json(layers))
    return value if isinstance(value, list) else []


def layers_from_wire(value: object) -> tuple[ExtensionControlLayer, ...]:
    if not isinstance(value, list):
        raise ExtensionControlAuthorityError("invalid extension control layers")
    return layers_from_json(json.dumps(value, sort_keys=True, separators=(",", ":")))


def view_to_wire(view: ExtensionControlAuthorityView) -> dict[str, object]:
    return {
        "health": view.health.value,
        "revision": view.revision,
        "catalog_digest": view.catalog_digest,
        "layers": layers_to_wire(view.layers),
        "managed_revision": view.managed_revision,
    }


def anchor_from_wire(value: object) -> AuthorityAnchor:
    if not isinstance(value, dict):
        raise ExtensionControlAuthorityError("invalid authority anchor")
    revision, snapshot_digest, phase = value.get("revision"), value.get("snapshot_digest"), value.get("phase")
    if type(revision) is not int or not isinstance(snapshot_digest, str) or not isinstance(phase, str):
        raise ExtensionControlAuthorityError("invalid authority anchor")
    try:
        return AuthorityAnchor(revision, snapshot_digest, AuthorityPhase(phase))
    except ValueError as exc:
        raise ExtensionControlAuthorityError("invalid authority anchor") from exc


def manifest_from_wire(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
        raise ExtensionControlAuthorityError("invalid extension control catalog manifest")
    return dict(value)


__all__ = [
    "EXTENSION_CONTROL_AUTHORITY_FEATURE",
    "NativeExtensionControlAuthorityUnavailableError",
    "anchor_from_wire",
    "extension_control_authority",
    "layers_from_wire",
    "layers_to_wire",
    "manifest_from_wire",
    "manifest_sha256",
    "raise_fault",
    "view_to_wire",
]
