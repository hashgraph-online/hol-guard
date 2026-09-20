"""Authenticate the local recency assigned to signed bundle rows."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from collections.abc import Mapping, Sequence
from typing import Protocol

from .native_policy_authority_state_keys import POLICY_BUNDLE_MATERIALIZATION_KEY as POLICY_BUNDLE_MATERIALIZATION_KEY
from .store_base import _canonical_utc_timestamp

_SCHEMA = "guard-policy-row-materialization.v1"
_DOMAIN = b"hol-guard.policy-row-materialization.v1\0"
_FIELDS = frozenset(
    {"schema", "bundleHash", "bundleVersion", "workspaceId", "deviceId", "materializedAt", "keyId", "mac"}
)


class PolicyBundleMaterializationError(ValueError):
    def __init__(self) -> None:
        super().__init__("policy_bundle_materialization_unavailable")


class PolicyMaterializationStore(Protocol):
    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]: ...


def _identity(bundle: Mapping[str, object], device_id: str, key_id: str, timestamp: str) -> dict[str, object]:
    revision = bundle.get("bundleVersion")
    if not (
        (type(revision) is int and revision > 0)
        or (isinstance(revision, str) and revision.strip() == revision and revision)
    ):
        raise PolicyBundleMaterializationError
    for value in (bundle.get("bundleHash"), bundle.get("workspaceId"), device_id, key_id):
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
            raise PolicyBundleMaterializationError
    if _canonical_utc_timestamp(timestamp) != timestamp:
        raise PolicyBundleMaterializationError
    return {
        "schema": _SCHEMA,
        "bundleHash": bundle["bundleHash"],
        "bundleVersion": revision,
        "workspaceId": bundle["workspaceId"],
        "deviceId": device_id,
        "materializedAt": timestamp,
        "keyId": key_id,
    }


def _mac(payload: Mapping[str, object], key: bytes) -> str:
    if len(key) != 32:
        raise PolicyBundleMaterializationError
    encoded = json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hmac.new(key, _DOMAIN + encoded, hashlib.sha256).hexdigest()


def verified_policy_materialization_time(
    value: object, *, bundle: Mapping[str, object], device_id: str, key: bytes | None, key_id: str | None
) -> str | None:
    """Return recency only when its exact source/device binding is authenticated."""

    if not isinstance(value, dict) or set(value) != _FIELDS or key is None or key_id is None:
        return None
    timestamp, actual_mac = value.get("materializedAt"), value.get("mac")
    if not isinstance(timestamp, str) or not isinstance(actual_mac, str):
        return None
    try:
        expected = _identity(bundle, device_id, key_id, timestamp)
        if any(type(value[name]) is not type(item) or value[name] != item for name, item in expected.items()):
            return None
        return timestamp if hmac.compare_digest(actual_mac, _mac(expected, key)) else None
    except (TypeError, ValueError, UnicodeEncodeError, OverflowError):
        return None


def bind_policy_bundle_materialization(
    store: PolicyMaterializationStore,
    connection: sqlite3.Connection,
    *,
    bundle: Mapping[str, object],
    rows: Sequence[tuple[object, ...]],
    now: str,
    require_source_binding: bool = False,
) -> tuple[list[tuple[object, ...]], dict[str, object] | None]:
    """Prepare a binding in the same transaction as the persisted rule set.

    A repeated identical source retains its authenticated recency. An invalid
    existing binding is never silently re-signed from mutable stored values.
    Empty rule sets retain legacy behavior unless the caller explicitly needs
    an authenticated source binding. This does not validate signed admission
    or establish native application; those remain separate caller boundaries.
    """

    if type(require_source_binding) is not bool:
        raise PolicyBundleMaterializationError
    if not rows and not require_source_binding:
        return list(rows), None
    key, key_id = store._policy_integrity_secret_material(create=True)
    device = connection.execute(
        "select installation_id from guard_devices where device_key = 'local-device'"
    ).fetchone()
    if key is None or key_id is None or device is None:
        raise PolicyBundleMaterializationError
    device_id = str(device["installation_id"])
    existing_row = connection.execute(
        "select payload_json from sync_state where state_key = ?", (POLICY_BUNDLE_MATERIALIZATION_KEY,)
    ).fetchone()
    existing = None
    if existing_row is not None:
        try:
            existing = json.loads(str(existing_row["payload_json"]))
        except (TypeError, ValueError) as error:
            raise PolicyBundleMaterializationError from error
        if not isinstance(existing, dict):
            raise PolicyBundleMaterializationError
    timestamp = _canonical_utc_timestamp(now)
    if existing is not None:
        previous = verified_policy_materialization_time(
            existing, bundle=bundle, device_id=device_id, key=key, key_id=key_id
        )
        if previous is not None:
            timestamp = previous
        elif (
            verified_policy_materialization_time(existing, bundle=existing, device_id=device_id, key=key, key_id=key_id)
            is None
        ):
            raise PolicyBundleMaterializationError
    payload = _identity(bundle, device_id, key_id, timestamp)
    payload["mac"] = _mac(payload, key)
    return [(*row[:12], timestamp, *row[13:]) for row in rows], payload


__all__ = [
    "POLICY_BUNDLE_MATERIALIZATION_KEY",
    "PolicyBundleMaterializationError",
    "PolicyMaterializationStore",
    "bind_policy_bundle_materialization",
    "verified_policy_materialization_time",
]
