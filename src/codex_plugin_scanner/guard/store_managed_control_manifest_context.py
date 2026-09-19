"""Pin managed allows to authenticated source fingerprints across catalog refreshes.

The cloud activation and its acknowledgement remain immutable. This separate
local record binds only its configured targets to that exact activation digest.
All callers hold the extension authority lock; every write closes the native
marker before committing any context or catalog migration intent.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from .managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    managed_controls_layers_from_activation_state,
)
from .runtime.extension_control_authority import (
    ExtensionControlAuthorityError,
    authenticated_record,
    verify_authenticated_record,
)
from .runtime.extension_control_contract import ExtensionControlLayer
from .runtime.extension_control_limits import MAX_CATALOG_PAYLOAD_BYTES, MAX_CONTROLS_PER_LAYER, MAX_INPUT_TEXT_LENGTH

if TYPE_CHECKING:
    from .store import GuardStore

MANAGED_CONTROLS_MANIFEST_CONTEXT_STATE_KEY = "managed_controls_manifest_context"
MANAGED_CONTROLS_SOURCE_MANIFEST_FIELD = "sourceTargetManifest"
_PURPOSE = "managed-controls.manifest-context"
_SCHEMA = "guard.managed-controls-manifest-context.v1"
# At most 512 target names of 256 characters, with their SHA-256 fingerprints,
# plus authenticated framing. The complete encoded record must fit this bound.
_MAX_CONTEXT_BYTES = 512 * 1024
_BODY_FIELDS = {"schema", "activation_digest", "catalog_digest", "target_manifest", "migration"}
_MAX_REVISION = (1 << 64) - 1


def _invalid() -> ExtensionControlAuthorityError:
    return ExtensionControlAuthorityError("invalid managed controls manifest context")


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise _invalid()
        result[name] = value
    return result


def _read_state(store: GuardStore, name: str, maximum_bytes: int) -> object:
    # Bound allocation before copying an untrusted SQL payload into Python.
    with store._connect() as connection:
        row = connection.execute(
            "select substr(cast(payload_json as blob), 1, ?) from sync_state where state_key = ?",
            (maximum_bytes + 1, name),
        ).fetchone()
    if row is None:
        return None
    encoded = row[0]
    if not isinstance(encoded, bytes) or not encoded or len(encoded) > maximum_bytes:
        raise _invalid()
    try:
        return json.loads(encoded, object_pairs_hook=_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise _invalid() from error


def _targets(layers: tuple[ExtensionControlLayer, ...]) -> set[str]:
    controls = tuple(control for layer in layers for control in layer.controls)
    if len(controls) > MAX_CONTROLS_PER_LAYER or any(
        len(control.target.target_id) > MAX_INPUT_TEXT_LENGTH for control in controls
    ):
        raise _invalid()
    return {f"{control.target.kind.value}:{control.target.target_id}" for control in controls}


def bounded_source_manifest(
    layers: tuple[ExtensionControlLayer, ...], source_manifest: Mapping[str, str]
) -> dict[str, str]:
    """Capture only configured targets from the trusted activation-time registry."""

    targets = _targets(layers)
    manifest = {name: value for name, value in source_manifest.items() if name in targets}
    if any(not _digest(value) for value in manifest.values()):
        raise _invalid()
    return manifest


def activation_source_manifest(
    active: Mapping[str, object], layers: tuple[ExtensionControlLayer, ...]
) -> dict[str, str] | None:
    """Validate the optional source after authenticating the activation itself."""

    if MANAGED_CONTROLS_SOURCE_MANIFEST_FIELD not in active:
        return None
    source = active[MANAGED_CONTROLS_SOURCE_MANIFEST_FIELD]
    if not isinstance(source, Mapping) or len(source) > MAX_CONTROLS_PER_LAYER:
        raise _invalid()
    manifest = bounded_source_manifest(layers, cast(Mapping[str, str], source))
    if manifest != source:
        raise _invalid()
    return manifest


def _read_context(store: GuardStore, key: bytes) -> dict[str, object] | None:
    wrapper = _read_state(store, MANAGED_CONTROLS_MANIFEST_CONTEXT_STATE_KEY, _MAX_CONTEXT_BYTES)
    if wrapper is None:
        return None
    if not isinstance(wrapper, dict) or set(wrapper) != {"record", "digest", "mac"}:
        raise _invalid()
    if not isinstance(wrapper["record"], str) or not _digest(wrapper["digest"]) or not _digest(wrapper["mac"]):
        raise _invalid()
    authenticated = verify_authenticated_record(
        wrapper["record"],
        expected_digest=wrapper["digest"],
        expected_mac=wrapper["mac"],
        key=key,
        purpose=_PURPOSE,
    )
    if set(authenticated) != _BODY_FIELDS | {"authority_schema_version", "purpose"}:
        raise _invalid()
    body = {name: authenticated[name] for name in _BODY_FIELDS}
    manifest, migration = body["target_manifest"], body["migration"]
    if body["schema"] != _SCHEMA or not _digest(body["activation_digest"]) or not _digest(body["catalog_digest"]):
        raise _invalid()
    if (
        not isinstance(manifest, dict)
        or len(manifest) > MAX_CONTROLS_PER_LAYER
        or any(
            not isinstance(name, str) or len(name) > MAX_INPUT_TEXT_LENGTH + 11 or not _digest(value)
            for name, value in manifest.items()
        )
    ):
        raise _invalid()
    if migration is not None and (
        not isinstance(migration, dict)
        or set(migration) != {"catalog_digest", "target_digest", "previous_revision"}
        or not _digest(migration["catalog_digest"])
        or not _digest(migration["target_digest"])
        or type(migration["previous_revision"]) is not int
        or not 0 <= migration["previous_revision"] < _MAX_REVISION
    ):
        raise _invalid()
    return body


def _write_context(store: GuardStore, body: dict[str, object], key: bytes) -> None:
    from .store_extension_control_authority_support import _now

    record, digest, mac = authenticated_record(body, key=key, purpose=_PURPOSE)
    encoded = json.dumps({"record": record, "digest": digest, "mac": mac}, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > _MAX_CONTEXT_BYTES:
        raise _invalid()
    store._invalidate_native_extension_control_policy()
    with store._connect() as connection:
        connection.execute(
            """insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)
               on conflict(state_key) do update set
                 payload_json = excluded.payload_json, updated_at = excluded.updated_at""",
            (MANAGED_CONTROLS_MANIFEST_CONTEXT_STATE_KEY, encoded, _now()),
        )


@dataclass(frozen=True)
class ManagedManifestContext:
    layers: tuple[ExtensionControlLayer, ...]
    body: dict[str, object]

    @property
    def manifest(self) -> Mapping[str, str]:
        return cast(Mapping[str, str], self.body["target_manifest"])


def pin_managed_manifest_context(
    store: GuardStore,
    *,
    active: Mapping[str, object],
    layers: tuple[ExtensionControlLayer, ...],
    key: bytes,
) -> ManagedManifestContext:
    """Pin after the caller has authenticated the complete active payload."""

    authentication = active.get("authentication")
    if not isinstance(authentication, Mapping) or not _digest(authentication.get("digest")):
        raise _invalid()
    catalog_digest = active.get("catalogDigest")
    if not _digest(catalog_digest):
        raise _invalid()
    targets = _targets(layers)
    source_manifest = activation_source_manifest(active, layers)
    body = _read_context(store, key)
    if body is not None and body["activation_digest"] == authentication["digest"]:
        if (
            body["catalog_digest"] != catalog_digest
            or not set(cast(dict[str, str], body["target_manifest"])) <= targets
        ):
            raise _invalid()
        if source_manifest is not None and body["target_manifest"] != source_manifest:
            raise _invalid()
        return ManagedManifestContext(layers, body)
    # Legacy activations have no immutable source binding. A missing context
    # cannot safely adopt the mutable current manifest: deletion after a catalog
    # refresh would revive an old allow. Preserve restrictions until reactivation.
    manifest = source_manifest or {}
    body = {
        "schema": _SCHEMA,
        "activation_digest": authentication["digest"],
        "catalog_digest": catalog_digest,
        "target_manifest": manifest,
        "migration": None,
    }
    _write_context(store, body, key)
    return ManagedManifestContext(layers, body)


def active_managed_manifest_context(
    store: GuardStore,
    *,
    key: bytes,
) -> ManagedManifestContext | None:
    """Capture and pin managed source context before overwriting a manifest."""

    active = _read_state(store, MANAGED_CONTROLS_ACTIVE_STATE_KEY, MAX_CATALOG_PAYLOAD_BYTES)
    if active is None or active == {}:
        return None
    if not isinstance(active, dict) or not isinstance(active.get("catalogDigest"), str):
        raise _invalid()
    active_catalog = active["catalogDigest"]
    layers, _revision = managed_controls_layers_from_activation_state(
        active, catalog_digest=active_catalog, authority_key=key
    )
    if any(layer.catalog_digest != active_catalog for layer in layers):
        raise _invalid()
    return pin_managed_manifest_context(store, active=active, layers=layers, key=key)


def managed_manifest_revision_required(
    store: GuardStore,
    context: ManagedManifestContext,
    *,
    catalog_digest: str,
    current_manifest: Mapping[str, str],
    revision: int,
    key: bytes,
) -> bool:
    """Record intent before advancing a revision; retries reuse that advance.

    A protected local revision past the authenticated intent already accounts
    for this target projection, including a crash before manifest replacement.
    An explicit authority reset can restart the revision and needs a new intent.
    """

    target = {name: current_manifest.get(name) for name in sorted(_targets(context.layers))}
    digest = hashlib.sha256(json.dumps(target, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    migration = context.body["migration"]
    same_target = (
        isinstance(migration, Mapping)
        and migration["catalog_digest"] == catalog_digest
        and migration["target_digest"] == digest
    )
    if same_target and revision > cast(int, cast(Mapping[str, object], migration)["previous_revision"]):
        return False
    intent = {"catalog_digest": catalog_digest, "target_digest": digest, "previous_revision": revision}
    if not same_target or migration != intent:
        _write_context(store, {**context.body, "migration": intent}, key)
    return True
