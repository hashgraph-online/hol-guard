"""Capture and authenticate complete scoped inputs outside native hooks."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

from .managed_controls_policy_bundle import MANAGED_CONTROLS_ACTIVE_STATE_KEY, MANAGED_CONTROLS_REVISION_STATE_KEY
from .native_policy_authority_blocked import (
    FrozenNativeBlockedCommandAuthority,
    command_controls_blocked,
    read_frozen_native_blocked_command_authority,
)
from .native_policy_authority_compile import compile_native_policy_authority, compile_native_policy_row
from .native_policy_authority_contract import NATIVE_AUTHORITY_MAX_ROWS, NativePolicyAuthorityDraft
from .native_policy_authority_managed import (
    FrozenNativeManagedAuthority,
    read_frozen_native_managed_authority,
    require_unenrolled_secrets,
)
from .native_policy_authority_sources import (
    FrozenNativePolicySources,
    signed_bundle_native_rows,
    signed_memory_native_rows,
)
from .native_policy_row_sort import native_policy_row_sort_key
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .policy_bundle_materialization import POLICY_BUNDLE_MATERIALIZATION_KEY
from .policy_bundle_trusted_keys import MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY
from .policy_integrity import (
    BUNDLE_OWNED_POLICY_SOURCES,
    MEMORY_POLICY_SOURCES,
    POLICY_INTEGRITY_VERSION,
    REMOTE_POLICY_SOURCES,
    verify_local_policy_row,
)
from .policy_rule_identity import PolicyRuleIdentity
from .review_memory_authority import REGISTRY_KEY, VERSION_KEY
from .review_verification_keyring import REVIEW_VERIFICATION_KEYRING_SYNC_KEY
from .runtime.time_support import parse_utc_timestamp

if TYPE_CHECKING:
    from .store import GuardStore

_STATE_KEYS = (
    "policy_bundle",
    "policy_bundle_keyring",
    "supply_chain_bundle_keyring",
    "policy_bundle_acceptance_checkpoint",
    POLICY_BUNDLE_MATERIALIZATION_KEY,
    MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY,
    REGISTRY_KEY,
    VERSION_KEY,
    REVIEW_VERIFICATION_KEYRING_SYNC_KEY,
    "policy_integrity",
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    MANAGED_CONTROLS_REVISION_STATE_KEY,
)
_MAX_CAPTURE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True, repr=False)
class NativeVerifiedPolicyInputs:
    """Compilation input; its digest is an invalidation key, not an ACK."""

    authority: NativePolicyAuthorityDraft
    _defaults_json: str | None
    _sources_json: str
    input_digest: str
    expires_at_ms: int | None
    rule_identities: tuple[tuple[int, PolicyRuleIdentity], ...]

    @property
    def defaults(self) -> dict[str, object] | None:
        return cast(dict[str, object], json.loads(self._defaults_json)) if self._defaults_json is not None else None

    @property
    def sources(self) -> list[dict[str, object]]:
        return cast(list[dict[str, object]], json.loads(self._sources_json))


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _database_identity(store: GuardStore) -> tuple[int, int]:
    metadata = store.path.stat()
    return metadata.st_dev, metadata.st_ino


def _credentials_for_capture(
    store: GuardStore,
    payload: object,
    *,
    needed: bool,
) -> dict[str, object] | None:
    if not needed:
        return None
    if not isinstance(payload, dict):
        raise NativePolicySnapshotError("native_policy_authority_memory_binding_unavailable")
    metadata = store._oauth_local_credentials_metadata(payload)
    secrets = store._load_oauth_secret_payload(payload, promote=False, allow_primary=False)
    if metadata is None or secrets is None:
        raise NativePolicySnapshotError("native_policy_authority_memory_binding_unavailable")
    credentials = store._build_oauth_local_credentials_result(metadata=metadata, secret_payload=secrets)
    if credentials is None:
        raise NativePolicySnapshotError("native_policy_authority_memory_binding_unavailable")
    # Memory authority requires the actual DPoP key pair. Refresh/access
    # tokens and display metadata are not needed for that verification.
    needed_fields = {
        "issuer",
        "client_id",
        "grant_id",
        "device_id",
        "machine_id",
        "runtime_id",
        "workspace_id",
        "dpop_private_key_pem",
        "dpop_public_jwk",
        "dpop_public_jwk_thumbprint",
    }
    return {key: value for key, value in credentials.items() if key in needed_fields}


def read_native_policy_authority_inputs(
    store: GuardStore, *, now: float, command_extensions: Mapping[str, object] | None = None
) -> NativeVerifiedPolicyInputs:
    """Authenticate one SQL snapshot after existing off-hook preparation.

    The first SQL read in the captured transaction is its linearization point.
    Unrelated commits do not invalidate that coherent view. This is not a claim
    of current resident application: the publication/reservation/ACK callers
    retain their separate source, epoch, metadata and data_version fences.
    """
    managed = (
        read_frozen_native_blocked_command_authority(store, command_extensions)
        if command_extensions is not None and command_controls_blocked(command_extensions)
        else read_frozen_native_managed_authority(store, command_extensions=command_extensions)
    )
    result = _capture_native_policy_authority_inputs(
        store, now=now, managed=managed, command_extensions=command_extensions
    )
    if managed is not None:
        managed.require_current_secrets(store)
    else:
        require_unenrolled_secrets(store)
    return result


def _capture_native_policy_authority_inputs(
    store: GuardStore,
    *,
    now: float,
    managed: FrozenNativeManagedAuthority | FrozenNativeBlockedCommandAuthority | None,
    command_extensions: Mapping[str, object] | None = None,
) -> NativeVerifiedPolicyInputs:
    """Reconstruct signed authority and verify local rows from one database view.

    The snapshot encoder must still negotiate support, authenticate the
    complete result, fence a fresh read after push, and verify the resident
    generation. No method here marks the runtime ready or reports application.
    """
    # Reuse setup only: integrity observations remain in autocommit before
    # BEGIN establishes the complete captured view. The independently opened
    # connection after this view still fences secret/control replacement.
    database_identity = _database_identity(store)
    with store.hold_oauth_credential_lock(), store._connect() as connection:
        key_material = store._policy_integrity_secret_material(create=False, connection=connection)
        control = store._load_policy_integrity_control_state(create=False, connection=connection)
        if key_material[0] is None or key_material[1] is None or store._policy_integrity_path_warnings():
            raise NativePolicySnapshotError("native_policy_authority_local_unavailable")
        generation = control.get("generation") if control is not None else None
        if control is not None and (type(generation) is not int or control.get("pending_generation") is not None):
            raise NativePolicySnapshotError("native_policy_authority_local_unavailable")
        now_text = datetime.fromtimestamp(now, timezone.utc).isoformat()
        state_keys = (*_STATE_KEYS, store._oauth_local_credentials_state_key)
        if _database_identity(store) != database_identity:
            raise NativePolicySnapshotError("native_policy_authority_changed_during_read")
        connection.execute("begin")
        connection.execute("pragma query_only=on")
        placeholders = ",".join("?" for _ in state_keys)
        state_rows = connection.execute(
            f"select state_key, payload_json from sync_state where state_key in ({placeholders})",
            state_keys,
        ).fetchall()
        captured_managed = (
            managed.recapture(store, connection)
            if isinstance(managed, FrozenNativeBlockedCommandAuthority)
            else read_frozen_native_managed_authority(
                store, connection=connection, command_extensions=command_extensions
            )
        )
        if managed is None and captured_managed is not None:
            raise NativePolicySnapshotError("native_policy_authority_managed_consumer_required")
        if captured_managed != managed:
            raise NativePolicySnapshotError("native_policy_authority_managed_unavailable")
        managed = captured_managed
        if sum(len(str(row["payload_json"]).encode("utf-8")) for row in state_rows) > _MAX_CAPTURE_BYTES:
            raise NativePolicySnapshotError("native_policy_authority_capture_limit")
        payloads: dict[str, dict[str, object] | list[object] | None] = {}
        for row in state_rows:
            value = json.loads(row["payload_json"])
            if value is not None and not isinstance(value, (dict, list)):
                raise NativePolicySnapshotError("native_policy_authority_state_invalid")
            payloads[str(row["state_key"])] = value
        controls = connection.execute(
            "select revision, catalog_digest, snapshot_digest "
            "from extension_control_authority_snapshot where singleton = 1"
        ).fetchone()
        if managed is not None:
            managed.validate_capture(payloads, dict(controls) if controls is not None else None)
        elif controls is not None or any(
            payloads.get(key) is not None
            for key in (MANAGED_CONTROLS_ACTIVE_STATE_KEY, MANAGED_CONTROLS_REVISION_STATE_KEY)
        ):
            raise NativePolicySnapshotError("native_policy_authority_managed_consumer_required")
        device_row = connection.execute(
            "select installation_id, device_label from guard_devices where device_key = 'local-device'"
        ).fetchone()
        if device_row is None:
            raise NativePolicySnapshotError("native_policy_authority_device_unavailable")
        device = {key: str(device_row[key]) for key in ("installation_id", "device_label")}
        remote_sources = tuple(sorted(REMOTE_POLICY_SOURCES))
        excluded = ",".join("?" for _ in remote_sources)
        retained_sources = {
            str(row["source"])
            for row in connection.execute(
                f"select distinct source from policy_decisions where source in ({excluded})",
                remote_sources,
            ).fetchall()
        }
        # An orphan cache cannot authorize anything, but its presence also
        # cannot turn missing signed authority into an empty permissive input.
        if payloads.get("policy_bundle") is None and (
            payloads.get(POLICY_BUNDLE_MATERIALIZATION_KEY) is not None
            or retained_sources & BUNDLE_OWNED_POLICY_SOURCES
        ):
            raise NativePolicySnapshotError("native_policy_authority_bundle_unavailable")
        if payloads.get(REGISTRY_KEY) is None and retained_sources & MEMORY_POLICY_SOURCES:
            raise NativePolicySnapshotError("native_policy_authority_memory_unavailable")
        local_rows = connection.execute(
            f"select * from policy_decisions where source not in ({excluded}) "
            "and not (source = 'approval-gate' and expires_at is not null) limit ?",
            (*remote_sources, NATIVE_AUTHORITY_MAX_ROWS + 1),
        ).fetchall()
        if len(local_rows) > NATIVE_AUTHORITY_MAX_ROWS:
            raise NativePolicySnapshotError("native_policy_authority_row_limit")
        oauth_payload = payloads.get(store._oauth_local_credentials_state_key)
        workspace = oauth_payload.get("workspace_id") if isinstance(oauth_payload, dict) else None
        workspace_id = workspace if isinstance(workspace, str) and workspace.strip() else None
        credentials = _credentials_for_capture(store, oauth_payload, needed=payloads.get(REGISTRY_KEY) is not None)
        state = FrozenNativePolicySources(
            payloads,
            device,
            workspace_id,
            credentials,
            key_material,
            store._normalized_policy_keys,
            store._guard_source,
        )
        bundle_rows, defaults, bundle_source = signed_bundle_native_rows(state, now=now, managed=managed)
        memory_rows, memory_source = signed_memory_native_rows(state, now=now_text)
        rows = bundle_rows + memory_rows
        for row in local_rows:
            value = dict(row)
            if (
                row["integrity_version"] != POLICY_INTEGRITY_VERSION
                or control is None
                or not control.get("cutover_complete")
                or type(generation) is not int
                or verify_local_policy_row(
                    value,
                    key=key_material[0],
                    key_id=key_material[1],
                    trusted_generation=generation,
                ).status
                != "valid"
            ):
                raise NativePolicySnapshotError("native_policy_authority_local_unavailable")
            rows.append(value)
        # Source-owned rows are reconstructed from authenticated content, so
        # their database IDs are not authority. IDs in this draft identify
        # rows only within one encoded snapshot; no approval can consume them.
        normalized = sorted(rows, key=native_policy_row_sort_key)
        active: list[dict[str, object]] = []
        rule_identities: list[tuple[int, PolicyRuleIdentity]] = []
        for index, row in enumerate(normalized, start=1):
            value = {**row, "decision_id": index}
            compiled = compile_native_policy_row(value)
            if compiled.expires_at_ms is None or compiled.expires_at_ms > int(now * 1_000):
                active.append(value)
                raw_identity = value.get("_policy_rule_identity")
                identity = (
                    PolicyRuleIdentity.from_selected_row(cast(Mapping[str, object], raw_identity))
                    if isinstance(raw_identity, Mapping)
                    else None
                )
                if identity is not None:
                    rule_identities.append((index, identity))
        authority = compile_native_policy_authority(active, managed=managed.authority if managed is not None else None)
        source_values = [
            source
            for source in (bundle_source, memory_source, managed.provenance() if managed is not None else None)
            if source is not None
        ]
        sources_json = _canonical(source_values)
        expiries = [row.expires_at_ms for row in authority.rows if row.expires_at_ms is not None]
        if bundle_source is not None and bundle_source.get("expires_at") is not None:
            expiry = parse_utc_timestamp(bundle_source["expires_at"])
            if expiry is None:
                raise NativePolicySnapshotError("native_policy_authority_expiry_invalid")
            expiries.append(int(expiry.timestamp() * 1_000))
        input_digest = hashlib.sha256(
            _canonical(
                {
                    "authority": authority.content_digest,
                    "sources": source_values,
                    "defaults": defaults,
                    "local_control": control,
                    "local_key_id": key_material[1],
                    "state": payloads,
                    "device": device,
                    "rule_identities": [
                        (index, identity.to_selected_row_dict()) for index, identity in rule_identities
                    ],
                }
            ).encode("utf-8")
        ).hexdigest()
    if _database_identity(store) != database_identity:
        raise NativePolicySnapshotError("native_policy_authority_changed_during_read")
    with store._connect() as integrity_connection:
        if store._policy_integrity_secret_material(create=False, connection=integrity_connection) != key_material or (
            store._load_policy_integrity_control_state(create=False, connection=integrity_connection) != control
        ):
            raise NativePolicySnapshotError("native_policy_authority_changed_during_read")
    if _database_identity(store) != database_identity:
        raise NativePolicySnapshotError("native_policy_authority_changed_during_read")
    return NativeVerifiedPolicyInputs(
        authority,
        _canonical(defaults) if defaults is not None else None,
        sources_json,
        input_digest,
        min(expiries) if expiries else None,
        tuple(rule_identities),
    )


__all__ = ["NativeVerifiedPolicyInputs", "read_native_policy_authority_inputs"]
