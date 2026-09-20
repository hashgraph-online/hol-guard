"""Read one consistent authenticated Cloud-defaults input off the hook path."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .native_cloud_policy_capabilities import require_native_v3_cloud_policy_support
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .policy_bundle_trusted_keys import MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY
from .synced_policy import cached_policy_bundle_validation, policy_defaults_from_validated_bundle

if TYPE_CHECKING:
    from .store import GuardStore

_STATE_KEYS = (
    "policy_bundle",
    "policy_bundle_keyring",
    "supply_chain_bundle_keyring",
    "policy_bundle_acceptance_checkpoint",
    MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY,
)


@dataclass(frozen=True)
class _CloudState:
    payloads: dict[str, dict[str, object] | list[object] | None]
    workspace_id: str | None

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None:
        return self.payloads.get(state_key)

    def get_cloud_workspace_id(self) -> str | None:
        return self.workspace_id


@dataclass(frozen=True)
class NativeCloudPolicyInputs:
    defaults: dict[str, object] | None = None
    # This identifies an input for invalidation, not a proof of application.
    source_identity: tuple[str | int, str, str | None, int | None] | None = None
    expires_at_ms: int | None = None


def read_native_cloud_policy_inputs(
    store: GuardStore, *, now: float, command_controls_bound: bool = False
) -> NativeCloudPolicyInputs:
    """Authenticate a transaction-consistent input without retaining credentials."""

    with store._connect() as connection:
        connection.execute("begin")
        placeholders = ",".join("?" for _ in _STATE_KEYS)
        rows = connection.execute(
            f"select state_key, payload_json from sync_state where state_key in ({placeholders})",
            _STATE_KEYS,
        ).fetchall()
        workspace_row = connection.execute(
            "select json_extract(payload_json, '$.workspace_id') as workspace_id "
            "from sync_state where state_key = 'oauth_local_credentials'"
        ).fetchone()
        raw_workspace = workspace_row["workspace_id"] if workspace_row is not None else None
        workspace = raw_workspace if isinstance(raw_workspace, str) and raw_workspace.strip() else None
        payloads: dict[str, dict[str, object] | list[object] | None] = {}
        for row in rows:
            payload = json.loads(row["payload_json"])
            if payload is not None and not isinstance(payload, (dict, list)):
                raise NativePolicySnapshotError("native_cloud_policy_state_invalid")
            payloads[str(row["state_key"])] = payload
    state = _CloudState(payloads, workspace)
    bundle, reason = cached_policy_bundle_validation(state, state.get_sync_payload("policy_bundle"), now=now)
    if bundle is None:
        if reason is not None:
            raise NativePolicySnapshotError("native_cloud_policy_authority_unavailable")
        return NativeCloudPolicyInputs()
    require_native_v3_cloud_policy_support(bundle, command_controls_bound=command_controls_bound)
    defaults = policy_defaults_from_validated_bundle(bundle)
    revision = bundle.get("bundleVersion")
    digest = bundle.get("bundleHash")
    if (
        defaults is None
        or not isinstance(digest, str)
        or not ((type(revision) is int and revision > 0) or (isinstance(revision, str) and revision.strip()))
    ):
        raise NativePolicySnapshotError("native_cloud_policy_defaults_invalid")
    expires = bundle.get("expiresAt")
    expires_at_ms = None
    if expires is not None:
        if not isinstance(expires, str):
            raise NativePolicySnapshotError("native_cloud_policy_expiry_invalid")
        parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        expires_at_ms = int(parsed.timestamp() * 1_000)
        if expires_at_ms <= int(now * 1_000):
            raise NativePolicySnapshotError("native_cloud_policy_authority_unavailable")
    return NativeCloudPolicyInputs(defaults, (revision, digest, workspace, expires_at_ms), expires_at_ms)


__all__ = ["NativeCloudPolicyInputs", "read_native_cloud_policy_inputs"]
