"""Capture a verified command refusal without treating broken controls as policy."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .managed_controls_policy_bundle import MANAGED_CONTROLS_ACTIVE_STATE_KEY, MANAGED_CONTROLS_REVISION_STATE_KEY
from .native_command_control_binding import validate_native_command_control_binding
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from .runtime.extension_control_authority import ExtensionControlAuthorityError
from .runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot

if TYPE_CHECKING:
    from .store import GuardStore

_BLOCKED_HEALTH = frozenset({"tampered", "recovery-required", "degraded-unacknowledged", "degraded-acknowledged"})


def command_controls_blocked(binding: Mapping[str, object] | None) -> bool:
    health = binding.get("health") if binding is not None else None
    return isinstance(health, str) and health in _BLOCKED_HEALTH


@dataclass(frozen=True, slots=True, repr=False)
class FrozenNativeBlockedCommandAuthority:
    """The authenticated native binding enforces an unconditional command block.

    No managed policy is reconstructed from the failed view. Other authority
    still passes through the complete source reader, and a retained managed
    activation remains unavailable until it can be authenticated again.
    """

    snapshot: ExtensionControlRuntimeSnapshot
    _key: bytes | None
    _anchor: str | None

    @property
    def authority(self) -> None:
        return None

    def require_current_secrets(self, store: GuardStore) -> None:
        try:
            if (
                store._authority_key(required=False) != self._key
                or store._secret_store().get_secret(store._anchor_ref()) != self._anchor
            ):
                raise NativePolicySnapshotError("native_policy_authority_managed_unavailable")
        except ExtensionControlAuthorityError as error:
            raise NativePolicySnapshotError("native_policy_authority_managed_unavailable") from error

    def validate_capture(self, payloads: Mapping[str, object], local_row: Mapping[str, object] | None) -> None:
        # A block is not evidence that the separately signed managed source
        # was validated or applied. Never turn its missing activation into an
        # empty control layer, including when only its revision floor remains.
        if any(
            payloads.get(key) is not None
            for key in (MANAGED_CONTROLS_ACTIVE_STATE_KEY, MANAGED_CONTROLS_REVISION_STATE_KEY)
        ):
            raise NativePolicySnapshotError("native_policy_authority_managed_unavailable")

    def require_signed_bundle(self, bundle: Mapping[str, object], payloads: Mapping[str, object]) -> None:
        raise NativePolicySnapshotError("native_policy_authority_bundle_semantics_unsupported")

    def provenance(self) -> dict[str, object]:
        return {
            "kind": "blocked-command-controls",
            "health": self.snapshot.health.value,
            "revision": self.snapshot.revision,
            "managed_revision": self.snapshot.managed_revision,
            "catalog_digest": self.snapshot.catalog_digest,
            "effective_digest": self.snapshot.effective_digest,
        }

    def recapture(self, store: GuardStore, connection: sqlite3.Connection) -> FrozenNativeBlockedCommandAuthority:
        current = _read_blocked_view(store, connection=connection)
        if current != self:
            raise NativePolicySnapshotError("native_policy_authority_managed_unavailable")
        return current


def _read_blocked_view(
    store: GuardStore, *, connection: sqlite3.Connection | None = None
) -> FrozenNativeBlockedCommandAuthority:
    try:
        key = store._authority_key(required=False)
        anchor = store._secret_store().get_secret(store._anchor_ref())
        view = (
            store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
            if connection is None
            else store._read_captured_extension_control_authority(connection, BUILT_IN_COMMAND_EXTENSION_REGISTRY)
        )
        if view.health.value not in _BLOCKED_HEALTH:
            raise NativePolicySnapshotError("native_policy_authority_managed_unavailable")
        captured = FrozenNativeBlockedCommandAuthority(
            ExtensionControlRuntimeSnapshot.from_authority_view(view), key, anchor
        )
        captured.require_current_secrets(store)
        return captured
    except ExtensionControlAuthorityError as error:
        raise NativePolicySnapshotError("native_policy_authority_managed_unavailable") from error


def read_frozen_native_blocked_command_authority(
    store: GuardStore, binding: Mapping[str, object]
) -> FrozenNativeBlockedCommandAuthority:
    validate_native_command_control_binding(binding)
    if not command_controls_blocked(binding) or "authority" not in binding:
        raise NativePolicySnapshotError("native_policy_authority_managed_unavailable")
    captured = _read_blocked_view(store)
    source = captured.provenance()
    if any(
        binding.get(field) != source[field]
        for field in ("health", "revision", "managed_revision", "catalog_digest", "effective_digest")
    ):
        raise NativePolicySnapshotError("native_command_control_binding_changed")
    return captured
