"""Shared validation, credential, and row helpers for extension-control authority."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownMemberType=false, reportUninitializedInstanceVariable=false

from __future__ import annotations

import base64
import hashlib
import sqlite3
import sys
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Final, cast

from .edge_events import build_policy_event
from .extension_control_events import extension_control_change_payload
from .native_extension_control import NativeExtensionControlError, compose_control_layers
from .native_extension_control_authority import anchor_from_wire
from .runtime.extension_control_authority import (
    AuthorityAnchor,
    AuthorityHealth,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
    layers_from_json,
)
from .runtime.extension_control_contract import (
    ControlLayerKind,
    ExtensionControlLayer,
)
from .store_base import (
    EncryptedFileSecretStore,
    MigratingFallbackSecretStore,
    SecretStore,
    SystemKeyringSecretStore,
)
from .store_extension_control_authority_schema import ensure_extension_control_authority_schema

_KEY_REF_SUFFIX = ":authentication-key"
_ANCHOR_REF_SUFFIX = ":anchor"
_MAX_TRANSITION_ID_LENGTH = 256
_MAX_CONTROLS_PER_LAYER = 512
_MAX_SERIALIZED_LAYERS_BYTES = 256 * 1024
_LAYER_INVALID_CODE: Final = "native_extension_control_layer_invalid"
# Composition is a pure function of the layers, so a layer set the native
# runtime accepted once stays accepted: validating a transition chain then asks
# the runtime once per distinct revision instead of once per read.
_COMPOSABLE_LAYER_SETS: Final = 512


@lru_cache(maxsize=_COMPOSABLE_LAYER_SETS)
def _require_composable(layers: tuple[ExtensionControlLayer, ...]) -> None:
    """Raise unless the native runtime composes ``layers`` without a resolver failure.

    A layer set the runtime rejects is a verdict on the stored layers. A
    runtime that cannot answer is an outage and never reads as one, so it
    surfaces as the same unavailability the authority lease reports. Only an
    accepted set is cached; a raised error is asked again.
    """

    try:
        composed = compose_control_layers(layers)
    except NativeExtensionControlError as error:
        if error.code == _LAYER_INVALID_CODE:
            raise ExtensionControlAuthorityError("invalid extension control layers") from error
        from .native_command_control_authority_io import NativeCommandControlAuthorityUnavailableError

        raise NativeCommandControlAuthorityUnavailableError(shared=True) from error
    if composed.failures:
        raise ExtensionControlAuthorityError("invalid extension control layers")


class _ExtensionControlAuthoritySupportMixin:
    def _invalidate_native_extension_control_policy(self, *, explicit_recovery: bool = False) -> None:
        """Close local native readiness before a durable control mutation.

        Mutation callers hold the authority lock. The asynchronous publisher
        must acquire that lock to verify committed controls, and its epoch
        check rejects any older publication already in flight. No ACK wait is
        performed under store locks; failed/rolled-back mutations are safely
        republished from their authenticated committed state.
        """

        from .native_command_control_authority_io import require_command_control_mutation_lease
        from .native_command_control_authority_store import begin_native_command_control_mutation
        from .native_policy_snapshot import notify_native_policy_mutation
        from .store import GuardStore

        require_command_control_mutation_lease(cast(Path, self.guard_home))
        notify_native_policy_mutation(cast(Path, self.guard_home))
        begin_native_command_control_mutation(cast(GuardStore, self), explicit_recovery=explicit_recovery)

    def _require_compatible_extension_control_schema(self) -> None:
        with self._connect() as connection:
            ensure_extension_control_authority_schema(connection)

    def read_persisted_extension_control_authority(self) -> ExtensionControlAuthorityView:
        """Read the authenticated authority using its persisted catalog identity."""

        from .native_command_control_authority_io import NativeCommandControlAuthorityUnavailableError

        catalog_digest = self._extension_control_last_catalog_digest
        try:
            with self._extension_control_authority_lock():
                self._require_compatible_extension_control_schema()
                with self._connect() as connection:
                    row = connection.execute(
                        "select catalog_digest from extension_control_authority_snapshot where singleton = 1"
                    ).fetchone()
                if row is not None:
                    catalog_digest = _row_str(row, "catalog_digest")
                return self._read_extension_control_authority_locked(catalog_digest)
        except NativeCommandControlAuthorityUnavailableError:
            # A busy lease is an outage, not a verdict on this authority.
            raise
        except ExtensionControlAuthorityError:
            return self._tampered_view(catalog_digest)
        except Exception:
            return self._degraded_view(catalog_digest)

    def _authority_key(self, *, required: bool) -> bytes | None:
        try:
            value = self._secret_store().get_secret(self._key_ref())
        except Exception as exc:
            raise ExtensionControlAuthorityError("extension control credential store unavailable") from exc
        if value is None:
            if required:
                raise ExtensionControlAuthorityError("extension control authentication key missing")
            return None
        try:
            key = base64.urlsafe_b64decode(value.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise ExtensionControlAuthorityError("invalid extension control authentication key") from exc
        if len(key) != 32:
            raise ExtensionControlAuthorityError("invalid extension control authentication key")
        return key

    def _read_anchor_json(self) -> str | None:
        """The anchor exactly as the credential store holds it, unverified."""

        return self._secret_store().get_secret(self._anchor_ref())

    def _read_anchor(self, *, key: bytes) -> AuthorityAnchor | None:
        value = self._read_anchor_json()
        if value is None:
            return None
        reply = self._extension_control_authority_op("anchor", key=key, anchor_json=value)
        return anchor_from_wire(reply.get("anchor"))

    def _write_and_verify_anchor(self, anchor: AuthorityAnchor, *, key: bytes) -> None:
        sealed = self._extension_control_authority_op(
            "seal_anchor",
            key=key,
            revision=anchor.revision,
            snapshot_digest=anchor.snapshot_digest,
            phase=anchor.phase.value,
        ).get("anchor_json")
        if not isinstance(sealed, str):
            raise ExtensionControlAuthorityError("invalid extension control anchor seal")
        encoded = sealed
        self._secret_store().set_secret(self._anchor_ref(), encoded)
        observed = self._secret_store().get_secret(self._anchor_ref())
        if observed != encoded:
            raise ExtensionControlAuthorityError("extension control anchor read-back mismatch")
        self._export_last_good_authority(anchor)

    def _secret_store(self) -> SecretStore:
        current = self._extension_control_authority_secret_store
        if current is None:
            fallback = EncryptedFileSecretStore(cast(Path, self.guard_home))
            system = SystemKeyringSecretStore(service_name="hol-guard.extension-control-authority")
            if sys.platform == "darwin" and not bool(getattr(self, "_allow_system_keyring", False)):
                # Passive macOS reads must never trigger Keychain UI. Explicit account
                # actions opt in to the migrating wrapper below.
                current = fallback
            else:
                # Persist every new authority secret in Guard's owner-only vault while
                # retaining the OS keyring as a best-effort legacy source. This makes
                # daemon, hook, and terminal processes converge on one prompt-free copy
                # instead of flapping when a session keyring is temporarily unavailable.
                current = MigratingFallbackSecretStore(system, fallback)
            self._extension_control_authority_secret_store = current
        return current

    def legacy_extension_control_authority_secret_migration_required(self) -> bool:
        """Return whether an authority row lacks its local vault material."""

        if sys.platform != "darwin":
            return False
        with self._connect() as connection:
            ensure_extension_control_authority_schema(connection)
            snapshot_exists = (
                connection.execute("select 1 from extension_control_authority_snapshot where singleton = 1").fetchone()
                is not None
            )
        if not snapshot_exists:
            return False
        store = EncryptedFileSecretStore(cast(Path, self.guard_home))
        return any(store.get_secret(secret_ref) is None for secret_ref in (self._key_ref(), self._anchor_ref()))

    def migrate_legacy_extension_control_authority_secrets(self, *, allow_interactive: bool = True) -> bool:
        """Mirror legacy Keychain authority material during an explicit action."""

        if not bool(getattr(self, "_allow_system_keyring", False)):
            return False
        if not self.legacy_extension_control_authority_secret_migration_required():
            return False
        store = self._secret_store()
        if not isinstance(store, MigratingFallbackSecretStore):
            return False
        migrated = False
        allow_interactive_read = allow_interactive
        for secret_ref in (self._key_ref(), self._anchor_ref()):
            if store.fallback.get_secret(secret_ref) is not None:
                continue
            value = store.get_secret(secret_ref) if allow_interactive_read else store.get_secret_no_ui(secret_ref)
            allow_interactive_read = False
            if value is None:
                return False
            migrated = True
        return migrated

    def _authority_ref_prefix(self) -> str:
        home = str(cast(Path, self.guard_home).resolve())
        return "extension-control:" + hashlib.sha256(home.encode("utf-8")).hexdigest()[:20]

    def _key_ref(self) -> str:
        return self._authority_ref_prefix() + _KEY_REF_SUFFIX

    def _anchor_ref(self) -> str:
        return self._authority_ref_prefix() + _ANCHOR_REF_SUFFIX

    @contextmanager
    def _extension_control_authority_lock(
        self, *, shared: bool = False, timeout_seconds: float | None = None
    ) -> Generator[None, None, None]:
        from .native_command_control_authority_io import (
            AUTHORITY_LOCK_TIMEOUT_SECONDS,
            hold_command_control_authority_lock,
        )

        budget = AUTHORITY_LOCK_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
        with hold_command_control_authority_lock(cast(Path, self.guard_home), shared=shared, timeout_seconds=budget):
            yield

    @staticmethod
    def _validate_layers(layers: tuple[ExtensionControlLayer, ...], catalog_digest: str) -> None:
        if len(layers) > len(ControlLayerKind):
            raise ExtensionControlAuthorityError("too many extension control layers")
        if any(len(layer.controls) > _MAX_CONTROLS_PER_LAYER for layer in layers):
            raise ExtensionControlAuthorityError("too many extension controls in layer")
        if any(layer.catalog_digest != catalog_digest for layer in layers):
            raise ExtensionControlAuthorityError("extension control catalog digest mismatch")
        _require_composable(tuple(layers))
        if len({layer.kind for layer in layers}) != len(layers):
            raise ExtensionControlAuthorityError("duplicate extension control layer")
        if any(layer.kind not in {ControlLayerKind.LOCAL_ADMIN, ControlLayerKind.SIGNED_CLOUD} for layer in layers):
            raise ExtensionControlAuthorityError("invalid extension control layer kind")

    @classmethod
    def _validate_commit_input(
        cls,
        layers: tuple[ExtensionControlLayer, ...],
        *,
        catalog_digest: str,
        actor_id: str,
        expected_revision: int,
        idempotency_key: str,
        nonce: str,
    ) -> None:
        cls._validate_layers(layers, catalog_digest)
        if type(expected_revision) is not int or expected_revision < 0:
            raise ExtensionControlAuthorityError("invalid expected authority revision")
        identities = (actor_id, idempotency_key, nonce)
        if any(not value.strip() or len(value) > _MAX_TRANSITION_ID_LENGTH for value in identities):
            raise ExtensionControlAuthorityError("invalid extension control transition identity")

    @staticmethod
    def _validate_serialized_layers(layers_json: str) -> None:
        if len(layers_json.encode("utf-8")) > _MAX_SERIALIZED_LAYERS_BYTES:
            raise ExtensionControlAuthorityError("extension control layers exceed storage limit")

    def _queue_extension_control_change_event(
        self,
        connection: sqlite3.Connection,
        *,
        revision: int,
        previous_revision: int,
        layers_json: str,
        occurred_at: str,
    ) -> None:
        layers = layers_from_json(layers_json)
        self._add_guard_event_v1(
            connection,
            build_policy_event(
                policy_key=f"extension-controls:{revision}",
                occurred_at=occurred_at,
                device_id=None,
                workspace_id=self._cloud_workspace_id_from_connection(connection),
                payload=extension_control_change_payload(
                    revision=revision,
                    previous_revision=previous_revision,
                    layers=layers,
                ),
            ),
        )

    def _degraded_view(self, catalog_digest: str) -> ExtensionControlAuthorityView:
        health = (
            AuthorityHealth.DEGRADED_ACKNOWLEDGED
            if self._extension_control_degraded_acknowledged
            else AuthorityHealth.DEGRADED_UNACKNOWLEDGED
        )
        return ExtensionControlAuthorityView(health, 0, catalog_digest, ())

    def extension_control_authority_unreadable_view(self, catalog_digest: str) -> ExtensionControlAuthorityView:
        """The view for a caller that could not read the authority and cannot fail.

        It carries no layers, so nothing taken from it widens what Guard
        allows. A caller that can wait retries instead: an unread authority is
        not a reading, and only the one caller that must still start uses this.

        It is marked unread so nothing downstream mistakes it for a verdict on
        the authority. Acknowledging degraded mode off a view like this would
        persist an outage the daemon never observed.
        """

        return replace(self._degraded_view(catalog_digest), unread=True)

    @staticmethod
    def _tampered_view(catalog_digest: str) -> ExtensionControlAuthorityView:
        return ExtensionControlAuthorityView(AuthorityHealth.TAMPERED, 0, catalog_digest, ())


def _row_str(row: sqlite3.Row, name: str) -> str:
    value = cast(object, row[name])
    if not isinstance(value, str):
        raise ExtensionControlAuthorityError("invalid extension control authority row")
    return value


def _row_optional_str(row: sqlite3.Row, name: str) -> str | None:
    value = cast(object, row[name])
    if value is not None and not isinstance(value, str):
        raise ExtensionControlAuthorityError("invalid extension control authority row")
    return value


def _row_int(row: sqlite3.Row, name: str) -> int:
    value = cast(object, row[name])
    if type(value) is not int:
        raise ExtensionControlAuthorityError("invalid extension control authority row")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _plan_int(plan: dict[str, object], name: str) -> int:
    value = plan.get(name)
    if type(value) is not int:
        raise ExtensionControlAuthorityError("invalid extension control authority plan")
    return value


def _plan_pack_digest(plan: dict[str, object]) -> str | None:
    """The command-pack record digest the resident found the transition binds."""

    value = plan.get("command_pack_record_digest")
    if value is not None and not isinstance(value, str):
        raise ExtensionControlAuthorityError("invalid extension control authority plan")
    return value


def _plan_map(plan: dict[str, object], name: str) -> dict[str, object]:
    value = plan.get(name)
    if not isinstance(value, dict):
        raise ExtensionControlAuthorityError("invalid extension control authority plan")
    return cast(dict[str, object], value)


def _plan_record(plan: dict[str, object], name: str) -> tuple[str, str, str]:
    """The ``json``, ``digest`` and ``mac`` of a record the resident sealed."""

    record = _plan_map(plan, name)
    sealed = (record.get("json"), record.get("digest"), record.get("mac"))
    if not all(isinstance(part, str) for part in sealed):
        raise ExtensionControlAuthorityError("invalid extension control authority plan")
    return cast(tuple[str, str, str], sealed)
