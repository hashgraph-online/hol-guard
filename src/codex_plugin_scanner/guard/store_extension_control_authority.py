"""Crash-safe, externally anchored extension-control authority persistence."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import base64
import logging
import secrets
import sqlite3
from typing import cast

from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.extension_control_authority import (
    AuthorityAnchor,
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityView,
)
from .store_base import SecretStore
from .store_extension_control_authority_catalog import ExtensionControlAuthorityCatalogMixin
from .store_extension_control_authority_commit import ExtensionControlAuthorityCommitMixin
from .store_extension_control_authority_reads import ExtensionControlAuthorityReadsMixin
from .store_extension_control_authority_schema import ensure_extension_control_authority_schema
from .store_extension_control_authority_support import (
    _now,
    _row_int,
    _row_str,
)
from .store_extension_control_authority_transitions import _ExtensionControlAuthorityTransitionMixin
from .store_extension_control_last_good import ExtensionControlLastGoodMixin, _count_controls

_LOGGER = logging.getLogger(__name__)


class StoreExtensionControlAuthorityMixin(
    ExtensionControlLastGoodMixin,
    ExtensionControlAuthorityReadsMixin,
    ExtensionControlAuthorityCommitMixin,
    ExtensionControlAuthorityCatalogMixin,
    _ExtensionControlAuthorityTransitionMixin,
):
    """GuardStore mixin for the local extension-control authority."""

    _extension_control_authority_secret_store: SecretStore | None = None
    _extension_control_degraded_acknowledged: bool = False
    _extension_control_last_catalog_digest: str = "0" * 64

    def recover_extension_control_authority(
        self,
        *,
        catalog_digest: str,
        migration_registry: CommandSafetyExtensionRegistry | None = None,
    ) -> ExtensionControlAuthorityView:
        from .catalog_delivery.activation_journal import UnverifiablePackTransitionError

        with self._extension_control_authority_lock():
            self._invalidate_native_extension_control_policy(explicit_recovery=True)
            key = self._authority_key(required=False)
            if key is None:
                return self._reset_extension_control_authority(
                    catalog_digest, key=None, reason="authentication-key-missing"
                )
            anchor = self._read_anchor(key=key)
            if anchor is not None:
                restored_view = self._restore_missing_snapshot_before_recovery(
                    anchor, key=key, catalog_digest=catalog_digest, migration_registry=migration_registry
                )
                if restored_view is not None:
                    return restored_view
            with self._connect() as connection:
                ensure_extension_control_authority_schema(connection)
                snapshot = connection.execute(
                    "select revision, snapshot_digest from extension_control_authority_snapshot where singleton = 1"
                ).fetchone()
                if snapshot is None or anchor is None:
                    return self._reset_extension_control_authority(
                        catalog_digest,
                        key=key,
                        reason="snapshot-or-anchor-missing",
                    )
                current_revision = _row_int(snapshot, "revision")
                current_digest = _row_str(snapshot, "snapshot_digest")
                pending = connection.execute(
                    """
                    select * from extension_control_authority_transition
                    where (revision = ? and phase != ?) or revision = ?
                    order by revision
                    limit 1
                    """,
                    (
                        current_revision,
                        AuthorityPhase.COMMITTED.value,
                        current_revision + 1,
                    ),
                ).fetchone()
                if pending is not None:
                    try:
                        resumed = self._resume_transition(connection, _row_int(pending, "revision"), key=key)
                    except UnverifiablePackTransitionError:
                        # Only damaged pending authentication permits the existing
                        # explicit recovery reset; environmental failures propagate.
                        connection.rollback()
                        return self._reset_extension_control_authority(
                            catalog_digest, key=key, reason="pending-transition-unverifiable"
                        )
                    if resumed is not None and resumed.health is AuthorityHealth.PROTECTED:
                        return resumed
                    connection.commit()
                if anchor.revision == current_revision and anchor.snapshot_digest == current_digest:
                    if anchor.phase is not AuthorityPhase.COMMITTED:
                        self._write_and_verify_anchor(
                            AuthorityAnchor(
                                current_revision,
                                current_digest,
                                AuthorityPhase.COMMITTED,
                            ),
                            key=key,
                        )
                    if current_revision > 0:
                        committed = connection.execute(
                            "select 1 from extension_control_authority_transition where revision = ? and phase = ?",
                            (current_revision, AuthorityPhase.COMMITTED.value),
                        ).fetchone()
                        if committed is None:
                            return self._reset_extension_control_authority(
                                catalog_digest,
                                key=key,
                                reason="committed-transition-missing",
                            )
                    # Catalog migration below uses its own transaction. Release
                    # the writer lock before re-reading the authority;
                    # the authority lock still excludes competing mutations.
                    connection.commit()
                    recovered = self._read_extension_control_authority_locked(
                        catalog_digest,
                        migration_registry=migration_registry,
                    )
                    if recovered.health is AuthorityHealth.PROTECTED:
                        if current_revision > 0:
                            self._extension_control_authority_op(
                                "queue_change",
                                key=key,
                                revision=current_revision,
                                now=_now(),
                                event_queue_limit=self._guard_event_queue_limit,
                            )
                        return recovered
            return self._reset_extension_control_authority(
                catalog_digest,
                key=key,
                reason="authenticated-recovery-unverifiable",
            )

    def _restore_missing_snapshot_before_recovery(
        self,
        anchor: AuthorityAnchor,
        *,
        key: bytes,
        catalog_digest: str,
        migration_registry: CommandSafetyExtensionRegistry | None,
    ) -> ExtensionControlAuthorityView | None:
        with self._connect() as connection:
            ensure_extension_control_authority_schema(connection)
            snapshot_missing = (
                connection.execute("select 1 from extension_control_authority_snapshot where singleton = 1").fetchone()
                is None
            )
        if not snapshot_missing:
            return None
        try:
            restored = self._restore_last_good_authority(key=key)
        except (sqlite3.Error, RuntimeError):
            # Leftover rows can conflict with the restore, and the resident can
            # refuse or fail to read them; fall back to the explicit reset,
            # which archives them. A resident that does not answer is not a
            # verdict, so that outage propagates instead of resetting.
            return None
        if not restored:
            return None
        view = self._read_extension_control_authority_locked(catalog_digest, migration_registry=migration_registry)
        return view if view.health is AuthorityHealth.PROTECTED else None

    def _note_controls_lost_by_reset(self, reason: str) -> None:
        """Preserve and announce any control state that a reset cannot carry over."""

        warnings: list[str] = []
        with self._connect() as connection:
            ensure_extension_control_authority_schema(connection)
            row = connection.execute(
                "select layers_json from extension_control_authority_snapshot where singleton = 1"
            ).fetchone()
        lost = _count_controls(str(row["layers_json"])) if row is not None else 0
        if lost:
            warnings.append(
                f"Authority reset ({reason}) dropped {lost} extension control(s); "
                "the previous snapshot is kept in the local recovery archive."
            )
        if self._last_good_path().is_file():
            if self._quarantine_unusable_last_good_export():
                warnings.append(
                    "A saved copy of the previous extension controls could not be verified against the current "
                    "authority and was set aside as extension-control-last-good.unapplied-*.json in the Guard home."
                )
            else:
                warnings.append(
                    "A saved copy of the previous extension controls could not be verified against the current "
                    "authority and could not be set aside; it remains as extension-control-last-good.json."
                )
        self.extension_control_recovery_warnings = tuple(warnings)
        for warning in warnings:
            _LOGGER.warning(warning)

    def _reset_extension_control_authority(
        self,
        catalog_digest: str,
        *,
        key: bytes | None,
        reason: str,
    ) -> ExtensionControlAuthorityView:
        # Never import rows with an unverifiable chain; re-establish an empty protected authority.
        from .native_command_control_authority_store import begin_native_command_control_recovery
        from .store import GuardStore

        self._note_controls_lost_by_reset(reason)
        recovered_key = key if key is not None else secrets.token_bytes(32)
        begin_native_command_control_recovery(cast(GuardStore, self), new_authority_key=recovered_key)
        if key is None:
            self._secret_store().set_secret(self._key_ref(), base64.urlsafe_b64encode(recovered_key).decode())
        with self._connect() as connection:
            ensure_extension_control_authority_schema(connection)
        # The resident archives every row whose chain cannot be verified and
        # empties the authority in one transaction. The catalog manifests the
        # lost key authenticated cannot be reused under the new one; managed
        # activation remains independently authenticated and fail-closed.
        self._extension_control_authority_op(
            "reset",
            key=recovered_key,
            catalog_digest=catalog_digest,
            now=_now(),
            reset={"reason": reason, "drop_manifest": key is None},
        )
        return self._bootstrap_extension_control_authority(catalog_digest, key=recovered_key)

    def acknowledge_extension_control_degraded_mode(self) -> ExtensionControlAuthorityView:
        with self._extension_control_authority_lock():
            self._invalidate_native_extension_control_policy()
            self._extension_control_degraded_acknowledged = True
            return self._degraded_view(self._extension_control_last_catalog_digest)
