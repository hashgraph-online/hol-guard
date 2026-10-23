"""Applying the resident's verdicts on extension-control transitions.

The resident decides whether a prepared transition is resumed, committed or
abandoned; this module performs the writes it cannot, under the caller's lease.
"""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import sqlite3
from typing import cast

from .native_extension_control_authority import view_to_wire
from .runtime.extension_control_authority import (
    AuthorityAnchor,
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
)
from .store_extension_control_authority_support import (
    _ExtensionControlAuthoritySupportMixin,
    _now,
    _plan_pack_digest,
    _row_int,
    _row_str,
)

_RESUMED_OUTCOMES = frozenset({"commit_pending", "mark_committed", "finish"})


def _plan(reply: dict[str, object]) -> dict[str, object]:
    plan = reply.get("plan")
    if not isinstance(plan, dict) or not isinstance(plan.get("outcome"), str):
        raise ExtensionControlAuthorityError("invalid extension control authority plan")
    return cast(dict[str, object], plan)


class _ExtensionControlAuthorityTransitionMixin(_ExtensionControlAuthoritySupportMixin):
    def _authority_plan(self, op: str, *, key: bytes, **fields: object) -> dict[str, object]:
        """The resident's decision for a write this caller applies under its lease."""

        reply = self._extension_control_authority_op(op, key=key, anchor_json=self._read_anchor_json(), **fields)
        return _plan(reply)

    def _apply_resumed_transition(
        self,
        connection: sqlite3.Connection,
        outcome: str,
        revision: int,
        *,
        current: ExtensionControlAuthorityView | None,
        key: bytes,
        pack_record_digest: str | None = None,
    ) -> ExtensionControlAuthorityView | None:
        """Apply the resident's verdict on a prepared transition.

        ``abandon`` removes the prepared row and returns None; every other
        outcome finishes the transition and returns the view it left.
        ``pack_record_digest`` is the pack record the resident found the
        authenticated transition binds.
        """

        self._invalidate_native_extension_control_policy()
        row = connection.execute(
            "select * from extension_control_authority_transition where revision = ?", (revision,)
        ).fetchone()
        if row is None:
            raise ExtensionControlAuthorityError("idempotent transition state mismatch")
        if outcome == "abandon":
            _ = connection.execute("delete from extension_control_authority_transition where revision = ?", (revision,))
            from .catalog_delivery.activation_journal import abandon

            abandon(connection, revision)
            return None

        def queue_event() -> None:
            self._queue_extension_control_change_event(
                connection,
                revision=revision,
                previous_revision=_row_int(row, "previous_revision"),
                layers_json=_row_str(row, "layers_json"),
                occurred_at=_row_str(row, "created_at"),
            )

        if outcome == "current" and current is not None:
            queue_event()
            connection.commit()
            return current
        if outcome not in _RESUMED_OUTCOMES:
            raise ExtensionControlAuthorityError("invalid extension control authority plan")
        if outcome == "commit_pending":
            self._commit_pending_transition(connection, row, pack_record_digest)
        elif outcome == "mark_committed":
            _ = connection.execute(
                "update extension_control_authority_transition set phase = ?, committed_at = ? where revision = ?",
                (AuthorityPhase.COMMITTED.value, _now(), revision),
            )
        connection.commit()
        self._write_and_verify_anchor(
            AuthorityAnchor(revision, _row_str(row, "snapshot_digest"), AuthorityPhase.COMMITTED),
            key=key,
        )
        queue_event()
        connection.commit()
        resumed = self._read_extension_control_authority_locked(_row_str(row, "catalog_digest"))
        if resumed.health is not AuthorityHealth.PROTECTED or resumed.revision != revision:
            raise ExtensionControlAuthorityError("idempotent transition recovery failed")
        return resumed

    def _resume_transition(
        self, connection: sqlite3.Connection, revision: int, *, key: bytes
    ) -> ExtensionControlAuthorityView | None:
        """Resume the prepared transition at ``revision`` for its own request."""

        plan = self._authority_plan("resume_plan", key=key, revision=revision)
        if plan["outcome"] == "absent":
            return None
        return self._apply_resumed_transition(
            connection,
            str(plan["outcome"]),
            revision,
            current=None,
            key=key,
            pack_record_digest=_plan_pack_digest(plan),
        )

    def _roll_back_abandoned_transition(self, revision: int, *, snapshot_digest: str, key: bytes) -> bool:
        """Discard a prepared transition the vault anchor never moved past.

        The resident decides: the row must sit above a committed anchor that
        still pins ``snapshot_digest``, authenticate as prepared, and have
        outlived the window in which its own request may retry with its
        single-use proof. Anchored or committed transitions are left for
        explicit recovery. Returns whether the abandoned row was removed.
        """

        from .native_policy_snapshot_constants import NativePolicySnapshotError

        plan = self._authority_plan(
            "rollback_plan", key=key, revision=revision, snapshot_digest=snapshot_digest, now=_now()
        )
        if plan["outcome"] != "abandon":
            return False
        try:
            with self._connect() as connection:
                _ = self._apply_resumed_transition(connection, "abandon", revision + 1, current=None, key=key)
                _ = connection.execute(
                    "delete from extension_control_authority_proof "
                    "where transition_revision = ? and consumed_at is null",
                    (revision + 1,),
                )
        except (ExtensionControlAuthorityError, NativePolicySnapshotError):
            # Readers holding only a shared lease cannot mutate; explicit
            # recovery remains available.
            return False
        return True

    def _validate_transition_chain(
        self,
        revision: int,
        *,
        current_snapshot_digest: str,
        key: bytes,
    ) -> None:
        self._extension_control_authority_op(
            "validate_chain", key=key, revision=revision, snapshot_digest=current_snapshot_digest
        )

    def list_extension_control_authority_history(
        self,
        *,
        catalog_digest: str,
        limit: int = 20,
    ) -> list[dict[str, object]]:
        """Return authenticated, privacy-safe prior snapshots for the current catalog."""

        # Refuse before the read below, which can recover a stale transition.
        if type(limit) is not int or limit < 1 or limit > 50:
            raise ExtensionControlAuthorityError("invalid extension control history limit")
        with self._extension_control_authority_lock():
            current = self._read_extension_control_authority_locked(catalog_digest)
            key = self._authority_key(required=current.health is AuthorityHealth.PROTECTED and current.revision > 0)
            reply = self._extension_control_authority_op(
                "history",
                key=key,
                anchor_json=self._read_anchor_json() if key is not None else None,
                catalog_digest=catalog_digest,
                view=view_to_wire(current),
                limit=limit,
            )
            history = reply.get("history")
            if not isinstance(history, list):
                raise ExtensionControlAuthorityError("invalid extension control history")
            return cast(list[dict[str, object]], history)

    def _commit_pending_transition(
        self, connection: sqlite3.Connection, row: sqlite3.Row, pack_record_digest: str | None
    ) -> None:
        self._validate_serialized_layers(_row_str(row, "layers_json"))
        from .catalog_delivery.activation_journal import finish

        finish(self, connection, row, expected_pack=pack_record_digest)
        _ = connection.execute(
            """
            update extension_control_authority_snapshot
            set revision = ?, catalog_digest = ?, layers_json = ?, previous_digest = snapshot_digest,
                snapshot_json = ?, snapshot_digest = ?, snapshot_mac = ?, committed_at = ?
            where singleton = 1 and revision = ?
            """,
            (
                _row_int(row, "revision"),
                _row_str(row, "catalog_digest"),
                _row_str(row, "layers_json"),
                _row_str(row, "snapshot_json"),
                _row_str(row, "snapshot_digest"),
                _row_str(row, "snapshot_mac"),
                _row_str(row, "created_at"),
                _row_int(row, "previous_revision"),
            ),
        )
        _ = connection.execute(
            "update extension_control_authority_transition set phase = ?, committed_at = ? where revision = ?",
            (AuthorityPhase.COMMITTED.value, _now(), _row_int(row, "revision")),
        )

    def _pending_transition(self, revision: int) -> sqlite3.Row | None:
        with self._connect() as connection:
            return connection.execute(
                "select * from extension_control_authority_transition where revision = ?",
                (revision,),
            ).fetchone()
