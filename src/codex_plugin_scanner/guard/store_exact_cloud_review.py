"""Persistence boundary for replay-safe exact Cloud Review decisions."""

from __future__ import annotations

import json
import sqlite3
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from typing import Protocol

from .approval_resolution import require_resolvable_approval_request
from .dpop_key_binding import verified_dpop_jwk_thumbprint
from .runtime.time_support import parse_utc_timestamp
from .store_approvals import get_approval_request as load_approval_request
from .store_approvals import resolve_one_request_only as persist_one_resolution

_CAPABILITY_KEY = "guard_exact_cloud_review_capability_v1"
_OAUTH_KEY = "oauth_local_credentials"
_REVOCATION_KEY = "guard_exact_cloud_review_revocation_v1"


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def hold_oauth_credential_lock(self) -> AbstractContextManager[None]: ...

    def _load_oauth_secret_payload(
        self,
        payload: dict[str, object],
        *,
        promote: bool = True,
        allow_primary: bool = True,
    ) -> dict[str, object] | None: ...


class StoreExactCloudReviewMixin:
    @staticmethod
    def _exact_transaction_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _load_exact_state(connection: sqlite3.Connection, state_key: str) -> object:
        row = connection.execute(
            "select payload_json from sync_state where state_key = ?",
            (state_key,),
        ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(str(row["payload_json"]))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _store_exact_state(
        connection: sqlite3.Connection,
        state_key: str,
        payload: dict[str, object] | None,
        *,
        now: str,
    ) -> None:
        if payload is None:
            connection.execute("delete from sync_state where state_key = ?", (state_key,))
            return
        connection.execute(
            """
            insert into sync_state (state_key, payload_json, updated_at)
            values (?, ?, ?)
            on conflict(state_key) do update set
              payload_json = excluded.payload_json,
              updated_at = excluded.updated_at
            """,
            (state_key, json.dumps(payload, sort_keys=True, separators=(",", ":")), now),
        )

    @staticmethod
    def _record_exact_event(
        connection: sqlite3.Connection,
        event_name: str,
        payload: dict[str, object],
        *,
        now: str,
    ) -> None:
        connection.execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
            (event_name, json.dumps(payload, sort_keys=True, separators=(",", ":")), now),
        )

    def replace_exact_cloud_review_state(
        self: _ConnectionOwner,
        *,
        capability: dict[str, object] | None,
        revocation: dict[str, object] | None,
        now: str,
        event_name: str,
        event_payload: dict[str, object],
        expected_capability: object = None,
        require_expected_capability: bool = False,
    ) -> bool:
        """Atomically persist consent state; an expected capability provides CAS."""

        with self._connect() as connection:
            connection.execute("begin immediate")
            capability_matches = (
                StoreExactCloudReviewMixin._load_exact_state(connection, _CAPABILITY_KEY) == expected_capability
            )
            if require_expected_capability and not capability_matches:
                return False
            StoreExactCloudReviewMixin._store_exact_state(connection, _CAPABILITY_KEY, capability, now=now)
            StoreExactCloudReviewMixin._store_exact_state(connection, _REVOCATION_KEY, revocation, now=now)
            StoreExactCloudReviewMixin._record_exact_event(connection, event_name, event_payload, now=now)
        return True

    def has_exact_cloud_review_receipt(self: _ConnectionOwner, receipt_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "select 1 from guard_remote_once_receipts where receipt_id = ?",
                (receipt_id,),
            ).fetchone()
        return row is not None

    def resolve_one_request_with_signed_remote_exact_result(
        self: _ConnectionOwner,
        request_id: str,
        *,
        receipt_id: str,
        resolution_action: str,
        resolution_scope: str,
        reason: str,
        expected_capability: dict[str, object],
        expected_oauth_binding: dict[str, object],
        expected_request: dict[str, object],
        receipt_expires_at: str,
        request_expires_at: str,
    ) -> dict[str, object]:
        """Claim and apply an exact receipt after rechecking all mutable state."""

        with self.hold_oauth_credential_lock(), self._connect() as connection:
            connection.execute("begin immediate")
            resolved_at = StoreExactCloudReviewMixin._exact_transaction_now()
            capability = StoreExactCloudReviewMixin._load_exact_state(connection, _CAPABILITY_KEY)
            if capability != expected_capability:
                return _exact_error("remote_exact_capability_changed", now=resolved_at)
            if StoreExactCloudReviewMixin._load_exact_state(connection, _REVOCATION_KEY) is not None:
                return _exact_error("cloud_review_capability_revoked", now=resolved_at)
            oauth_state = StoreExactCloudReviewMixin._load_exact_state(connection, _OAUTH_KEY)
            oauth_secret = (
                self._load_oauth_secret_payload(oauth_state, promote=False, allow_primary=False)
                if isinstance(oauth_state, dict)
                else None
            )
            oauth_binding = _oauth_binding_from_state(connection, oauth_state, oauth_secret)
            if oauth_binding != expected_oauth_binding:
                return _exact_error("remote_exact_oauth_changed", now=resolved_at)
            if not _capability_matches_oauth_binding(capability, oauth_binding):
                return _exact_error("cloud_review_capability_binding_mismatch", now=resolved_at)
            current = parse_utc_timestamp(resolved_at)
            capability_expires_at = (
                parse_utc_timestamp(capability.get("expiresAt")) if isinstance(capability, dict) else None
            )
            if current is None or capability_expires_at is None or capability_expires_at <= current:
                return _exact_error("cloud_review_capability_expired", now=resolved_at)
            expires_at = parse_utc_timestamp(receipt_expires_at)
            if expires_at is None or expires_at <= current:
                return _exact_error("remote_approval_expired", now=resolved_at)
            request_expires = parse_utc_timestamp(request_expires_at)
            if request_expires is None or request_expires <= current:
                return _exact_error("remote_exact_request_expired", now=resolved_at)
            request = load_approval_request(connection, request_id)
            if request is None or request.get("status") != "pending":
                return _exact_error("remote_exact_request_not_pending", now=resolved_at)
            if _request_snapshot(request) != _request_snapshot(expected_request):
                return _exact_error("remote_exact_request_stale", now=resolved_at)
            try:
                connection.execute(
                    """
                    insert into guard_remote_once_receipts (receipt_id, request_id, claimed_at)
                    values (?, ?, ?)
                    """,
                    (receipt_id, request_id, resolved_at),
                )
            except sqlite3.IntegrityError:
                return {"checked_at": resolved_at, "replayed": True, "resolved": False}
            require_resolvable_approval_request(request)
            resolved = persist_one_resolution(
                connection,
                request_id,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )
            if not resolved:
                connection.execute(
                    "delete from guard_remote_once_receipts where receipt_id = ?",
                    (receipt_id,),
                )
                return _exact_error("remote_exact_apply_failed", now=resolved_at)
            resolved_request = load_approval_request(connection, request_id)
            StoreExactCloudReviewMixin._record_exact_event(
                connection,
                "cloud_review.exact_applied",
                {
                    "receipt_id": receipt_id,
                    "request_id": request_id,
                    "resolution_action": resolution_action,
                    "resolution_scope": resolution_scope,
                },
                now=resolved_at,
            )
            return {
                "replayed": False,
                "resolved": True,
                "resolved_at": resolved_at,
                "resolved_request": resolved_request,
                "resolved_duplicate_ids": [],
            }


def _request_snapshot(request: dict[str, object]) -> str:
    """Compare every persisted request input with canonical JSON semantics."""

    return json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _exact_error(code: str, *, now: str) -> dict[str, object]:
    return {"checked_at": now, "error": code, "replayed": False, "resolved": False}


def _oauth_binding_from_state(
    connection: sqlite3.Connection,
    oauth_state: object,
    oauth_secret: object,
) -> dict[str, object] | None:
    if not isinstance(oauth_state, dict) or not isinstance(oauth_secret, dict):
        return None
    device = connection.execute(
        "select installation_id from guard_devices where device_key = ?",
        ("local-device",),
    ).fetchone()
    installation_id = str(device["installation_id"]) if device is not None else None
    machine_id = oauth_state.get("machine_id")
    device_id = oauth_state.get("device_id")
    try:
        dpop_thumbprint = verified_dpop_jwk_thumbprint(
            private_key_pem=oauth_secret.get("dpop_private_key_pem"),
            public_jwk=oauth_secret.get("dpop_public_jwk"),
        )
    except ValueError:
        return None
    if (
        not isinstance(device_id, str)
        or not device_id.strip()
        or device_id != dpop_thumbprint
        or oauth_state.get("dpop_public_jwk_thumbprint") != dpop_thumbprint
        or oauth_secret.get("dpop_public_jwk_thumbprint") != dpop_thumbprint
    ):
        return None
    return {
        "deviceId": device_id,
        "dpopThumbprint": dpop_thumbprint,
        "grantId": oauth_state.get("grant_id"),
        "installationId": installation_id,
        "machineId": machine_id,
        "runtimeId": oauth_state.get("runtime_id"),
        "workspaceId": oauth_state.get("workspace_id"),
    }


def _capability_matches_oauth_binding(capability: object, oauth_binding: dict[str, object] | None) -> bool:
    """Recheck the signed capability's local target inside the write transaction."""

    if not isinstance(capability, dict) or oauth_binding is None:
        return False
    return all(capability.get(key) == value for key, value in oauth_binding.items())
