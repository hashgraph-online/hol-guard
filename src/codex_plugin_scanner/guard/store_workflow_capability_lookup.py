"""Authenticated workflow-capability lookup and authority validation."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager

from . import store_workflow_capabilities as workflow_capability_store
from .store_workflow_capabilities import (
    _decode_signed_claim,
    _require_store_key,
    _validate_claim_row,
    _validate_public_identifier,
    _verify_persisted_claim_signature,
)
from .store_workflow_capabilities_schema import ensure_workflow_capability_schema
from .store_workflow_capability_authority import load_and_validate_authority
from .store_workflow_capability_control import load_validate_and_observe_control
from .store_workflow_capability_lock import serialized_workflow_capability_authority
from .workflow_capabilities import SignedWorkflowCapability, WorkflowCapabilityError


class StoreWorkflowCapabilityLookupMixin:
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]:
        raise NotImplementedError

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
        _ = create
        raise NotImplementedError

    def _load_workflow_capability_control(self) -> str | None:
        raise NotImplementedError

    def _store_workflow_capability_control(self, encoded: str) -> bool:
        _ = encoded
        raise NotImplementedError

    @serialized_workflow_capability_authority
    def lookup_workflow_capability(self, capability_id: str) -> SignedWorkflowCapability | None:
        _validate_public_identifier("capability_id", capability_id)
        key, key_id = _require_store_key(self, create=False)
        with self._connect() as connection:
            connection.execute("begin")
            now = workflow_capability_store._workflow_capability_store_now()
            ensure_workflow_capability_schema(connection, applied_at=now)
            load_validate_and_observe_control(self, connection, key=key, key_id=key_id, now=now, create=False)
            return load_validated_workflow_capability(
                connection,
                capability_id,
                key=key,
                key_id=key_id,
            )


def load_validated_workflow_capability(
    connection: sqlite3.Connection,
    capability_id: str,
    *,
    key: bytes,
    key_id: str,
) -> SignedWorkflowCapability | None:
    row = connection.execute(
        """
        select signed_claim_json, approval_provenance_id, nonce, key_id,
               issued_at, not_before, expires_at, max_uses, used_count,
               revoked_at, revocation_code
        from guard_workflow_capabilities where capability_id = ?
        """,
        (capability_id,),
    ).fetchone()
    if row is None:
        return None
    signed = _decode_signed_claim(str(row["signed_claim_json"]))
    _validate_claim_row(signed, row, capability_id)
    _verify_persisted_claim_signature(signed, key=key, key_id=key_id)
    load_and_validate_authority(
        connection,
        signed,
        key=key,
        key_id=key_id,
        used_count=int(row["used_count"]),
        revoked_at=row["revoked_at"],
        revocation_code=row["revocation_code"],
    )
    return signed


def require_validated_workflow_capability(
    connection: sqlite3.Connection,
    capability_id: str,
    *,
    key: bytes,
    key_id: str,
) -> SignedWorkflowCapability:
    signed = load_validated_workflow_capability(connection, capability_id, key=key, key_id=key_id)
    if signed is None:
        raise WorkflowCapabilityError("receipt_claim_missing")
    return signed
