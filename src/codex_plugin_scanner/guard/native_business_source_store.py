"""Approved whole-source installation shared by CLI and MCP transaction owners.

Closed markers precede all source/database writes. A verified database commit,
independent local retention and exact source identity precede the final marker.
This is local policy integrity, not provider credential custody or actor proof.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .approval_gate import require_high_risk
from .approval_gate_state import epoch
from .native_business_document_compile import compile_business_policy_document
from .native_business_source_anchor_bridge import (
    MAX_ANCHOR_BYTES,
    KeyAuthenticatedBusinessSourceAnchor,
    build_business_source_anchor,
    verify_business_source_anchor,
)
from .native_business_source_bridge import (
    MAX_RECORD_BYTES,
    KeyAuthenticatedBusinessSource,
    _consumer,
    _deadline,
    _remaining,
    build_business_source_record,
    verify_business_source_record,
)
from .native_business_source_retention import (
    read_retained_business_source_anchor,
    write_retained_business_source_anchor,
)
from .native_command_control_authority_io import (
    hold_command_control_authority_lock,
    read_private_state,
    write_private_state,
)
from .native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,
    _strict_json_loads_v3,
    derive_native_policy_verifier_key,
)
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .policy_document_authority import policy_import_approval_binding

if TYPE_CHECKING:
    from .approval_gate import ApprovalGateGrant
    from .policy_document import GuardPolicyDocument
    from .store import GuardStore

SOURCE_FILE_NAME = "business-source-authority.v1.json"
PREPARED_SOURCE_FILE_NAME = "business-source-prepared.v1.json"
ANCHOR_FILE_NAME = "business-source-anchor.v1.json"
INSTALLATION_STATE_KEY = "business_source_installation_v1"
CURRENT_FENCE_CAPABILITY = "native-business-source-current-fence-v2"
_UNSPECIFIED_CURRENT = object()
# An approved installation runs compile, status, build, verify and two anchor
# builds as separate native processes, plus the caller's SQL transaction. Slow
# process start (Windows on emulated x64, endpoint scanning) can exceed the
# single-operation cap in total while every step is individually healthy.
MUTATION_BUDGET_SECONDS = 30.0


def _error(code: str = "native_business_source_installation_incoherent") -> NativePolicySnapshotError:
    return NativePolicySnapshotError(code)


def _require_approved(store, binding, approval_gate_grant, now):
    if (
        approval_gate_grant is None
        or require_high_risk(
            store.guard_home,
            purpose="policy_import",
            **binding,
            approval_gate_grant=approval_gate_grant,
            now=now,
        )
        is None
    ):
        raise _error("native_business_source_approval_required")


def _mutation_deadline(deadline_monotonic: float | None, approval_gate_grant: ApprovalGateGrant | None) -> float:
    deadline = _deadline(deadline_monotonic, budget_seconds=MUTATION_BUDGET_SECONDS)
    if approval_gate_grant is None:
        return deadline
    # Approval is rechecked after the caller's SQL commit. Do not let the
    # installation run past the grant that authorizes it; an already expired
    # grant is still refused by the approval check, not the deadline.
    grant_remaining = epoch(approval_gate_grant.expires_at) - time.time()
    return min(deadline, time.monotonic() + grant_remaining) if grant_remaining > 0 else deadline


def _witness(anchor: KeyAuthenticatedBusinessSourceAnchor) -> bytes:
    return _canonical_json_bytes_v3(
        {
            "schema": "guard.business-source-installation.v1",
            "anchor_digest": anchor.anchor_digest,
            "retained_identity": _strict_json_loads_v3(anchor.retained_identity_bytes),
        }
    )


def _read_witness(connection: sqlite3.Connection) -> bytes | None:
    row = connection.execute(
        "select payload_json from sync_state where state_key = ?", (INSTALLATION_STATE_KEY,)
    ).fetchone()
    if row is None:
        return None
    value = row[0]
    if type(value) is not str or len(value.encode("utf-8")) > MAX_ANCHOR_BYTES:
        raise _error()
    return value.encode("utf-8")


def _database_witness(store: GuardStore) -> bytes | None:
    with store._connect() as connection:
        return _read_witness(connection)


def _refuse_native_business_floor_without_source(store: GuardStore, key: bytes) -> None:
    from .native_command_control_authority_store import read_native_control_floor
    from .native_policy_snapshot_constants import _RUST_SNAPSHOT_STATE_NAME, POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES

    content = read_private_state(store.guard_home, _RUST_SNAPSHOT_STATE_NAME, POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES)
    if content is None:
        return
    # Authenticate the existing combined floor before interpreting its identity.
    read_native_control_floor(store, key)
    record = _strict_json_loads_v3(content)
    if not isinstance(record, dict) or "business_policy_floor" in record:
        raise _error("native_business_source_recovery_required")


def _write_private(store: GuardStore, name: str, wire: bytes, limit: int, deadline: float) -> None:
    _remaining(deadline)
    write_private_state(store.guard_home, name, wire, limit)
    if read_private_state(store.guard_home, name, limit) != wire:
        raise _error("native_business_source_installation_write_mismatch")
    _remaining(deadline)


def _verify_installed(
    record: bytes | None,
    marker: bytes | None,
    retained: bytes | None,
    witness: bytes | None,
    key: bytes,
    deadline: float,
) -> KeyAuthenticatedBusinessSource | None:
    if all(value is None for value in (record, marker, retained, witness)):
        return None
    if any(value is None for value in (record, marker, retained, witness)) or marker != retained:
        raise _error()
    status = _consumer(deadline, anchor=True)
    assert status.capabilities is not None
    if CURRENT_FENCE_CAPABILITY not in status.capabilities.features:
        raise _error("native_business_source_current_fence_unavailable")
    assert record is not None and marker is not None
    anchor = verify_business_source_anchor(marker, key, deadline_monotonic=deadline)
    if anchor.phase != "committed" or witness != _witness(anchor):
        raise _error()
    source = verify_business_source_record(
        record, key, deadline_monotonic=deadline, retained_identity_bytes=anchor.retained_identity_bytes
    )
    if source.retained_identity_bytes != anchor.retained_identity_bytes:
        raise _error()
    return source


def read_installed_business_source(
    store: GuardStore, verifier_key: bytes, *, deadline_monotonic: float | None = None
) -> KeyAuthenticatedBusinessSource | None:
    """Recompile the complete authenticated source off the synchronous hook path."""
    deadline = _deadline(deadline_monotonic)
    with hold_command_control_authority_lock(store.guard_home, shared=True, timeout_seconds=_remaining(deadline)):
        result = _verify_installed(
            read_private_state(store.guard_home, SOURCE_FILE_NAME, MAX_RECORD_BYTES),
            read_private_state(store.guard_home, ANCHOR_FILE_NAME, MAX_ANCHOR_BYTES),
            read_retained_business_source_anchor(store),
            _database_witness(store),
            verifier_key,
            deadline,
        )
        if result is None:
            if read_private_state(store.guard_home, PREPARED_SOURCE_FILE_NAME, MAX_RECORD_BYTES) is not None:
                raise _error("native_business_source_recovery_required")
            _refuse_native_business_floor_without_source(store, verifier_key)
        _remaining(deadline)
        return result


@dataclass(frozen=True, slots=True, repr=False)
class BusinessSourceMutation:
    source: KeyAuthenticatedBusinessSource
    committed_anchor: KeyAuthenticatedBusinessSourceAnchor
    previous_source: KeyAuthenticatedBusinessSource | None = None

    def stage_on_connection(self, connection: sqlite3.Connection, *, now: str) -> None:
        """The existing request owner commits its status and this witness together."""
        if not connection.in_transaction:
            raise _error("native_business_source_transaction_required")
        connection.execute(
            "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) "
            "on conflict(state_key) do update set payload_json=excluded.payload_json, updated_at=excluded.updated_at",
            (INSTALLATION_STATE_KEY, _witness(self.committed_anchor).decode("utf-8"), now),
        )


@contextmanager
def approved_business_source_mutation(
    store: GuardStore,
    document: GuardPolicyDocument,
    *,
    mode: str,
    now: str,
    approval_gate_grant: ApprovalGateGrant | None,
    deadline_monotonic: float | None = None,
    expected_current_digest: str | None | object = _UNSPECIFIED_CURRENT,
    reject_already_installed: bool = False,
) -> Iterator[BusinessSourceMutation]:
    """Own the complete mutation lease; callers begin/commit SQL inside it.

    Failure leaves a closed marker. Missing or interrupted prior installations
    require an explicit recovery path; ordinary import never silently repairs.
    """
    if mode != "replace":
        raise _error("native_business_source_replace_required")
    deadline = _mutation_deadline(deadline_monotonic, approval_gate_grant)
    candidate = compile_business_policy_document(document, deadline_monotonic=deadline)
    status = _consumer(deadline, anchor=True)
    assert status.capabilities is not None
    if CURRENT_FENCE_CAPABILITY not in status.capabilities.features:
        raise _error("native_business_source_current_fence_unavailable")
    binding = policy_import_approval_binding(document, mode)
    _require_approved(store, binding, approval_gate_grant, now)
    with hold_command_control_authority_lock(store.guard_home, timeout_seconds=_remaining(deadline)):
        _require_approved(
            store,
            binding,
            approval_gate_grant,
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        retained = read_retained_business_source_anchor(store)
        marker = read_private_state(store.guard_home, ANCHOR_FILE_NAME, MAX_ANCHOR_BYTES)
        record = read_private_state(store.guard_home, SOURCE_FILE_NAME, MAX_RECORD_BYTES)
        prepared = read_private_state(store.guard_home, PREPARED_SOURCE_FILE_NAME, MAX_RECORD_BYTES)
        witness = _database_witness(store)
        fresh = all(value is None for value in (retained, marker, record, witness, prepared))
        material = store._policy_integrity_secret_material(create=fresh)
        if material is None or type(material[0]) is not bytes or len(material[0]) != 32:
            raise _error("native_business_source_installation_key_unavailable")
        key = derive_native_policy_verifier_key(material[0])
        prior = _verify_installed(record, marker, retained, witness, key, deadline)
        if reject_already_installed and prior is not None:
            from .policy_document import policy_document_digest

            if prior.source_digest == policy_document_digest(document):
                raise _error("native_business_source_already_installed")
        if prepared is not None and (prior is None or prepared != prior.record_bytes):
            raise _error("native_business_source_recovery_required")
        if prior is None:
            _refuse_native_business_floor_without_source(store, key)
        if expected_current_digest is not _UNSPECIFIED_CURRENT:
            from .policy_document import policy_document_digest
            from .policy_document_compile import build_policy_document_from_rows

            imported = [row for row in store.list_policy_decisions() if row.get("source") == "policy-yaml-import"]
            current_digest = None
            if prior is not None:
                current_digest = prior.source_digest
            elif imported:
                current_digest = policy_document_digest(
                    build_policy_document_from_rows(imported, document_id="local-policy")
                )
            if current_digest != expected_current_digest:
                raise _error("native_business_source_current_digest_changed")
        next_revision = 1 if prior is None else prior.mutation_revision + 1
        source = build_business_source_record(candidate, key, next_revision, deadline_monotonic=deadline)
        if prior is not None:
            source = verify_business_source_record(
                source.record_bytes,
                key,
                deadline_monotonic=deadline,
                retained_identity_bytes=prior.retained_identity_bytes,
            )
        closed = build_business_source_anchor(source, key, "closed", deadline_monotonic=deadline)
        committed = build_business_source_anchor(source, key, "committed", deadline_monotonic=deadline)
        _require_approved(
            store,
            binding,
            approval_gate_grant,
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        # Signed complete candidate is durable before retiring the active source.
        # A failed import can be explicitly resumed with fresh exact approval.
        _write_private(store, PREPARED_SOURCE_FILE_NAME, source.record_bytes, MAX_RECORD_BYTES, deadline)
        _write_private(store, ANCHOR_FILE_NAME, closed.anchor_bytes, MAX_ANCHOR_BYTES, deadline)
        write_retained_business_source_anchor(store, closed.anchor_bytes)
        _write_private(store, SOURCE_FILE_NAME, source.record_bytes, MAX_RECORD_BYTES, deadline)
        mutation = BusinessSourceMutation(source, committed, prior)
        yield mutation
        _remaining(deadline)
        # A rollback is not a successful commit merely because in_transaction
        # became false. Read the intended witness from a separate connection.
        if _database_witness(store) != _witness(committed):
            raise _error("native_business_source_transaction_not_committed")
        if (
            read_private_state(store.guard_home, SOURCE_FILE_NAME, MAX_RECORD_BYTES) != source.record_bytes
            or read_private_state(store.guard_home, ANCHOR_FILE_NAME, MAX_ANCHOR_BYTES) != closed.anchor_bytes
            or read_retained_business_source_anchor(store) != closed.anchor_bytes
        ):
            raise _error()
        _require_approved(
            store,
            binding,
            approval_gate_grant,
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        write_retained_business_source_anchor(store, committed.anchor_bytes)
        _write_private(store, ANCHOR_FILE_NAME, committed.anchor_bytes, MAX_ANCHOR_BYTES, deadline)
