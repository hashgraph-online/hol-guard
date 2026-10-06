"""Route complete business documents to Rust and the shared source owner."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING, cast

from .approval_gate import require_high_risk
from .native_business_document_compile import compile_business_policy_document
from .native_business_source_retention import read_retained_business_source_anchor
from .native_business_source_store import (
    ANCHOR_FILE_NAME,
    PREPARED_SOURCE_FILE_NAME,
    SOURCE_FILE_NAME,
    BusinessSourceMutation,
    _database_witness,
    approved_business_source_mutation,
    read_installed_business_source,
)
from .native_command_control_authority_io import read_private_state
from .native_policy_snapshot_codec import _strict_json_loads_v3, derive_native_policy_verifier_key
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .policy_document import GuardPolicyDocument, policy_document_digest
from .policy_document_authority import policy_import_approval_binding
from .policy_document_compile import compile_policy_document

if TYPE_CHECKING:
    from .approval_gate import ApprovalGateGrant
    from .native_business_source_bridge import KeyAuthenticatedBusinessSource
    from .store import GuardStore


def has_business_rules(document: GuardPolicyDocument) -> bool:
    return any("business" in rule.match.to_mapping() for rule in document.rules)


def compile_document_for_import(document: GuardPolicyDocument):
    if has_business_rules(document):
        # Rust validates the *whole* document, including unsupported mixed
        # selectors and lifetimes. Empty legacy rows are not a policy projection.
        compile_business_policy_document(document)
        return ()
    return compile_policy_document(document)


def plan_document_for_import(store, document, compiled_rows, mode):
    if not has_business_rules(document):
        refuse_legacy_import_over_business_source(store)
        return store.plan_policy_document_import(compiled_rows, mode=mode)
    from .store_policy_document import PolicyDocumentImportPlan

    if mode != "replace":
        raise NativePolicySnapshotError("native_business_source_replace_required")
    prior = read_business_document_for_store(store)
    old_ids = {rule.id for rule in prior.rules} if prior else set()
    new_ids = {rule.id for rule in document.rules}
    legacy = store.plan_policy_document_import((), mode="replace")
    return PolicyDocumentImportPlan(
        additions=tuple(sorted(new_ids - old_ids)),
        replacements=tuple(sorted(new_ids & old_ids)),
        removals=tuple(sorted(set(legacy.removals) | (old_ids - new_ids))),
    )


def read_business_source_for_store(store: GuardStore) -> KeyAuthenticatedBusinessSource | None:
    material = store._policy_integrity_secret_material(create=False)
    if material is None or material[0] is None:
        # Legacy unprotected stores cannot issue signed native snapshots. Any
        # retained source evidence still prohibits treating them as fresh.
        from .native_business_source_anchor_bridge import MAX_ANCHOR_BYTES
        from .native_business_source_bridge import MAX_RECORD_BYTES

        if (
            read_private_state(store.guard_home, SOURCE_FILE_NAME, MAX_RECORD_BYTES) is not None
            or read_private_state(store.guard_home, PREPARED_SOURCE_FILE_NAME, MAX_RECORD_BYTES) is not None
            or read_private_state(store.guard_home, ANCHOR_FILE_NAME, MAX_ANCHOR_BYTES) is not None
            or (
                store._policy_integrity_secret_store is not None
                and read_retained_business_source_anchor(store) is not None
            )
            or _database_witness(store) is not None
        ):
            raise NativePolicySnapshotError("native_business_source_installation_key_unavailable")
        return None
    return read_installed_business_source(store, derive_native_policy_verifier_key(material[0]))


def read_business_document_for_store(store: GuardStore) -> GuardPolicyDocument | None:
    source = read_business_source_for_store(store)
    if source is None:
        return None
    record = cast(dict[str, object], _strict_json_loads_v3(source.record_bytes))
    return GuardPolicyDocument.from_mapping(cast(dict[str, object], record["source_document"]))


def refuse_legacy_import_over_business_source(store: GuardStore) -> None:
    if read_business_source_for_store(store) is not None:
        raise NativePolicySnapshotError("native_business_policy_removal_requires_authority")


def apply_business_document_on_connection(
    store: GuardStore,
    document: GuardPolicyDocument,
    mutation: BusinessSourceMutation,
    *,
    mode: str,
    now: str,
    approval_gate_grant: ApprovalGateGrant | None,
    connection: sqlite3.Connection,
):
    from .store_policy_document import PolicyDocumentImportResult

    digest = policy_document_digest(document)
    if mode != "replace" or digest != mutation.source.source_digest:
        raise NativePolicySnapshotError("native_business_source_installation_incoherent")
    require_high_risk(
        store.guard_home,
        purpose="policy_import",
        **policy_import_approval_binding(document, mode),
        approval_gate_grant=approval_gate_grant,
        now=now,
    )
    result = store._import_policy_rows_on_connection(
        connection,
        document=document,
        compiled_rows=(),
        normalized_rows=[],
        mode="replace",
        now=now,
        digest=digest,
        secret_material=store._policy_integrity_secret_material(create=False),
    )
    mutation.stage_on_connection(connection, now=now)
    return PolicyDocumentImportResult(
        document_id=document.metadata.id, digest=digest, inserted=len(document.rules), replaced=result.replaced
    )


def import_business_document(
    store: GuardStore,
    document: GuardPolicyDocument,
    *,
    mode: str,
    now: str,
    approval_gate_grant: ApprovalGateGrant | None,
):
    with (
        approved_business_source_mutation(
            store, document, mode=mode, now=now, approval_gate_grant=approval_gate_grant
        ) as mutation,
        store._connect() as connection,
    ):
        connection.execute("begin immediate")
        result = apply_business_document_on_connection(
            store,
            document,
            mutation,
            mode=mode,
            now=now,
            approval_gate_grant=approval_gate_grant,
            connection=connection,
        )
        connection.commit()
    return result
