"""Atomic canonical policy document persistence."""

from __future__ import annotations

import sqlite3

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

from .approval_gate import ApprovalGateGrant, require_high_risk
from .native_store_policy import encode_key
from .policy_authority import validate_policy_write_authority
from .policy_document import GuardPolicyDocument, policy_document_digest
from .policy_document_authority import policy_import_approval_binding
from .policy_document_compile import compile_policy_document
from .policy_document_io import CompiledPolicyRow
from .store_base import _validate_scoped_policy_artifact_target, serialize_policy_integrity_generation

PolicyImportMode = Literal["merge", "replace"]

if TYPE_CHECKING:
    from .store import GuardStore


@dataclass(frozen=True, slots=True)
class PolicyDocumentImportResult:
    document_id: str
    digest: str
    inserted: int
    replaced: int


@dataclass(frozen=True, slots=True)
class PolicyDocumentImportPlan:
    additions: tuple[str, ...]
    replacements: tuple[str, ...]
    removals: tuple[str, ...]


def _validate_compiled_document_rows(
    document: GuardPolicyDocument,
    compiled_rows: tuple[CompiledPolicyRow, ...],
) -> None:
    # Reuse the canonical adapter; do not trust a caller's claimed projection.
    # This check adds no matcher or policy evaluator and preserves refusal of
    # documents the existing adapter cannot represent.
    if compile_policy_document(document) != compiled_rows:
        raise ValueError("policy_document_compilation_mismatch")


def policy_import_result(
    document: GuardPolicyDocument,
    digest: str,
    payload: Mapping[str, object],
) -> PolicyDocumentImportResult:
    inserted, replaced = payload.get("inserted"), payload.get("replaced")
    if not isinstance(inserted, int) or not isinstance(replaced, int):
        raise RuntimeError("Guard policy document was not imported.")
    return PolicyDocumentImportResult(
        document_id=document.metadata.id,
        digest=digest,
        inserted=inserted,
        replaced=replaced,
    )


class StorePolicyDocumentMixin:
    def plan_policy_document_import(
        self,
        compiled_rows: tuple[CompiledPolicyRow, ...],
        *,
        mode: PolicyImportMode,
    ) -> PolicyDocumentImportPlan:
        if mode not in {"merge", "replace"}:
            raise ValueError("invalid_policy_import_mode")
        current_rows = self.list_policy_decisions()
        current_by_key: dict[
            tuple[str, str, str | None, str | None, str | None, str | None],
            dict[str, object],
        ] = {}
        for row in current_rows:
            if row.get("source") != "policy-yaml-import":
                continue
            current_by_key[
                (
                    str(row.get("harness", "")),
                    str(row.get("scope", "")),
                    str(row["artifact_id"]) if row.get("artifact_id") is not None else None,
                    str(row["artifact_hash"]) if row.get("artifact_hash") is not None else None,
                    str(row["workspace"]) if row.get("workspace") is not None else None,
                    str(row["publisher"]) if row.get("publisher") is not None else None,
                )
            ] = row

        incoming_by_key: dict[
            tuple[str, str, str | None, str | None, str | None, str | None],
            str,
        ] = {}
        for compiled in compiled_rows:
            decision = compiled.decision
            artifact_id, artifact_hash, workspace, publisher = self._normalized_policy_keys(decision)
            key = (
                decision.harness,
                decision.scope,
                artifact_id,
                artifact_hash,
                workspace,
                publisher,
            )
            if key in incoming_by_key:
                raise ValueError(f"duplicate_policy_selector:{compiled.rule_id}")
            incoming_by_key[key] = compiled.rule_id

        additions = sorted(rule_id for key, rule_id in incoming_by_key.items() if key not in current_by_key)
        replacements = sorted(rule_id for key, rule_id in incoming_by_key.items() if key in current_by_key)
        removals: list[str] = []
        if mode == "replace":
            for key, row in current_by_key.items():
                if row.get("source") != "policy-yaml-import" or key in incoming_by_key:
                    continue
                rule_id = row.get("policy_rule_id")
                decision_id = row.get("decision_id")
                local_decision_id = (
                    decision_id if isinstance(decision_id, int) and not isinstance(decision_id, bool) else 0
                )
                removals.append(str(rule_id) if rule_id is not None else f"local-{local_decision_id}")
        return PolicyDocumentImportPlan(
            additions=tuple(additions),
            replacements=tuple(replacements),
            removals=tuple(sorted(removals)),
        )

    @serialize_policy_integrity_generation
    def import_policy_document(
        self,
        document: GuardPolicyDocument,
        compiled_rows: tuple[CompiledPolicyRow, ...],
        *,
        mode: PolicyImportMode,
        now: str,
        approval_gate_grant: ApprovalGateGrant | None,
    ) -> PolicyDocumentImportResult:
        """Persist one fully compiled document as an all-or-nothing local mutation."""
        if mode not in {"merge", "replace"}:
            raise ValueError("invalid_policy_import_mode")

        from .business_policy_document_import import (
            has_business_rules,
            import_business_document,
            refuse_legacy_import_over_business_source,
        )

        if has_business_rules(document):
            if compiled_rows:
                raise ValueError("policy_document_compilation_mismatch")
            return import_business_document(
                cast("GuardStore", self), document, mode=mode, now=now, approval_gate_grant=approval_gate_grant
            )
        normalized_rows = self._normalize_compiled_rows(compiled_rows)

        _validate_compiled_document_rows(document, compiled_rows)

        require_high_risk(
            self.guard_home,
            purpose="policy_import",
            **policy_import_approval_binding(document, mode),
            approval_gate_grant=approval_gate_grant,
            now=now,
        )

        digest = policy_document_digest(document)
        from .native_command_control_authority_io import hold_command_control_authority_lock

        # The resident owns the row writes and the generation advance; the
        # integrity key and control state stay here.
        with hold_command_control_authority_lock(self.guard_home):
            refuse_legacy_import_over_business_source(cast("GuardStore", self))
            args = self.policy_import_args(document, normalized_rows, mode=mode, now=now, digest=digest)
            payload = self._native_store_call("import_policy_rows", args)
            if not isinstance(payload, dict):
                raise RuntimeError("Guard policy document was not imported.")
            self.finalize_policy_import(payload.get("next_control_state"))
        return policy_import_result(document, digest, payload)

    def policy_import_args(
        self,
        document: GuardPolicyDocument,
        normalized_rows: list[tuple[CompiledPolicyRow, str | None, str | None, str | None, str | None]],
        *,
        mode: PolicyImportMode,
        now: str,
        digest: str,
    ) -> dict[str, object]:
        """The native ``import_policy_rows`` arguments, with the signing material.

        When the store is protected the pending generation is persisted first,
        so an interrupted write leaves a generation the next start reconciles.
        """

        rows: list[dict[str, object]] = []
        for compiled, artifact_id, artifact_hash, workspace, publisher in normalized_rows:
            decision = compiled.decision
            rows.append(
                {
                    "harness": decision.harness,
                    "scope": decision.scope,
                    "artifact_id": artifact_id,
                    "artifact_hash": artifact_hash,
                    "workspace": workspace,
                    "publisher": publisher,
                    "action": decision.action,
                    "reason": decision.reason,
                    "owner": decision.owner,
                    "source": decision.source,
                    "expires_at": decision.expires_at,
                    "rule_id": compiled.rule_id,
                    "provenance_json": compiled.provenance_json,
                }
            )
        args: dict[str, object] = {
            "mode": mode,
            "now": now,
            "document": {"api_version": document.api_version, "id": document.metadata.id, "digest": digest},
            "rows": rows,
        }
        secret_material = self._policy_integrity_secret_material(create=True)
        with self._connect() as connection:
            state = self._refresh_policy_integrity_state(
                connection,
                now=now,
                create_key=True,
                secret_material=secret_material,
                allow_cutover_resign=False,
            )
        key, key_id = secret_material
        if state.get("mode") == "protected" and key is not None and key_id is not None:
            trusted_state = self._load_policy_integrity_control_state(create=True)
            if trusted_state is not None:
                args["current_generation"] = self._begin_policy_integrity_generation(trusted_state)
                args["integrity_key_b64"] = encode_key(key)
                args["integrity_key_id"] = key_id
        return args

    def finalize_policy_import(self, next_control_state: object) -> None:
        """Adopt the control state a native import advanced to, if any."""

        if next_control_state is None:
            return
        if not isinstance(next_control_state, dict):
            raise RuntimeError("Guard policy integrity control state is invalid.")
        self._finalize_policy_integrity_control_state(next_control_state)

    def _normalize_compiled_rows(
        self,
        compiled_rows: tuple[CompiledPolicyRow, ...],
    ) -> list[tuple[CompiledPolicyRow, str | None, str | None, str | None, str | None]]:
        normalized_rows: list[tuple[CompiledPolicyRow, str | None, str | None, str | None, str | None]] = []
        seen_keys: set[tuple[str, str, str | None, str | None, str | None, str | None]] = set()
        for compiled in compiled_rows:
            decision = compiled.decision
            validate_policy_write_authority(decision, remote_write_authorized=False)
            _validate_scoped_policy_artifact_target(decision.scope, decision.artifact_id)
            artifact_id, artifact_hash, workspace, publisher = self._normalized_policy_keys(decision)
            key = (
                decision.harness,
                decision.scope,
                artifact_id,
                artifact_hash,
                workspace,
                publisher,
            )
            if key in seen_keys:
                raise ValueError(f"duplicate_policy_selector:{compiled.rule_id}")
            seen_keys.add(key)
            normalized_rows.append((compiled, artifact_id, artifact_hash, workspace, publisher))
        return normalized_rows

    def _import_policy_rows_on_connection(
        self,
        connection: sqlite3.Connection,
        *,
        document: GuardPolicyDocument,
        compiled_rows: tuple[CompiledPolicyRow, ...],
        normalized_rows: list[tuple[CompiledPolicyRow, str | None, str | None, str | None, str | None]],
        mode: PolicyImportMode,
        now: str,
        digest: str,
        secret_material: tuple[bytes | None, str | None],
    ) -> PolicyDocumentImportResult:
        """Write policy rows on a caller-owned connection (already in BEGIN IMMEDIATE).

        The caller is responsible for commit/rollback. Only the business
        source import uses it, because its source swap shares the request's
        transaction; local imports go through the resident's
        ``import_policy_rows``.
        """
        next_control_state: dict[str, object] | None = None
        inserted_ids: set[int] = set()
        replaced = 0
        state = self._refresh_policy_integrity_state(
            connection,
            now=now,
            create_key=True,
            secret_material=secret_material,
            allow_cutover_resign=False,
        )
        if mode == "replace":
            cursor = connection.execute("delete from policy_decisions where source = 'policy-yaml-import'")
            replaced += max(cursor.rowcount, 0)

        for compiled, artifact_id, artifact_hash, workspace, publisher in normalized_rows:
            decision = compiled.decision
            if mode == "merge":
                cursor = connection.execute(
                    """
                    delete from policy_decisions
                    where source = 'policy-yaml-import'
                      and harness = ? and scope = ? and coalesce(artifact_id, '') = coalesce(?, '')
                      and coalesce(artifact_hash, '') = coalesce(?, '')
                      and coalesce(workspace, '') = coalesce(?, '')
                      and coalesce(publisher, '') = coalesce(?, '')
                    """,
                    (
                        decision.harness,
                        decision.scope,
                        artifact_id,
                        artifact_hash,
                        workspace,
                        publisher,
                    ),
                )
                replaced += max(cursor.rowcount, 0)
            cursor = connection.execute(
                """
                insert into policy_decisions (
                  harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason,
                  owner, source, expires_at, policy_document_schema_version, policy_document_id,
                  policy_document_digest, policy_rule_id, policy_provenance_json, updated_at,
                  integrity_version, integrity_generation, payload_hash, payload_mac,
                  integrity_key_id, signed_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.harness,
                    decision.scope,
                    artifact_id,
                    artifact_hash,
                    workspace,
                    publisher,
                    decision.action,
                    decision.reason,
                    decision.owner,
                    decision.source,
                    decision.expires_at,
                    document.api_version,
                    document.metadata.id,
                    digest,
                    compiled.rule_id,
                    compiled.provenance_json,
                    now,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("Guard policy decision row was not inserted.")
            inserted_ids.add(cursor.lastrowid)

        if state.get("mode") == "protected":
            key, key_id = secret_material
            if key is not None and key_id is not None:
                trusted_state = self._load_policy_integrity_control_state(create=True)
                if trusted_state is not None:
                    next_control_state = self._advance_policy_integrity_generation(
                        connection,
                        now=now,
                        key=key,
                        key_id=key_id,
                        trusted_state=trusted_state,
                        force_sign_decision_ids=inserted_ids,
                    )

        if next_control_state is not None:
            self._finalize_policy_integrity_control_state(next_control_state)
        return PolicyDocumentImportResult(
            document_id=document.metadata.id,
            digest=digest,
            inserted=len(inserted_ids),
            replaced=replaced,
        )

    def policy_creation_import_args(
        self,
        document: GuardPolicyDocument,
        compiled_rows: tuple[CompiledPolicyRow, ...],
        *,
        mode: PolicyImportMode,
        now: str,
        approval_gate_grant: ApprovalGateGrant | None,
    ) -> dict[str, object]:
        """The import arguments for an approved MCP policy creation request.

        The resident's ``apply_mcp_policy_request`` writes these rows and
        moves the request to applied in one transaction. The caller holds the
        command-control authority lock.
        """
        if mode not in {"merge", "replace"}:
            raise ValueError("invalid_policy_import_mode")
        from .business_policy_document_import import has_business_rules, refuse_legacy_import_over_business_source

        if has_business_rules(document):
            # MCP must hold the source-owner lease outside its request/status
            # transaction and call apply_business_document_on_connection.
            raise ValueError("native_business_source_transaction_owner_required")
        normalized_rows = self._normalize_compiled_rows(compiled_rows)
        _validate_compiled_document_rows(document, compiled_rows)
        require_high_risk(
            self.guard_home,
            purpose="policy_import",
            **policy_import_approval_binding(document, mode),
            approval_gate_grant=approval_gate_grant,
            now=now,
        )
        refuse_legacy_import_over_business_source(cast("GuardStore", self))
        digest = policy_document_digest(document)
        return self.policy_import_args(document, normalized_rows, mode=mode, now=now, digest=digest)
