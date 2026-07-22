"""Atomic canonical policy document persistence."""

from __future__ import annotations

import sqlite3

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false
from dataclasses import dataclass
from typing import Literal

from .approval_gate import ApprovalGateGrant, require_high_risk
from .policy_authority import validate_policy_write_authority
from .policy_document import GuardPolicyDocument, policy_document_digest
from .policy_document_io import CompiledPolicyRow
from .store_base import _validate_scoped_policy_artifact_target

PolicyImportMode = Literal["merge", "replace"]


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

        normalized_rows = self._normalize_compiled_rows(compiled_rows)

        require_high_risk(
            self.guard_home,
            purpose="policy_import",
            approval_gate_grant=approval_gate_grant,
            now=now,
        )

        digest = policy_document_digest(document)
        secret_material = self._policy_integrity_secret_material(create=True)
        with self._connect() as connection:
            connection.execute("begin immediate")
            result = self._import_policy_rows_on_connection(
                connection,
                document=document,
                compiled_rows=compiled_rows,
                normalized_rows=normalized_rows,
                mode=mode,
                now=now,
                digest=digest,
                secret_material=secret_material,
            )
            connection.commit()

        return result

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

        The caller is responsible for commit/rollback.  This method is the
        shared row-write core used by both ``import_policy_document`` and
        ``apply_policy_creation_request``.
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

    def apply_policy_creation_request(
        self,
        document: GuardPolicyDocument,
        compiled_rows: tuple[CompiledPolicyRow, ...],
        *,
        mode: PolicyImportMode,
        now: str,
        approval_gate_grant: ApprovalGateGrant | None,
        connection: sqlite3.Connection,
    ) -> PolicyDocumentImportResult:
        """Apply policy rows on a caller-owned transaction (BEGIN IMMEDIATE).

        Used by the MCP policy creation path so that policy row writes and
        the pending-request status transition commit atomically in one
        shared transaction.  The caller owns commit/rollback.
        """
        if mode not in {"merge", "replace"}:
            raise ValueError("invalid_policy_import_mode")
        normalized_rows = self._normalize_compiled_rows(compiled_rows)
        require_high_risk(
            self.guard_home,
            purpose="policy_import",
            approval_gate_grant=approval_gate_grant,
            now=now,
        )
        digest = policy_document_digest(document)
        secret_material = self._policy_integrity_secret_material(create=True)
        return self._import_policy_rows_on_connection(
            connection,
            document=document,
            compiled_rows=compiled_rows,
            normalized_rows=normalized_rows,
            mode=mode,
            now=now,
            digest=digest,
            secret_material=secret_material,
        )
