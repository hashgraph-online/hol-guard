"""Keep complete command rules associated while native snapshot row IDs change.

This pure adapter has no store writes, signature verification, capability
advertisement or authority admission. Its caller must authenticate the complete
original publication and supply the independently resolved target identity.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from .models import PolicyDecision
from .native_command_expression import materialize_native_command_projection
from .native_policy_authority_compile import compile_native_policy_row
from .native_policy_authority_contract import NativeScopedPolicyRow
from .native_policy_row_sort import native_policy_row_sort_key
from .policy_command_projection import CanonicalCommandProjection, CanonicalCommandSource
from .policy_document_types import PolicyCompilationError
from .policy_rule_identity import PolicyRuleIdentity
from .store_base import _canonical_utc_timestamp

NormalizedPolicyKeys = tuple[str | None, str | None, str | None, str | None]


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


@dataclass(frozen=True, slots=True)
class NativeBoundCommandRow:
    """One snapshot-local ID binds the selectors, expression and provenance."""

    row: NativeScopedPolicyRow
    identity: PolicyRuleIdentity
    source: CanonicalCommandSource
    expression_payload: str | None

    def expression_mapping(self) -> dict[str, object] | None:
        if self.expression_payload is None:
            return None
        return {
            "decision_id": self.row.decision_id,
            "expression": json.loads(self.expression_payload),
        }


@dataclass(frozen=True, slots=True)
class NativeCommandSourceRow:
    """Immutable row content before its final snapshot-local ID is assigned."""

    source: CanonicalCommandSource
    identity: PolicyRuleIdentity
    expression_payload: str | None
    _row_json: str

    def __post_init__(self) -> None:
        value = json.loads(self._row_json)
        if (
            not isinstance(value, dict)
            or _canonical(value) != self._row_json
            or "decision_id" in value
            or value.get("_command_expression_json") != self.expression_payload
            or value.get("_policy_rule_identity") != self.identity.to_selected_row_dict()
            or value.get("owner") != self.identity.rule_id
            or value.get("source") != "policy-bundle-canonical"
            or self.identity.policy_id != self.source.policy_id
            or self.identity.policy_version != self.source.policy_version
            or self.identity.publication != self.source.publication
        ):
            raise ValueError("native_command_row_association_invalid")

    def source_mapping(self) -> dict[str, object]:
        # Every call returns fresh nested values. The expression participates
        # in the same existing canonical sort and eventual signed input digest.
        return cast(dict[str, object], json.loads(self._row_json))

    @property
    def sort_key(self) -> str:
        return native_policy_row_sort_key(self.source_mapping())

    def bind_snapshot_row_id(self, decision_id: int) -> NativeBoundCommandRow:
        value = self.source_mapping()
        value["decision_id"] = decision_id
        return NativeBoundCommandRow(
            compile_native_policy_row(value), self.identity, self.source, self.expression_payload
        )


@dataclass(frozen=True, slots=True)
class NativeCommandSourceRows:
    # Retain the complete original projection, including inert/off-target
    # dispositions. Filtered native rows are never the source denominator.
    projection: CanonicalCommandProjection
    rows: tuple[NativeCommandSourceRow, ...]


def materialize_native_command_source_rows(
    projection: CanonicalCommandProjection,
    *,
    target_device_id: str,
    normalize_keys: Callable[[PolicyDecision], NormalizedPolicyKeys],
    materialized_at: str,
) -> NativeCommandSourceRows:
    """Validate the full source before target selection, preserving all AND fields.

    IDs are deliberately absent here: the caller combines these immutable
    records with other authenticated rows, sorts once, then binds each actual
    snapshot-local ID. A stripped expression selector must never be inserted
    into generic SQLite policy rows or admitted as a generic native rule.
    """
    source = projection.source
    if target_device_id != source.target_device_id:
        raise ValueError("native_command_target_identity_mismatch")
    native = materialize_native_command_projection(projection)
    rows: list[NativeCommandSourceRow] = []
    for projected, expression in zip(projection.rows, native.expression_payloads, strict=True):
        identity = projected.identity
        if (
            identity.policy_id != source.policy_id
            or identity.policy_version != source.policy_version
            or identity.publication != source.publication
            or projected.selector.source != "policy-bundle-canonical"
            or projected.selector.owner != identity.rule_id
        ):
            raise PolicyCompilationError("native_command_source_identity_mismatch", identity.rule_id)
        applicable = not projected.device_selectors or target_device_id in projected.device_selectors
        if projected.applicable_to_target is not applicable:
            raise PolicyCompilationError("native_command_target_disposition_mismatch", identity.rule_id)
        decision = projected.selector
        artifact, digest, workspace, publisher = normalize_keys(decision)
        value: dict[str, object] = {
            "harness": decision.harness,
            "scope": decision.scope,
            "artifact_id": artifact,
            "artifact_hash": digest,
            "workspace": workspace,
            "publisher": publisher,
            "exact_command_sha256": decision.exact_command_sha256,
            "action": decision.action,
            "reason": decision.reason,
            "owner": decision.owner,
            "source": decision.source,
            "expires_at": _canonical_utc_timestamp(decision.expires_at) if decision.expires_at is not None else None,
            "updated_at": materialized_at,
            "_policy_rule_identity": identity.to_selected_row_dict(),
        }
        if expression is not None:
            value["_command_expression_json"] = expression
        # Validate selectors/timestamps even for off-target rows. This temporary
        # validation ID is never returned or treated as a persisted row identity.
        compile_native_policy_row({**value, "decision_id": 1})
        if applicable:
            rows.append(NativeCommandSourceRow(source, identity, expression, _canonical(value)))
    return NativeCommandSourceRows(projection, tuple(rows))
