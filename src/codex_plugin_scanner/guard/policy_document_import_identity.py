"""Reject ambiguous portable rule identity reuse before local authority writes."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from .policy_document import GuardPolicyDocument
from .policy_document_types import CompiledPolicyRow, PolicyCompilationError

NormalizedPolicyRow = tuple[CompiledPolicyRow, str | None, str | None, str | None, str | None]
_SELECTOR_COLUMNS = ("harness", "scope", "artifact_id", "artifact_hash", "workspace", "publisher")


def validate_import_identities(
    normalized_rows: Sequence[NormalizedPolicyRow],
    current_rows: Iterable[Mapping[str, object]],
    *,
    document: GuardPolicyDocument,
    mode: str,
) -> None:
    rule_ids = [rule.id for rule in document.rules]
    if len(set(rule_ids)) != len(rule_ids):
        raise PolicyCompilationError("duplicate_policy_rule_identity", document.metadata.id)
    if mode == "replace":
        return
    incoming: dict[str, set[tuple[object, ...]]] = {}
    for compiled, artifact, digest, workspace, publisher in normalized_rows:
        decision = compiled.decision
        incoming.setdefault(compiled.rule_id, set()).add(
            (decision.harness, decision.scope, artifact, digest, workspace, publisher)
        )
    current: dict[str, set[tuple[object, ...]]] = {}
    for row in current_rows:
        rule_id = row.get("policy_rule_id")
        if row.get("source") != "policy-yaml-import" or rule_id not in incoming:
            continue
        assert isinstance(rule_id, str)
        if row.get("policy_document_id") != document.metadata.id:
            raise PolicyCompilationError("policy_rule_identity_conflict", rule_id)
        current.setdefault(rule_id, set()).add(tuple(row.get(field) for field in _SELECTOR_COLUMNS))
    for rule_id, selectors in current.items():
        if selectors != incoming[rule_id]:
            raise PolicyCompilationError("policy_rule_identity_conflict", rule_id)
