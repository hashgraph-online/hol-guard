"""Native portable-policy rows with the existing public Python DTOs."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict

from .models import PolicyDecision
from .native_policy_document import NativePolicyDocumentError, policy_query
from .policy_document import GuardPolicyDocument
from .policy_document_types import CompiledPolicyRow
from .policy_document_types import PolicyCompilationError as PolicyCompilationError


def build_policy_document_from_rows(
    rows: Iterable[Mapping[str, object]],
    *,
    document_id: str = "local-policy",
    name: str = "Local Guard policy",
    revision: int = 0,
    include_provenance: bool = False,
) -> GuardPolicyDocument:
    value = policy_query(
        "rows",
        {
            "rows": [dict(row) for row in rows],
            "document_id": document_id,
            "name": name,
            "revision": revision,
            "include_provenance": include_provenance,
        },
    )
    return GuardPolicyDocument.from_mapping(value)


def compile_policy_document(document: GuardPolicyDocument) -> tuple[CompiledPolicyRow, ...]:
    """Present the complete native compilation; transport pages bytes only."""
    items = policy_query("compile_dto", {"dto": asdict(document)})
    if not isinstance(items, list) or len(items) > 10_000:
        raise NativePolicyDocumentError("native_policy_document_rows_malformed")
    compiled = []
    for item in items:
        if (
            not isinstance(item, dict)
            or set(item) != {"decision", "rule_id", "provenance_json"}
            or not isinstance(item["rule_id"], str)
            or not isinstance(item["provenance_json"], str)
            or not isinstance(item["decision"], dict)
            or item["decision"].get("action") not in {"allow", "block"}
            or item["decision"].get("scope") not in {"artifact", "workspace", "publisher", "harness", "global"}
            or not isinstance(item["decision"].get("harness"), str)
            or any(value is not None and not isinstance(value, str) for value in item["decision"].values())
        ):
            raise NativePolicyDocumentError("native_policy_document_rows_malformed")
        try:
            compiled.append(
                CompiledPolicyRow(PolicyDecision(**item["decision"]), item["rule_id"], item["provenance_json"])
            )
        except TypeError as exc:
            raise NativePolicyDocumentError("native_policy_document_rows_malformed") from exc
    return tuple(compiled)
