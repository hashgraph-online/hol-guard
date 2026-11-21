"""Exact document identity for the existing local approval gate."""

from __future__ import annotations

from typing import TypedDict

from .policy_document import GuardPolicyDocument, policy_document_digest


class PolicyImportApprovalBinding(TypedDict):
    action: str
    scope: str
    subject: str


def policy_import_approval_binding(
    document: GuardPolicyDocument,
    mode: str,
) -> PolicyImportApprovalBinding:
    if mode not in {"merge", "replace"}:
        raise ValueError("invalid_policy_import_mode")
    return {
        "action": "policy_document_import",
        "scope": "policy_document",
        "subject": f"policy-document:{mode}:{policy_document_digest(document)}",
    }
