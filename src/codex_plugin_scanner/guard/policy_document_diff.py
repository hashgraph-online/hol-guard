"""Native policy-change semantics and Python unified-diff presentation."""

from __future__ import annotations

import difflib

from .native_policy_document import NativePolicyDocumentError, policy_query
from .policy_document import GuardPolicyDocument
from .policy_document_types import PolicyDocumentDiff
from .policy_document_yaml import format_policy_document_yaml


def diff_policy_documents(
    baseline: GuardPolicyDocument,
    candidate: GuardPolicyDocument,
    *,
    baseline_name: str = "baseline",
    candidate_name: str = "candidate",
) -> PolicyDocumentDiff:
    text = "".join(
        difflib.unified_diff(
            format_policy_document_yaml(baseline).splitlines(keepends=True),
            format_policy_document_yaml(candidate).splitlines(keepends=True),
            fromfile=baseline_name,
            tofile=candidate_name,
        )
    )
    result = policy_query("diff", {"baseline": baseline.to_mapping(), "candidate": candidate.to_mapping()})
    expected = {
        "additions",
        "modifications",
        "removals",
        "impacted_scopes",
        "impacted_harnesses",
        "impacted_artifact_families",
        "conflict_warnings",
        "broadened_rules",
        "narrowed_rules",
        "unchanged_rules",
        "effective_action_changes",
        "broad_relaxing_changes",
    }
    if (
        not isinstance(result, dict)
        or set(result) != expected
        or not all(
            isinstance(values, list) and all(isinstance(value, str) for value in values) for values in result.values()
        )
    ):
        raise NativePolicyDocumentError("native_policy_document_diff_malformed")
    return PolicyDocumentDiff(changed=bool(text), text=text, **{key: tuple(value) for key, value in result.items()})
