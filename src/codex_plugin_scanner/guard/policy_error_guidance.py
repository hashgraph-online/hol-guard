"""Bounded public guidance for policy document failures; never format raw values."""

from __future__ import annotations

import re

from .policy_document_types import PolicyCompilationError
from .policy_document_yaml import MAX_DIAGNOSTICS, JsonPath, PolicyDocumentError

_RULE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
# Stop at an unknown segment: extension names and arbitrary dictionary keys can
# contain credentials. A schema field name alone is safe to show.
_PUBLIC_FIELDS = frozenset(
    {
        "apiVersion",
        "kind",
        "metadata",
        "id",
        "name",
        "revision",
        "spec",
        "defaults",
        "mode",
        "defaultAction",
        "rolloutState",
        "rules",
        "enabled",
        "effect",
        "match",
        "lifetime",
        "expiresAt",
        "provenance",
        "source",
        "createdAt",
        "createdBy",
        "artifacts",
        "harnesses",
        "publishers",
        "tools",
        "workspaces",
        "devices",
        "commands",
        "conditions",
        "combinator",
        "field",
        "operator",
        "value",
    }
)
_COMPILE_GUIDANCE: dict[str, tuple[str, str]] = {
    "unsupported_policy_match": (
        "match",
        "Use supported artifacts, harnesses, publishers, tools, or workspaces only if they preserve "
        "the intended target; otherwise use a runtime that supports this matcher.",
    ),
    "unsupported_policy_lifetime": (
        "lifetime",
        "Use permanent or until only if that preserves the intended lifetime; otherwise use a runtime "
        "that supports this lifetime.",
    ),
    "policy_compilation_limit": (
        "match",
        "Reduce selector expansion to at most 10,000 rows without broadening the intended targets.",
    ),
    "unsupported_policy_effect": (
        "effect",
        "Use a supported allow, block, review, or inert ignore effect while preserving the intended behavior.",
    ),
    "unsupported_policy_device_selector": (
        "match.devices",
        "Deliver device-targeted policy through Cloud using installation IDs; "
        "a local import cannot apply device selection.",
    ),
    "command_expression_requires_guard_3_1_runtime": (
        "match.commands",
        "Use a compatible command-policy runtime; command expressions cannot become local policy rows.",
    ),
    "invalid_policy_expiry": ("lifetime.expiresAt", "Set a valid UTC expiry for an until lifetime."),
    "invalid_policy_match_selector": ("match", "Use non-empty string selectors supported by the target runtime."),
    "unsupported_policy_scope_projection": (
        "match",
        "Use a supported scope combination that preserves every intended restriction; do not discard a selector.",
    ),
    "policy_rule_identity_conflict": ("id", "Use distinct rule IDs or review a replacement import."),
}


def _public_path(path: JsonPath) -> str:
    result = "$"
    for segment in path[:12]:
        if isinstance(segment, int) and not isinstance(segment, bool) and 0 <= segment <= 1000:
            result += f"[{segment}]"
        elif isinstance(segment, str) and segment in _PUBLIC_FIELDS:
            result += f".{segment}"
        else:
            break
    return result


def _public_code(code: str) -> str:
    # Command regex diagnostics append an engine exception after a stable code.
    candidate = code.partition(":")[0]
    return candidate if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", candidate) else "invalid_policy_document"


def _parse_remediation(code: str) -> str:
    if code == "forbidden_sensitive_field":
        return "Remove credential fields from the policy and use the configured credential store."
    if code.startswith("limit_") or code == "yaml_resource_limit":
        return (
            "Reduce the document to the published policy size and collection limits; "
            "split rules without broadening their targets."
        )
    if code == "duplicate_rule_id":
        return "Assign a distinct stable ID to each rule."
    return "Correct the indicated field using the GuardPolicy schema, then validate the file again."


def public_policy_document_error(error: PolicyCompilationError | PolicyDocumentError) -> dict[str, object]:
    diagnostics: list[dict[str, object]] = []
    if isinstance(error, PolicyCompilationError):
        field, remediation = _COMPILE_GUIDANCE.get(
            error.code,
            (
                "",
                "Review this rule against the target runtime's supported policy capabilities, then validate again.",
            ),
        )
        diagnostics.append(
            {
                "code": error.code,
                "rule_id": error.rule_id if _RULE_ID.fullmatch(error.rule_id) else None,
                "path": "$.spec.rules[*]" + (f".{field}" if field else ""),
                "remediation": remediation,
            }
        )
        code = error.code
    else:
        for diagnostic in error.diagnostics[:MAX_DIAGNOSTICS]:
            diagnostic_code = _public_code(diagnostic.code)
            diagnostics.append(
                {
                    "code": diagnostic_code,
                    "rule_id": None,
                    "path": _public_path(diagnostic.path),
                    "line": diagnostic.line,
                    "column": diagnostic.column,
                    "remediation": _parse_remediation(diagnostic_code),
                }
            )
        # Preserve the existing CLI error code; concrete parser codes are additive.
        code = "PolicyDocumentError"
    first = diagnostics[0] if diagnostics else {}
    location = first.get("path", "$")
    rule_id = first.get("rule_id")
    subject = f"Rule {rule_id}" if rule_id else "Policy"
    message = (
        f"{subject} could not be validated at {location}. {first.get('remediation', 'Validate the policy file again.')}"
    )
    return {
        "error": code,
        "code": first.get("code", code),
        "rule_id": rule_id,
        "field_path": location,
        "remediation": first.get("remediation", "Validate the policy file again."),
        "message": message,
        "diagnostics": diagnostics,
    }
