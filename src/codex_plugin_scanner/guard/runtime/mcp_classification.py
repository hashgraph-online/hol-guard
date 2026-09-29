"""Bounded, advisory MCP classification. Evidence never confers authority."""

from __future__ import annotations

from collections.abc import Mapping

# Deliberately exact, versioned mappings. Prefixes and friendly names cannot
# borrow a reviewed action's semantics. New provider actions remain unknown.
_REVIEWED: dict[str, tuple[str, str, str, str]] = {
    # Inspected hosted tool_schemas response, 2026-09-27. This mapping is an
    # advisory description of the provider's contract, not proof of behavior.
    "SLACK_SEARCH_MESSAGES": ("read", "private-content", "slack", "not-applicable"),
}
_CONTENT_FIELDS = frozenset({"body", "content", "text", "message", "messages", "attachment", "attachments"})
_DESTINATION_FIELDS = frozenset({"url", "uri", "endpoint", "webhook_url", "recipient", "recipients", "to", "email"})
_EXECUTION_FIELDS = frozenset({"command", "script", "code", "shell_command"})
_SECRET_FIELDS = frozenset({"password", "token", "api_key", "secret", "credential", "credentials"})


def classify_mcp_action(
    name: str,
    schema: object,
    *,
    provider: str | None = None,
    annotations: object = None,
    full_schema: bool = True,
) -> dict[str, object]:
    """Describe static evidence without reading field values or executing tools.

    Descriptions, defaults, URLs, and enum values are deliberately excluded.
    Schemas and annotations are provider-controlled; no result is a safe/allow
    recommendation, a verified destination, or an account binding.
    """
    mapping = _REVIEWED.get(name) if provider == "composio" else None
    effect, data, destination, reversibility = mapping or ("unknown", "unknown", "unknown", "unknown")
    evidence: list[str] = []
    warnings: list[str] = []
    if mapping:
        evidence.append("reviewed-provider-mapping:v1")
    fields, complete = _schema_fields(schema)
    if fields & _CONTENT_FIELDS:
        if data == "unknown":
            data = "content-possible"
        evidence.append("schema:content-fields")
    if fields & _SECRET_FIELDS:
        data = "credentials-possible"
        evidence.append("schema:credential-fields")
    if fields & _DESTINATION_FIELDS:
        destination = "caller-selected"
        evidence.append("schema:destination-fields")
        warnings.append("external-transfer-possible")
    if fields & _EXECUTION_FIELDS:
        effect = "execute"
        evidence.append("schema:execution-fields")
        warnings.append("arbitrary-execution-possible")
    claims = annotations if isinstance(annotations, dict) else {}
    hint_keys = ("readOnlyHint", "destructiveHint", "openWorldHint", "idempotentHint")
    if any(type(claims.get(key)) is bool for key in hint_keys):
        evidence.append("provider-annotations:unverified")
        if claims.get("readOnlyHint") is True and effect in {"write", "communicate", "delete", "administer", "execute"}:
            warnings.append("annotation-conflicts-with-evidence")
        if claims.get("destructiveHint") is True:
            warnings.append("provider-claims-destructive")
        # A benign claim cannot turn an unknown operation into read-only.
    if not complete or not full_schema:
        warnings.append("schema-incomplete")
    if effect == "unknown":
        warnings.append("effect-unresolved")
    return {
        "schema_version": "guard.mcp-classification.v1",
        "effect": effect,
        "data": data,
        "destination": destination,
        "reversibility": reversibility,
        "confidence": "reviewed-mapping" if mapping and complete and full_schema else "limited",
        "evidence": evidence,
        "warnings": warnings,
        "advisory_only": True,
    }


def _schema_fields(schema: object) -> tuple[set[str], bool]:
    if not isinstance(schema, Mapping):
        return set(), False
    pending: list[tuple[object, int]] = [(schema, 0)]
    seen: set[int] = set()
    fields: set[str] = set()
    nodes = 0
    while pending:
        node, depth = pending.pop()
        nodes += 1
        if nodes > 2048 or depth > 16:
            return fields, False
        if not isinstance(node, (dict, list)):
            continue
        if id(node) in seen:
            return fields, False
        seen.add(id(node))
        if isinstance(node, list):
            if len(node) > 256:
                return fields, False
            pending.extend((child, depth + 1) for child in node)
            continue
        if len(node) > 256:
            return fields, False
        properties = node.get("properties")
        if isinstance(properties, dict):
            if len(properties) > 256:
                return fields, False
            fields.update(key.casefold() for key in properties if isinstance(key, str) and len(key) <= 128)
            pending.extend((child, depth + 1) for child in properties.values())
        for key in ("items", "additionalProperties", "allOf", "anyOf", "oneOf", "$defs", "definitions"):
            child = node.get(key)
            if key in {"$defs", "definitions"} and isinstance(child, dict):
                if len(child) > 256:
                    return fields, False
                pending.extend((value, depth + 1) for value in child.values())
            elif isinstance(child, (dict, list)):
                pending.append((child, depth + 1))
        if "$ref" in node:
            # Resolving references or fetching remote schemas is outside this
            # bounded display classifier. Keep uncertainty explicit.
            return fields, False
    return fields, True
