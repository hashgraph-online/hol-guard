"""Bundled JSON contracts for the offline extension authoring compiler."""

from __future__ import annotations

from functools import lru_cache

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from .errors import BuilderError
from .io import object_value
from .validation import COMMAND_TOKEN_PATTERN, LAUNCHERS, OPTION_PATTERN, RISKS, SHA_PATTERN, SLUG_PATTERN

MAX_OPERATIONS = 256
MAX_MCP_TOOLS = 79
DISCOVERY_SCHEMA = "guard.extension-discovery.v1"
REVIEW_SCHEMA = "guard.extension-review.v1"
ADAPTERS = ("cli", "help", "click", "oclif", "mcp")
HINTS = ("read-name", "destructive-name", "read-only-hint", "destructive-hint", "network-hint")
LIMITATIONS = (
    "metadata-is-not-semantics",
    "unknown-cli-operations-review",
    "help-inventory-partial",
    "unrecognized-help-grammar",
    "click-multi-value-options",
    "click-runtime-plugins-not-inspected",
    "manifest-runtime-plugins-not-inspected",
    "mcp-inventory-is-snapshot",
    "mcp-tool-annotations-untrusted",
    "mcp-schemas-fingerprinted-not-executed",
)


def string_schema(maximum: int, *, minimum: int = 1, pattern: str | None = None) -> dict[str, object]:
    result: dict[str, object] = {"type": "string", "minLength": minimum, "maxLength": maximum}
    if pattern:
        result["pattern"] = f"^{pattern}$"
    return result


def array_schema(items: object, maximum: int, *, minimum: int = 0, unique: bool = True) -> dict[str, object]:
    return {"type": "array", "items": items, "minItems": minimum, "maxItems": maximum, "uniqueItems": unique}


def object_schema(properties: dict[str, object]) -> dict[str, object]:
    return {"type": "object", "additionalProperties": False, "properties": properties, "required": list(properties)}


_OPERATION_SCHEMA = object_schema(
    {
        "id": string_schema(21, pattern=r"(?:op|tool)-[a-f0-9]{16}"),
        "path": array_schema(string_schema(64, pattern=COMMAND_TOKEN_PATTERN), 8, unique=False),
        "name": string_schema(128, minimum=0),
        "flags": array_schema(string_schema(64, pattern=OPTION_PATTERN), 128),
        "optionsWithValues": array_schema(string_schema(64, pattern=OPTION_PATTERN), 128),
        "evidenceSha256": string_schema(64, pattern=SHA_PATTERN),
        "hints": array_schema({"enum": list(HINTS)}, len(HINTS)),
    }
)
DISCOVERY_JSON_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    **object_schema(
        {
            "schemaVersion": {"const": DISCOVERY_SCHEMA},
            "metadata": object_schema(
                {
                    "kind": {"enum": ["cli", "mcp"]},
                    "slug": string_schema(40, pattern=SLUG_PATTERN),
                    "name": string_schema(128),
                    "publisher": object_schema({"id": string_schema(128), "displayName": string_schema(128)}),
                    "homepage": string_schema(512),
                    "upstreamVersion": string_schema(64),
                    "executable": string_schema(64, minimum=0),
                    "launcher": {"enum": ["", *LAUNCHERS]},
                    "package": string_schema(256, minimum=0),
                }
            ),
            "adapter": {"enum": list(ADAPTERS)},
            "sourceSha256": string_schema(64, pattern=SHA_PATTERN),
            "operations": array_schema(_OPERATION_SCHEMA, MAX_OPERATIONS, minimum=1),
            "limitations": array_schema({"enum": list(LIMITATIONS)}, len(LIMITATIONS)),
            "digest": string_schema(64, pattern=SHA_PATTERN),
        }
    ),
}
REVIEW_JSON_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    **object_schema(
        {
            "schemaVersion": {"const": REVIEW_SCHEMA},
            "discoveryDigest": string_schema(64, pattern=SHA_PATTERN),
            "entries": {
                "type": "object",
                "maxProperties": MAX_OPERATIONS,
                "propertyNames": string_schema(21, pattern=r"(?:op|tool)-[a-f0-9]{16}"),
                "additionalProperties": object_schema(
                    {
                        "state": {"enum": ["review", "inherit", "allow", "block"]},
                        "reviewed": {"type": "boolean"},
                        "rationale": string_schema(512, minimum=0),
                        "evidenceUrl": string_schema(512, minimum=0),
                        "riskClasses": array_schema({"enum": list(RISKS)}, len(RISKS), minimum=1),
                        "saferAlternative": string_schema(256),
                        "safeArgv": array_schema(array_schema(string_schema(64), 16, minimum=1, unique=False), 16),
                    }
                ),
            },
        }
    ),
}


@lru_cache(maxsize=2)
def _validator(kind: str) -> Draft202012Validator:
    schema = DISCOVERY_JSON_SCHEMA if kind == "discovery" else REVIEW_JSON_SCHEMA
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_document(value: object, kind: str) -> dict[str, object]:
    try:
        _validator(kind).validate(value)
    except (ValidationError, RecursionError) as exc:
        raise BuilderError("invalid_contract", "Document violates the versioned extension authoring contract.") from exc
    return object_value(value)
