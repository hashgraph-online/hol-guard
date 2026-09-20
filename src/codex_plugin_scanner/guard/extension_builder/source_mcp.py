"""Validate exported MCP tool inventories without opening a connection or calling tools."""

from __future__ import annotations

from typing import cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .errors import BuilderError
from .io import list_value, object_value
from .models import Operation, make_operation
from .source_cli import name_hints
from .validation import TOOL_PATTERN, token

_DIALECTS = frozenset({"https://json-schema.org/draft/2020-12/schema", "http://json-schema.org/draft/2020-12/schema"})
_HINT_FIELDS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def _schema(value: object, *, input_schema: bool) -> None:
    schema = object_value(value)
    if input_schema and schema.get("type") != "object":
        raise BuilderError("mcp_schema", "MCP inputSchema must explicitly describe an object.")
    pending: list[object] = [schema]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            row = cast(dict[str, object], current)
            for key, child in row.items():
                if key in {"$ref", "$dynamicRef"} and (not isinstance(child, str) or not child.startswith("#")):
                    raise BuilderError(
                        "mcp_schema_reference", "External schema references are not resolved or accepted."
                    )
                if key == "$schema" and (not isinstance(child, str) or child not in _DIALECTS):
                    raise BuilderError(
                        "mcp_schema_dialect", "Only the bundled JSON Schema 2020-12 dialect is supported."
                    )
                pending.append(child)
        elif isinstance(current, list):
            pending.extend(cast(list[object], current))
    try:
        Draft202012Validator.check_schema(schema)
    except (SchemaError, RecursionError) as exc:
        raise BuilderError("mcp_schema", "MCP tool metadata contains an invalid JSON Schema.") from exc


def _result(value: object) -> dict[str, object]:
    row = object_value(value)
    if "error" in row:
        raise BuilderError("mcp_response", "An MCP error response cannot be used as a tool inventory.")
    if "result" in row:
        if row.get("jsonrpc") != "2.0" or "id" not in row:
            raise BuilderError("mcp_response", "Expected a JSON-RPC 2.0 response envelope.")
        row = object_value(row["result"])
    if row.get("resultType", "complete") != "complete" or "tools" not in row:
        raise BuilderError("mcp_response", "Expected a completed MCP tools/list response.")
    return row


def _cursor(value: object) -> str:
    # Cursors are protocol data: even an empty or whitespace-bearing value is
    # a continuation token. Never apply display-text normalization to them.
    if not isinstance(value, str) or len(value) > 1024:
        raise BuilderError("mcp_pagination", "Pagination cursors must be strings within the supported length limit.")
    return value


def _pages(value: object) -> tuple[dict[str, object], ...]:
    document = object_value(value)
    if "pages" not in document:
        result = _result(document)
        if "nextCursor" in result:
            raise BuilderError("mcp_pagination", "Tool inventory is incomplete; export every cursor-linked page.")
        return (result,)
    if set(document) != {"pages"}:
        raise BuilderError("mcp_pagination", "A paginated export must contain only its pages array.")
    pages = list_value(document["pages"], maximum=80)
    if not pages:
        raise BuilderError("mcp_pagination", "A paginated export must contain at least one page.")
    expected: str | None = None
    seen: set[str] = set()
    results: list[dict[str, object]] = []
    for index, page in enumerate(pages):
        item = object_value(page)
        if set(item) != {"requestCursor", "response"} or item["requestCursor"] != expected:
            raise BuilderError("mcp_pagination", "Tool inventory pages do not form a complete ordered cursor chain.")
        row = _result(item["response"])
        results.append(row)
        if "nextCursor" not in row:
            if index != len(pages) - 1:
                raise BuilderError("mcp_pagination", "Inventory contains pages after a terminal response.")
            expected = None
            continue
        next_cursor = _cursor(row["nextCursor"])
        if next_cursor in seen:
            raise BuilderError("mcp_pagination", "Inventory repeats a pagination cursor.")
        seen.add(next_cursor)
        expected = next_cursor
    if expected is not None:
        raise BuilderError("mcp_pagination", "Inventory ends before its final tool-list page.")
    return tuple(results)


def mcp_surface(value: object) -> tuple[tuple[Operation, ...], tuple[str, ...]]:
    operations: list[Operation] = []
    for page in _pages(value):
        for value_row in list_value(page["tools"], maximum=79):
            if len(operations) >= 79:
                raise BuilderError(
                    "mcp_tool_limit", "A contribution supports at most 79 named tools plus the inherit fallback."
                )
            row = object_value(value_row)
            name = token(row.get("name"), pattern=TOOL_PATTERN, maximum=128)
            _schema(row.get("inputSchema"), input_schema=True)
            if "outputSchema" in row:
                _schema(row["outputSchema"], input_schema=False)
            annotations = object_value(row.get("annotations", {}))
            if any(key in annotations and not isinstance(annotations[key], bool) for key in _HINT_FIELDS):
                raise BuilderError("mcp_annotation", "Known MCP behavioral annotations must be Boolean hints.")
            hints = list(name_hints((name,)))
            if annotations.get("readOnlyHint") is True:
                hints.append("read-only-hint")
            if annotations.get("destructiveHint") is True:
                hints.append("destructive-hint")
            if annotations.get("openWorldHint") is True:
                hints.append("network-hint")
            operations.append(make_operation("mcp", name=name, evidence=row, hints=tuple(hints)))
    return tuple(operations), (
        "mcp-inventory-is-snapshot",
        "mcp-tool-annotations-untrusted",
        "mcp-schemas-fingerprinted-not-executed",
    )
