"""Bounded metadata from the inspected Composio discovery response profile.

This is provider-result evidence, not an authenticated host inventory event.
Neither session IDs nor connection-status labels establish account authority.
"""

from __future__ import annotations

import json
import math
import re
from copy import deepcopy
from dataclasses import dataclass

from ..strict_json_pairs import unique_json_object
from .composio_contract import composio_tool_role

_MAX_BYTES = 1_000_000
_MAX_ACTIONS = 1_000
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@dataclass(frozen=True, slots=True)
class ComposioActionSchema:
    toolkit: str
    tool_slug: str
    description: str
    input_schema: dict[str, object]
    full_schema: bool


def composio_discovered_actions(tool_name: str, response: object) -> tuple[ComposioActionSchema, ...] | None:
    """Accept only the observed successful response contract, never arbitrary nested JSON."""
    if composio_tool_role(tool_name) != "discovery":
        return None
    value = _response_object(response)
    if not isinstance(value, dict) or value.get("successful") is not True or value.get("error") is not None:
        return None
    data = value.get("data")
    if (
        not isinstance(data, dict)
        or ("success" in data and data["success"] is not True)
        or data.get("error") is not None
    ):
        return None
    schemas = data.get("tool_schemas")
    if not isinstance(schemas, dict) or not 1 <= len(schemas) <= _MAX_ACTIONS:
        return None
    actions: list[ComposioActionSchema] = []
    byte_count = 0
    for key, entry in schemas.items():
        if not isinstance(entry, dict):
            return None
        slug, toolkit, description = entry.get("tool_slug"), entry.get("toolkit"), entry.get("description", "")
        schema, full = entry.get("input_schema"), entry.get("hasFullSchema")
        if (
            not isinstance(slug, str)
            or not _TOKEN.fullmatch(slug)
            or key != slug
            or not isinstance(toolkit, str)
            or not _TOKEN.fullmatch(toolkit)
            or not isinstance(description, str)
            or not isinstance(full, bool)
            or not isinstance(schema, dict)
            or not _bounded_json_tree(schema)
        ):
            return None
        try:
            encoded = json.dumps(schema, allow_nan=False, ensure_ascii=True, separators=(",", ":"))
        except (ValueError, TypeError, RecursionError):
            return None
        description = description[:2_000]
        try:
            byte_count += len(encoded.encode("utf-8")) + len(description.encode("utf-8")) + len(slug) + len(toolkit)
        except UnicodeError:
            return None
        if byte_count > _MAX_BYTES:
            return None
        actions.append(ComposioActionSchema(toolkit, slug, description, deepcopy(schema), full))
    return tuple(actions)


def _response_object(response: object) -> object:
    if not isinstance(response, dict) or ("isError" in response and response["isError"] is not False):
        return None
    if "successful" in response:
        return response
    structured = response.get("structuredContent")
    if isinstance(structured, dict):
        return structured
    content = response.get("content")
    if not isinstance(content, list) or len(content) != 1:
        return None
    block = content[0]
    text = block.get("text") if isinstance(block, dict) and block.get("type") == "text" else None
    if not isinstance(text, str) or len(text) > _MAX_BYTES or len(text.encode("utf-8")) > _MAX_BYTES:
        return None
    try:
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, TypeError, RecursionError):
        return None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    return unique_json_object(pairs, "duplicate metadata key")


def _invalid_constant(value: str) -> object:
    raise ValueError("non-finite metadata value")


def _bounded_json_tree(value: object) -> bool:
    pending = [(value, 0)]
    nodes = chars = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > 20_000 or depth > 32:
            return False
        if isinstance(item, dict):
            if len(item) > 2_000 or any(not isinstance(key, str) for key in item):
                return False
            chars += sum(len(key) for key in item)
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            if len(item) > 2_000:
                return False
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            chars += len(item)
        elif (item is not None and not isinstance(item, (bool, int, float))) or (
            isinstance(item, float) and not math.isfinite(item)
        ):
            return False
        if chars > _MAX_BYTES:
            return False
    return True
