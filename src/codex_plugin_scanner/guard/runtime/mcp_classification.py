"""Bounded, advisory MCP classification. Evidence never confers authority.

The description itself is built in the native runtime. This module carries the
declaration there and carries the answer back; it holds no mapping, no field
vocabulary and no traversal of its own, so a classification can never be
reconstructed here when the resident is unavailable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from ..native_mcp_classification import (
    McpClassificationUnavailableError,
    native_mcp_classifications,
)

__all__ = [
    "McpClassificationUnavailableError",
    "classify_mcp_action",
    "classify_mcp_actions",
]


def classify_mcp_actions(
    definitions: Sequence[Mapping[str, object]],
    *,
    guard_home: Path,
) -> list[dict[str, object] | None]:
    """Describe a batch of declarations in request order.

    Each definition carries ``name`` and ``schema``, optionally ``provider``,
    ``annotations`` and ``full_schema``. Raises when the resident cannot
    describe any of them, and gives ``None`` for a single declaration it
    cannot carry; no caller receives a locally invented description.
    """
    return native_mcp_classifications(definitions, guard_home=guard_home)


def classify_mcp_action(
    name: str,
    schema: object,
    *,
    guard_home: Path,
    provider: str | None = None,
    annotations: object = None,
    full_schema: bool = True,
) -> dict[str, object] | None:
    """Describe static evidence without reading field values or executing tools.

    Descriptions, defaults, URLs, and enum values are deliberately excluded.
    Schemas and annotations are provider-controlled; no result is a safe/allow
    recommendation, a verified destination, or an account binding.
    """
    described = classify_mcp_actions(
        [
            {
                "name": name,
                "schema": schema,
                "provider": provider,
                "annotations": annotations,
                "full_schema": full_schema,
            }
        ],
        guard_home=guard_home,
    )
    return described[0]
