"""MCP pagination cursors are opaque values, not display metadata or terminal markers."""

from __future__ import annotations

from dataclasses import asdict

import pytest

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.source_mcp import mcp_surface

_CURSORS = ("", " ", "  next  ", "\n\t", "opaque:\u754c", "x" * 1024)


def _export(cursor: object) -> dict[str, object]:
    return {
        "pages": [
            {
                "requestCursor": None,
                "response": {
                    "tools": [{"name": "read_item", "inputSchema": {"type": "object"}}],
                    "nextCursor": cursor,
                },
            },
            {"requestCursor": cursor, "response": {"tools": []}},
        ]
    }


@pytest.mark.parametrize("cursor", _CURSORS, ids=("empty", "space", "padded", "controls", "unicode", "max-length"))
def test_opaque_cursor_is_preserved_until_the_terminal_page(cursor: str) -> None:
    operations, _ = mcp_surface(_export(cursor))
    assert [operation.name for operation in operations] == ["read_item"]


@pytest.mark.parametrize("cursor", _CURSORS, ids=("empty", "space", "padded", "controls", "unicode", "max-length"))
def test_every_cursor_including_empty_requires_its_next_page(cursor: str) -> None:
    payload = _export(cursor)
    pages = payload["pages"]
    assert isinstance(pages, list)
    pages.pop()
    with pytest.raises(BuilderError, match="final tool-list page"):
        mcp_surface(payload)


@pytest.mark.parametrize("cursor", ("", " ", "opaque"))
def test_opaque_cursor_reuse_is_rejected(cursor: str) -> None:
    payload = _export(cursor)
    pages = payload["pages"]
    assert isinstance(pages, list)
    pages[1]["response"]["nextCursor"] = cursor
    with pytest.raises(BuilderError, match="repeats a pagination cursor"):
        mcp_surface(payload)


@pytest.mark.parametrize("cursor", (" ", "  next  ", "\n\t"))
def test_cursor_whitespace_is_not_normalized(cursor: str) -> None:
    payload = _export(cursor)
    pages = payload["pages"]
    assert isinstance(pages, list)
    pages[1]["requestCursor"] = cursor.strip()
    with pytest.raises(BuilderError, match="ordered cursor chain"):
        mcp_surface(payload)


@pytest.mark.parametrize(
    "cursor",
    (None, True, 0, [], {}, b"bytes", "x" * 1025),
    ids=("null", "boolean", "integer", "array", "object", "bytes", "too-long"),
)
def test_cursor_type_and_length_limits_still_apply(cursor: object) -> None:
    with pytest.raises(BuilderError) as caught:
        mcp_surface(_export(cursor))
    assert caught.value.code == "mcp_pagination"
    assert str(cursor) not in str(caught.value)


def test_cursor_contents_are_not_published_as_operation_metadata() -> None:
    cursor = "PRIVATE_CURSOR_SENTINEL ; $(not-a-command)\n"
    operations, _ = mcp_surface(_export(cursor))
    assert "PRIVATE_CURSOR_SENTINEL" not in repr([asdict(operation) for operation in operations])
