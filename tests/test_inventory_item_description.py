from __future__ import annotations

from codex_plugin_scanner.guard.inventory_item_description import resolve_inventory_item_description


def test_resolve_inventory_item_description_prefers_metadata_description() -> None:
    result = resolve_inventory_item_description(
        harness="antigravity",
        item_kind="plugin",
        display_name="Pyrefly",
        metadata={"description": "Fast Python type checker and language server."},
        publisher="meta",
    )

    assert result == "Fast Python type checker and language server."


def test_resolve_inventory_item_description_uses_explicit_mcp_tool_description() -> None:
    result = resolve_inventory_item_description(
        harness="cursor",
        item_kind="mcp_tool",
        display_name="read_file",
        metadata={"toolName": "read_file"},
        explicit_description="Read a file from the workspace.",
    )

    assert result == "Read a file from the workspace."


def test_resolve_inventory_item_description_falls_back_for_plugins() -> None:
    result = resolve_inventory_item_description(
        harness="antigravity",
        item_kind="plugin",
        display_name="meta.pyrefly",
        metadata={},
        publisher="meta",
    )

    assert "meta.pyrefly" in result
    assert "extension" in result
    assert "meta" in result
    assert "antigravity" in result


def test_resolve_inventory_item_description_truncates_long_text() -> None:
    long_text = "a" * 600
    result = resolve_inventory_item_description(
        harness="codex",
        item_kind="skill",
        display_name="Long Skill",
        metadata={"description": long_text},
    )

    assert len(result) == 500
    assert result.endswith("…")
