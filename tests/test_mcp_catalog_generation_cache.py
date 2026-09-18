"""Complete catalog identity survives caching, aliasing, and replacement."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.proxy.runtime_mcp import _tool_catalog_fingerprint
from codex_plugin_scanner.guard.proxy.tool_catalog import ToolCatalog


def test_catalog_owns_nested_schemas_and_returns_detached_values() -> None:
    schema = {"type": "object", "properties": {"target": {"type": "string"}}}
    source = {"safe": {"input_schema": schema, "annotations": {"readOnlyHint": True}}}
    catalog = ToolCatalog(source)
    expected = _tool_catalog_fingerprint(source)
    assert _tool_catalog_fingerprint(catalog) == expected
    schema["properties"]["target"]["type"] = "number"
    detached = catalog["safe"]
    detached["annotations"]["readOnlyHint"] = False
    assert _tool_catalog_fingerprint(catalog) == expected
    assert catalog["safe"]["annotations"] == {"readOnlyHint": True}


def test_sibling_replacement_invalidates_complete_catalog_digest() -> None:
    catalog = ToolCatalog({"requested": {"description": "Read"}, "sibling": {"description": "Echo"}})
    original = _tool_catalog_fingerprint(catalog)
    catalog["sibling"] = {"description": "Execute command", "inputSchema": {"type": "object"}}
    replaced = _tool_catalog_fingerprint(catalog)
    assert original != replaced
    assert replaced == _tool_catalog_fingerprint(dict(catalog))
    del catalog["sibling"]
    assert _tool_catalog_fingerprint(catalog) != replaced


def test_lifecycle_state_and_all_advertised_fields_remain_bound() -> None:
    catalog = ToolCatalog({"safe": {"output_schema": {"type": "string"}, "_meta": {"version": 1}}})
    complete = _tool_catalog_fingerprint(catalog)
    assert _tool_catalog_fingerprint(catalog, state="pending") != complete
    assert _tool_catalog_fingerprint(catalog) == complete
    entry = catalog["safe"]
    entry["_meta"] = {"version": 2}
    catalog["safe"] = entry
    assert _tool_catalog_fingerprint(catalog) != complete


def test_nonfinite_replacement_does_not_poison_existing_generation() -> None:
    catalog = ToolCatalog({"safe": {"description": "Echo"}})
    original = _tool_catalog_fingerprint(catalog)
    with pytest.raises(ValueError):
        catalog["safe"] = {"limit": float("nan")}
    assert _tool_catalog_fingerprint(catalog) == original
