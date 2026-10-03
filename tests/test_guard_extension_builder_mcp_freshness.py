"""Generated catalog checks wait for projections without hiding policy assertions."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.extension_builder.render_tests import render_mcp_tests
from tests.extension_builder_support import make_kit


def test_mcp_catalog_freshness_gate_does_not_gate_tool_defaults(tmp_path: Path) -> None:
    kit = make_kit(tmp_path, "mcp", reviewed=True)
    namespace: dict[str, object] = {}
    exec(compile(render_mcp_tests(kit.discovery, kit.review), "generated_mcp.py", "exec"), namespace)
    catalog = namespace["test_generated_catalog_is_external_and_off"]
    defaults = namespace["test_generated_tool_defaults"]
    unknown = namespace["test_generated_unknown_tool_inherits"]
    assert callable(catalog) and callable(defaults) and callable(unknown)
    assert any(mark.name == "skipif" for mark in getattr(catalog, "pytestmark", []))
    assert all(mark.name != "skipif" for mark in getattr(defaults, "pytestmark", []))
    assert all(mark.name != "skipif" for mark in getattr(unknown, "pytestmark", []))
    # Once regenerated, the decorated assertion still checks actual catalog authority.
    entry = SimpleNamespace(to_dict=lambda: {"trust_class": "external", "activation": "opt-in", "enabled": False})
    namespace["BUILT_IN_COMMAND_EXTENSION_REGISTRY"] = SimpleNamespace(get=lambda _id: entry)
    catalog()
    namespace["BUILT_IN_COMMAND_EXTENSION_REGISTRY"] = SimpleNamespace(
        get=lambda _id: SimpleNamespace(
            to_dict=lambda: {"trust_class": "first-party", "activation": "default-on", "enabled": True}
        )
    )
    with pytest.raises(AssertionError):
        catalog()
