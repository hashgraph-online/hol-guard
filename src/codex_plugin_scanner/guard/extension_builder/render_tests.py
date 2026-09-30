"""Generate MCP metadata tests; CLI behavior uses portable native fixtures."""

from __future__ import annotations

from .models import Discovery
from .python_literals import emit
from .review import Review


def _catalog_tests() -> list[str]:
    return [
        "def test_generated_catalog_is_external_and_off() -> None:",
        "    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_CATALOG_ID)",
        "    assert extension is not None",
        "    payload = extension.to_dict()",
        '    assert payload["trust_class"] == "external"',
        '    assert payload["activation"] == "opt-in"',
        '    assert payload["enabled"] is False',
        "",
        "",
    ]


def render_mcp_tests(discovery: Discovery, review: Review) -> str:
    decisions = review.by_id()
    cases = tuple((row.name, decisions[row.operation_id].state) for row in discovery.operations)
    return "\n".join(
        [
            '"""Generated MCP contract cases. No server or tool is invoked."""',
            "",
            "from __future__ import annotations",
            "",
            "import pytest",
            "",
            "from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY",
            "from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (",
            "    mcp_payload_for_catalog_id,",
            "    mcp_tool_state,",
            "    validate_mcp_contribution,",
            ")",
            "",
            *emit(discovery.metadata.catalog_id, prefix="_CATALOG_ID = "),
            *emit(cases, prefix="_TOOL_CASES = "),
            "",
            "",
            *_catalog_tests(),
            '@pytest.mark.parametrize(("tool_name", "expected"), _TOOL_CASES)',
            "def test_generated_tool_defaults(tool_name: str, expected: str) -> None:",
            "    payload = mcp_payload_for_catalog_id(_CATALOG_ID)",
            "    assert payload is not None",
            "    validate_mcp_contribution(payload)",
            "    assert mcp_tool_state(payload, tool_name) == expected",
            "",
            "",
            "def test_generated_unknown_tool_inherits() -> None:",
            "    payload = mcp_payload_for_catalog_id(_CATALOG_ID)",
            "    assert payload is not None",
            '    assert mcp_tool_state(payload, "z" * 129) == "inherit"',
            "",
        ]
    )
