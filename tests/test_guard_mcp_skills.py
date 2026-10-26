from __future__ import annotations

from codex_plugin_scanner.guard.runtime.mcp_skills import mcp_skills_declared

_CAPABILITIES = {"resources": {}, "extensions": {"io.modelcontextprotocol/skills": {}}}


def test_declaration_requires_resources_and_actual_extension_not_tool_names():
    assert mcp_skills_declared(_CAPABILITIES, protocol_version="2026-07-28")
    assert mcp_skills_declared(_CAPABILITIES, protocol_version="2027-01-01")
    for capabilities in ({}, {"tools": {}}, {"extensions": _CAPABILITIES["extensions"]}, {"resources": {}}):
        assert not mcp_skills_declared(capabilities, protocol_version="2026-07-28")
    assert not mcp_skills_declared(_CAPABILITIES, protocol_version="2025-11-25")
    for invalid in ("2026-07-27", "2026-13-01", "2026-07-28-extra", "20260728"):
        assert not mcp_skills_declared(_CAPABILITIES, protocol_version=invalid)
