from __future__ import annotations

import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.runtime import local_mcp_stdio
from codex_plugin_scanner.guard.runtime.local_mcp_stdio import (
    MAX_MCP_PROBE_TOOLS,
    run_mcp_catalog,
    run_mcp_tools_list,
)


def _server(
    tmp_path: Path,
    pages: dict[str, dict[str, object]],
    *,
    discovery: dict[str, object] | None = None,
    silent_discovery: bool = False,
    legacy_version: str = "2024-11-05",
    notify_before_cursor: str | None = None,
    skills: list[dict[str, object]] | None = None,
) -> list[str]:
    server = tmp_path / "catalog_server.py"
    server.write_text(
        f"""
import json
import sys

pages = json.loads({json.dumps(pages)!r})
discovery = json.loads({json.dumps(discovery)!r})
skills = json.loads({json.dumps(skills)!r})
for line in sys.stdin:
    request = json.loads(line)
    with open({str(tmp_path / 'requests.jsonl')!r}, "a", encoding="utf-8") as log:
        print(json.dumps(request), file=log)
    method = request.get("method")
    if method == "server/discover":
        if {silent_discovery!r}:
            continue
        response = discovery or {{"error": {{"code": -32601, "message": "Method not found"}}}}
    elif method == "initialize":
        response = {{
            "result": {{
                "protocolVersion": {legacy_version!r},
                "capabilities": {{"tools": {{}}}},
                "serverInfo": {{"name": "catalog-fixture", "version": "1"}},
            }}
        }}
    elif method == "tools/list":
        cursor = request.get("params", {{}}).get("cursor", "<root>")
        if cursor == {notify_before_cursor!r}:
            print(json.dumps({{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}}), flush=True)
        response = (
            {{"result": pages[cursor]}}
            if cursor in pages
            else {{"error": {{"code": -32602, "message": "Unknown cursor"}}}}
        )
    elif method == "skills/list":
        response = {{"result": {{
            "resultType": "complete", "skills": skills or [], "ttlMs": 0, "cacheScope": "private"
        }}}}
    elif "id" in request:
        response = {{"error": {{"code": -32601, "message": "Method not found"}}}}
    else:
        continue
    print(json.dumps({{"jsonrpc": "2.0", "id": request["id"], **response}}), flush=True)
""",
        encoding="utf-8",
    )
    return [sys.executable, str(server)]


def _tools(count: int, *, prefix: str = "tool") -> list[dict[str, object]]:
    return [
        {"name": f"{prefix}_{index}", "inputSchema": {"type": "object"}}
        for index in range(count)
    ]


def test_tool_limit_does_not_report_a_partial_catalog_as_complete(tmp_path: Path) -> None:
    argv = _server(
        tmp_path,
        {
            "<root>": {"tools": _tools(MAX_MCP_PROBE_TOOLS), "nextCursor": "more"},
            "more": {"tools": _tools(1, prefix="remaining")},
        },
    )
    assert run_mcp_tools_list(argv) is None


def test_page_limit_does_not_report_a_partial_catalog_as_complete(tmp_path: Path) -> None:
    pages = {
        "<root>" if index == 0 else f"page-{index}": {
            "tools": _tools(1, prefix=f"page_{index}"),
            "nextCursor": f"page-{index + 1}",
        }
        for index in range(9)
    }
    assert run_mcp_tools_list(_server(tmp_path, pages)) is None


def test_pagination_cursor_is_preserved_as_an_opaque_value(tmp_path: Path) -> None:
    first = _tools(1, prefix="first")
    second = _tools(1, prefix="second")
    argv = _server(
        tmp_path,
        {"<root>": {"tools": first, "nextCursor": " next "}, " next ": {"tools": second}},
    )
    assert run_mcp_tools_list(argv) == [*first, *second]


def test_invalid_cursor_cannot_mark_a_catalog_complete(tmp_path: Path) -> None:
    argv = _server(tmp_path, {"<root>": {"tools": _tools(1), "nextCursor": 7}})
    assert run_mcp_tools_list(argv) is None


def test_partial_catalog_retains_bounded_tools_and_coverage(tmp_path: Path) -> None:
    tools = _tools(MAX_MCP_PROBE_TOOLS + 1)
    catalog = run_mcp_catalog(_server(tmp_path, {"<root>": {"tools": tools}}))
    assert catalog.tools == tuple(tools[:MAX_MCP_PROBE_TOOLS])
    assert not catalog.complete
    assert catalog.reason == "tool_limit"
    assert catalog.pages == 1


def test_exact_tool_limit_can_be_complete(tmp_path: Path) -> None:
    tools = _tools(MAX_MCP_PROBE_TOOLS)
    catalog = run_mcp_catalog(_server(tmp_path, {"<root>": {"tools": tools}}))
    assert catalog.complete
    assert catalog.reason is None
    assert catalog.tools == tuple(tools)


def test_duplicate_tool_page_does_not_publish_ambiguous_metadata(tmp_path: Path) -> None:
    original = _tools(1)
    changed = [{"name": "tool_0", "description": "different", "inputSchema": {"type": "object"}}]
    catalog = run_mcp_catalog(
        _server(tmp_path, {"<root>": {"tools": original, "nextCursor": "second"}, "second": {"tools": changed}})
    )
    assert catalog.tools == tuple(original)
    assert not catalog.complete
    assert catalog.reason == "duplicate_tool"


def test_failed_followup_retains_successful_page(tmp_path: Path) -> None:
    tools = _tools(1)
    catalog = run_mcp_catalog(_server(tmp_path, {"<root>": {"tools": tools, "nextCursor": "missing"}}))
    assert catalog.tools == tuple(tools)
    assert not catalog.complete
    assert catalog.reason == "list_failed"


def test_repeated_cursor_is_a_partial_catalog(tmp_path: Path) -> None:
    first, second = _tools(1, prefix="first"), _tools(1, prefix="second")
    catalog = run_mcp_catalog(
        _server(
            tmp_path,
            {
                "<root>": {"tools": first, "nextCursor": "again"},
                "again": {"tools": second, "nextCursor": "again"},
            },
        )
    )
    assert catalog.tools == tuple([*first, *second])
    assert not catalog.complete
    assert catalog.reason == "repeated_cursor"


def test_invalid_page_is_not_partially_published(tmp_path: Path) -> None:
    catalog = run_mcp_catalog(_server(tmp_path, {"<root>": {"tools": [*_tools(1), {"name": " "}]}}))
    assert catalog.tools == ()
    assert not catalog.complete
    assert catalog.reason == "invalid_tool"


def _discovery(versions: list[str] | None = None) -> dict[str, object]:
    return {
        "result": {
            "resultType": "complete",
            "supportedVersions": ["2026-07-28"] if versions is None else versions,
            "capabilities": {"tools": {}},
            "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "modern-fixture", "version": "1"}},
        }
    }


def _requests(tmp_path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in (tmp_path / "requests.jsonl").read_text().splitlines()]


def test_declared_skills_are_listed_on_real_stdio_without_fetching_content(tmp_path: Path):
    discovery = _discovery()
    discovery["result"]["capabilities"].update(
        resources={}, extensions={"io.modelcontextprotocol/skills": {}},
    )
    skill = {"uri": "skill://report/SKILL.md", "frontmatter": {"name": "report", "description": "Synthetic workflow"},
             "resources": [{"uri": "skill://report/SKILL.md", "digest": "sha256:" + "a" * 64, "size": 50}]}
    catalog = run_mcp_catalog(_server(tmp_path, {"<root>": {
        "resultType": "complete", "tools": _tools(1),
    }}, discovery=discovery, skills=[skill]), connection_identity_hash="b" * 64)
    assert catalog.complete
    assert catalog.skills_complete is True
    assert len(catalog.skills) == 1
    assert catalog.skills[0]["connection_identity_hash"] == "b" * 64
    assert catalog.skills[0]["activation_supported"] is False
    methods = [request["method"] for request in _requests(tmp_path)]
    assert methods == ["server/discover", "tools/list", "skills/list"]
    assert "resources/read" not in methods


def test_failed_skill_metadata_does_not_turn_tools_into_an_empty_catalog(tmp_path: Path):
    discovery = _discovery()
    discovery["result"]["capabilities"].update(
        resources={}, extensions={"io.modelcontextprotocol/skills": {}},
    )
    catalog = run_mcp_catalog(_server(tmp_path, {"<root>": {
        "resultType": "complete", "tools": _tools(1),
    }}, discovery=discovery, skills=[{"uri": "skill://invalid/SKILL.md"}]), connection_identity_hash="b" * 64)
    assert catalog.complete and len(catalog.tools) == 1
    assert catalog.skills_complete is False
    assert catalog.skills_reason == "invalid_skill_frontmatter"


def test_modern_discovery_uses_request_metadata_without_initialization(tmp_path: Path) -> None:
    first, second = _tools(1, prefix="first"), _tools(1, prefix="second")
    catalog = run_mcp_catalog(
        _server(
            tmp_path,
            {
                "<root>": {"resultType": "complete", "tools": first, "nextCursor": " next "},
                " next ": {"resultType": "complete", "tools": second},
            },
            discovery=_discovery(),
        )
    )
    assert catalog.complete
    assert catalog.protocol_version == "2026-07-28"
    assert catalog.server_info == {"name": "modern-fixture", "version": "1"}
    assert catalog.capabilities == {"tools": {}}
    assert catalog.tools == tuple([*first, *second])
    requests = _requests(tmp_path)
    assert [request["method"] for request in requests] == ["server/discover", "tools/list", "tools/list"]
    for request in requests:
        meta = request["params"]["_meta"]
        assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {}
    assert requests[-1]["params"]["cursor"] == " next "


def test_cache_freshness_uses_earliest_page_and_preserves_private_scope(tmp_path: Path) -> None:
    catalog = run_mcp_catalog(_server(tmp_path, {
        "<root>": {"resultType": "complete", "tools": _tools(1), "nextCursor": "next",
                   "ttlMs": 100_000, "cacheScope": "private"},
        "next": {"resultType": "complete", "tools": _tools(1, prefix="next"),
                 "ttlMs": 5_000, "cacheScope": "private"},
    }, discovery=_discovery()))
    assert catalog.complete and catalog.cache_scope == "private"
    assert 0 < catalog.cache_ttl_ms <= 5_000


def test_conflicting_page_scope_cannot_publish_a_complete_catalog(tmp_path: Path) -> None:
    catalog = run_mcp_catalog(_server(tmp_path, {
        "<root>": {"tools": _tools(1), "nextCursor": "next", "ttlMs": 100_000, "cacheScope": "private"},
        "next": {"tools": _tools(1, prefix="next"), "ttlMs": 5_000, "cacheScope": "public"},
    }))
    assert not catalog.complete and catalog.reason == "inconsistent_cache_scope"
    assert catalog.tools == tuple(_tools(1))


def test_change_notification_during_pagination_invalidates_partial_snapshot(tmp_path: Path) -> None:
    catalog = run_mcp_catalog(_server(tmp_path, {
        "<root>": {"tools": _tools(1), "nextCursor": "next"},
        "next": {"tools": _tools(1, prefix="next")},
    }, notify_before_cursor="next"))
    assert not catalog.complete and catalog.reason == "catalog_changed"
    assert catalog.tools == tuple(_tools(1))


def test_rpc_parser_rejects_ambiguous_keys_and_nonfinite_schema_values() -> None:
    for raw in [
        b'{"jsonrpc":"2.0","id":2,"result":{"tools":[]},"result":{"tools":[{"name":"hidden"}]}}',
        b'{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"x","inputSchema":{"default":NaN}}]}}',
    ]:
        assert local_mcp_stdio._pop_json_message(raw + b"\n")[0] is None
        framed = b"Content-Length: " + str(len(raw)).encode() + b"\r\n\r\n" + raw
        assert local_mcp_stdio._pop_json_message(framed)[0] is None


def test_blank_line_flood_does_not_recurse() -> None:
    raw = b"\n" * 2_000 + b'{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}\n'
    messages = []
    while raw:
        message, raw = local_mcp_stdio._pop_json_message(raw)
        if message is not None:
            messages.append(message)
    assert len(messages) == 1 and messages[0]["id"] == 2


def test_modern_version_error_does_not_initialize_legacy(tmp_path: Path) -> None:
    catalog = run_mcp_catalog(
        _server(
            tmp_path,
            {},
            discovery={
                "error": {
                    "code": -32022,
                    "message": "Unsupported version",
                    "data": {"supported": ["2027-01-01"], "requested": "2026-07-28"},
                }
            },
        )
    )
    assert not catalog.complete
    assert catalog.reason == "unsupported_protocol"
    assert [request["method"] for request in _requests(tmp_path)] == ["server/discover"]


def test_discovered_unsupported_version_does_not_initialize_legacy(tmp_path: Path) -> None:
    catalog = run_mcp_catalog(_server(tmp_path, {}, discovery=_discovery(["2027-01-01"])))
    assert catalog.reason == "unsupported_protocol"
    assert [request["method"] for request in _requests(tmp_path)] == ["server/discover"]


def test_modern_capability_error_does_not_initialize_legacy(tmp_path: Path) -> None:
    catalog = run_mcp_catalog(
        _server(tmp_path, {}, discovery={"error": {"code": -32021, "message": "Required capability"}})
    )
    assert catalog.reason == "discovery_rejected"
    assert [request["method"] for request in _requests(tmp_path)] == ["server/discover"]


def test_discovery_timeout_can_fall_back_to_legacy(tmp_path: Path) -> None:
    catalog = run_mcp_catalog(_server(tmp_path, {"<root>": {"tools": _tools(1)}}, silent_discovery=True), timeout=1)
    assert catalog.complete
    assert catalog.protocol_version == "2024-11-05"
    assert [request["method"] for request in _requests(tmp_path)] == [
        "server/discover", "initialize", "notifications/initialized", "tools/list"
    ]


def test_unsupported_legacy_protocol_cannot_publish_a_catalog(tmp_path: Path) -> None:
    catalog = run_mcp_catalog(_server(tmp_path, {"<root>": {"tools": _tools(1)}}, legacy_version="2027-01-01"))
    assert catalog.reason == "unsupported_protocol"
    assert [request["method"] for request in _requests(tmp_path)] == ["server/discover", "initialize"]


def test_modern_conditional_response_requires_a_known_cached_catalog(tmp_path: Path) -> None:
    catalog = run_mcp_catalog(
        _server(tmp_path, {"<root>": {"resultType": "notModified"}}, discovery=_discovery())
    )
    assert not catalog.complete
    assert catalog.reason == "invalid_page"
