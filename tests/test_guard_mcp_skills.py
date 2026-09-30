from __future__ import annotations

from copy import deepcopy
from hashlib import sha256

import pytest

from codex_plugin_scanner.guard.runtime.mcp_skills import (
    McpSkillError,
    McpSkillsClient,
    mcp_skills_declared,
    parse_mcp_skill_entry,
)

_ORIGIN = "a" * 64
_URI = "skill://team/report/SKILL.md"
_CONTENT = b"---\nname: report\ndescription: Prepare a report.\n---\nUntrusted instructions.\n"
_CAPABILITIES = {"resources": {}, "extensions": {"io.modelcontextprotocol/skills": {}}}


def _resource(uri=_URI, content=_CONTENT):
    return {"uri": uri, "digest": "sha256:" + sha256(content).hexdigest(), "size": len(content)}


def _entry():
    return {"uri": _URI, "frontmatter": {"name": "report", "description": "Prepare a report."},
            "resources": [_resource()]}


def _result(**fields):
    return {"resultType": "complete", "ttlMs": 0, "cacheScope": "private", **fields}


def test_oversized_frontmatter_reports_metadata_limit():
    entry = _entry()
    entry["frontmatter"]["notes"] = "x" * 262_144
    with pytest.raises(McpSkillError, match="skill_metadata_limit"):
        parse_mcp_skill_entry(entry, origin=_ORIGIN)


def test_declaration_requires_resources_and_actual_extension_not_tool_names():
    assert mcp_skills_declared(_CAPABILITIES, protocol_version="2026-07-28")
    assert mcp_skills_declared(_CAPABILITIES, protocol_version="2027-01-01")
    for capabilities in ({}, {"tools": {}}, {"extensions": _CAPABILITIES["extensions"]}, {"resources": {}}):
        assert not mcp_skills_declared(capabilities, protocol_version="2026-07-28")
        with pytest.raises(McpSkillError, match="not_declared"):
            McpSkillsClient(
                origin=_ORIGIN, capabilities=capabilities, protocol_version="2026-07-28", request=lambda *_: {},
            )
    assert not mcp_skills_declared(_CAPABILITIES, protocol_version="2025-11-25")
    for invalid in ("2026-07-27", "2026-13-01", "2026-07-28-extra", "20260728"):
        assert not mcp_skills_declared(_CAPABILITIES, protocol_version=invalid)


def test_later_negotiated_revision_is_sent_in_skills_request_metadata():
    def request(method, params):
        assert method == "skills/list"
        assert params["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2027-01-01"
        return _result(skills=[])

    client = McpSkillsClient(
        origin=_ORIGIN, capabilities=_CAPABILITIES, protocol_version="2027-01-01", request=request,
    )
    assert client.list_metadata() == ((), True, None)


def test_list_metadata_is_lazy_and_direct_get_can_find_unlisted_skill():
    calls = []

    def request(method, params):
        calls.append((method, params))
        assert params["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
        if method == "skills/list":
            return _result(skills=[])
        if method == "skills/get":
            assert params["uri"] == _URI
            return _result(skill=_entry())
        assert method == "resources/read"
        return _result(contents=[{"uri": _URI, "text": _CONTENT.decode()}])

    client = McpSkillsClient(origin=_ORIGIN, capabilities=_CAPABILITIES, protocol_version="2026-07-28", request=request)
    assert client.list_metadata() == ((), True, None)
    entry = client.get_metadata(_URI)
    assert [call[0] for call in calls] == ["skills/list", "skills/get"]
    assert entry.public_metadata()["activation_supported"] is False
    assert client.inspect_content(entry, _URI) == _CONTENT
    assert client.inspect_content(entry, _URI) == _CONTENT
    assert [call[0] for call in calls].count("resources/read") == 1


def test_manifest_binds_whole_resource_set_frontmatter_and_origin():
    value = _entry()
    first = parse_mcp_skill_entry(value, origin=_ORIGIN)
    copy = first.frontmatter
    copy["name"] = "mutated"
    assert first.frontmatter["name"] == "report"
    second = parse_mcp_skill_entry(value, origin="b" * 64)
    assert first.manifest_digest != second.manifest_digest
    value["resources"].append(_resource("skill://team/report/reference.md", b"reference"))
    third = parse_mcp_skill_entry(value, origin=_ORIGIN)
    assert first.manifest_digest != third.manifest_digest
    value["resources"].reverse()
    assert parse_mcp_skill_entry(value, origin=_ORIGIN).manifest_digest == third.manifest_digest
    value["frontmatter"]["allowed-tools"] = "*"
    assert parse_mcp_skill_entry(value, origin=_ORIGIN).manifest_digest != third.manifest_digest


@pytest.mark.parametrize("uri", [
    "skill://team/report/../outside.md", "skill://team/report/%2e%2e/outside.md",
    "skill://team/report/%252e%252e/outside.md", "skill://team/report/%2foutside.md",
    "skill://team/report/%0aoutside.md", "skill://team/report\\outside.md", "skill://different/reference.md",
])
def test_manifest_cannot_escape_its_skill_directory(uri):
    value = _entry()
    value["resources"].append(_resource(uri, b""))
    with pytest.raises(McpSkillError, match="invalid_skill_resource"):
        parse_mcp_skill_entry(value, origin=_ORIGIN)


def test_manifest_accepts_required_512_entries_and_16_mib_limits_without_reading():
    value = _entry()
    value["resources"].extend(_resource(f"skill://team/report/file-{index}.txt", b"") for index in range(511))
    value["resources"][-1]["size"] = 16_777_216 - len(_CONTENT)
    assert len(parse_mcp_skill_entry(value, origin=_ORIGIN).resources) == 512
    over = deepcopy(value)
    over["resources"][-1]["size"] += 1
    with pytest.raises(McpSkillError, match="size_limit"):
        parse_mcp_skill_entry(over, origin=_ORIGIN)
    value["resources"].append(_resource("skill://team/report/extra.txt", b""))
    with pytest.raises(McpSkillError, match="resource_limit"):
        parse_mcp_skill_entry(value, origin=_ORIGIN)


def test_changed_or_unlisted_content_revokes_held_entry_and_cache():
    value = _entry()

    def request(method, _params):
        if method == "skills/get":
            return _result(skill=value)
        return _result(contents=[{"uri": _URI, "text": _CONTENT.decode()}])

    client = McpSkillsClient(origin=_ORIGIN, capabilities=_CAPABILITIES, protocol_version="2026-07-28", request=request)
    old = client.get_metadata(_URI)
    client.inspect_content(old, _URI)
    key = next(iter(client._cache))
    client._cache[key] = b"X" * len(_CONTENT)
    with pytest.raises(McpSkillError, match="skill_content_changed"):
        client.inspect_content(old, _URI)
    assert not client._cache
    with pytest.raises(McpSkillError, match="skill_entry_changed"):
        client.inspect_content(old, _URI)
    current = client.get_metadata(_URI)
    with pytest.raises(McpSkillError, match="unlisted_skill_resource"):
        client.inspect_content(current, "skill://team/report/new.txt")
    value["resources"].append(_resource("skill://team/report/new.txt", b""))
    client.get_metadata(_URI)
    with pytest.raises(McpSkillError, match="skill_entry_changed"):
        client.inspect_content(old, _URI)


def test_frontmatter_mismatch_and_cross_origin_are_rejected_and_dynamic_declined():
    value = _entry()
    value["frontmatter"]["allowed-tools"] = "*"
    client = McpSkillsClient(origin=_ORIGIN, capabilities=_CAPABILITIES, protocol_version="2026-07-28",
                            request=lambda method, _: _result(skill=value) if method == "skills/get"
                            else _result(contents=[{"uri": _URI, "text": _CONTENT.decode()}]))
    entry = client.get_metadata(_URI)
    with pytest.raises(McpSkillError, match="skill_frontmatter_changed"):
        client.inspect_content(entry, _URI)
    other = parse_mcp_skill_entry(value, origin="b" * 64)
    with pytest.raises(McpSkillError, match="cross_origin"):
        client.inspect_content(other, _URI)
    value["resources"] = "dynamic"
    dynamic = client.get_metadata(_URI)
    assert dynamic.manifest_digest is None
    assert dynamic.public_metadata()["dynamic"] is True
    with pytest.raises(McpSkillError, match="dynamic_skill"):
        client.inspect_content(dynamic, _URI)


def test_repeated_cursor_retains_partial_metadata_and_malformed_cache_scope_is_typed():
    calls = []

    def request(_method, params):
        calls.append(params)
        return _result(skills=[_entry()] if len(calls) == 1 else [], nextCursor="opaque")

    client = McpSkillsClient(origin=_ORIGIN, capabilities=_CAPABILITIES, protocol_version="2026-07-28", request=request)
    entries, complete, reason = client.list_metadata()
    assert len(entries) == 1 and not complete and reason == "repeated_skills_cursor"
    assert calls[1]["cursor"] == "opaque"
    broken = McpSkillsClient(origin=_ORIGIN, capabilities=_CAPABILITIES, protocol_version="2026-07-28",
                            request=lambda *_: _result(skills=[], cacheScope={"private": True}))
    assert broken.list_metadata() == ((), False, "invalid_skills_result")
