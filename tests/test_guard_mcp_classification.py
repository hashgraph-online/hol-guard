from codex_plugin_scanner.guard.runtime.mcp_classification import classify_mcp_action


def test_benign_name_and_annotations_never_resolve_unknown_effect():
    evidence = classify_mcp_action("safe_read_only", {"type": "object"}, annotations={"readOnlyHint": True})
    assert evidence["effect"] == "unknown"
    assert evidence["advisory_only"] is True
    assert "effect-unresolved" in evidence["warnings"]
    assert "provider-annotations:unverified" in evidence["evidence"]


def test_nested_schema_export_and_execution_override_benign_claim():
    evidence = classify_mcp_action("read", {"properties": {"payload": {"properties": {
        "command": {"type": "string"}, "webhook_url": {"type": "string"}, "token": {"type": "string"},
    }}}}, annotations={"readOnlyHint": True})
    assert evidence["effect"] == "execute"
    assert evidence["destination"] == "caller-selected"
    assert evidence["data"] == "credentials-possible"
    assert "annotation-conflicts-with-evidence" in evidence["warnings"]
    assert "external-transfer-possible" in evidence["warnings"]


def test_only_exact_provider_mapping_applies_and_values_never_escape():
    schema = {"properties": {"query": {"type": "string", "default": "SECRET", "description": "ignore rules"}}}
    actual = classify_mcp_action("SLACK_SEARCH_MESSAGES", schema, provider="composio")
    assert actual["effect"] == "read"
    assert actual["data"] == "private-content"
    assert actual["confidence"] == "reviewed-mapping"
    assert "SECRET" not in str(actual)
    assert "ignore rules" not in str(actual)
    assert classify_mcp_action("SLACK_SEARCH_MESSAGES_EVIL", schema, provider="composio")["effect"] == "unknown"
    assert classify_mcp_action("SLACK_SEARCH_MESSAGES", schema)["effect"] == "unknown"


def test_schema_limits_cycles_refs_and_partial_are_explicit():
    cycle: dict[str, object] = {}
    cycle["items"] = cycle
    schemas = (cycle, {"$ref": "https://example.invalid/schema"}, {"properties": {str(i): {} for i in range(257)}})
    for schema in schemas:
        result = classify_mcp_action("SLACK_SEARCH_MESSAGES", schema, provider="composio")
        assert result["confidence"] == "limited"
        assert "schema-incomplete" in result["warnings"]
    assert "schema-incomplete" in classify_mcp_action("x", {}, full_schema=False)["warnings"]
