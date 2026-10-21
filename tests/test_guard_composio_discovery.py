import json

import pytest

from codex_plugin_scanner.guard.runtime.composio_discovery import composio_discovered_actions

_TOOL = "mcp__codex_apps__composio__composio_search_tools"


def _result():
    return {
        "successful": True,
        "error": None,
        "data": {
            "tool_schemas": {
                "SLACK_SEARCH_MESSAGES": {
                    "toolkit": "slack",
                    "tool_slug": "SLACK_SEARCH_MESSAGES",
                    "description": "Search messages",
                    "input_schema": {"type": "object", "required": ["query"]},
                    "hasFullSchema": True,
                }
            },
            "session": {"session_id": "private-fixture-session"},
            "toolkit_connection_statuses": [{"toolkit": "slack", "has_active_connection": True}],
        },
    }


@pytest.mark.parametrize("envelope", ["direct", "structured", "text"])
def test_inspected_discovery_contract_retains_schemas_without_account_claims(envelope: str) -> None:
    value = _result()
    response = (
        value
        if envelope == "direct"
        else {"structuredContent": value}
        if envelope == "structured"
        else {
            "content": [{"type": "text", "text": json.dumps(value)}],
        }
    )
    actions = composio_discovered_actions(_TOOL, response)
    assert actions is not None and len(actions) == 1
    assert actions[0].tool_slug == "SLACK_SEARCH_MESSAGES"
    assert actions[0].full_schema
    assert "private-fixture-session" not in repr(actions)
    assert not hasattr(actions[0], "account")
    value["data"]["tool_schemas"]["SLACK_SEARCH_MESSAGES"]["input_schema"]["required"].append("changed")
    assert actions[0].input_schema["required"] == ["query"]


@pytest.mark.parametrize("failure", ["failed", "error", "bad-key", "bad-schema", "partial-member", "cycle"])
def test_unsupported_or_malformed_discovery_never_becomes_an_inventory(failure: str) -> None:
    value = _result()
    schemas = value["data"]["tool_schemas"]
    if failure == "failed":
        value["successful"] = False
    elif failure == "error":
        value["data"]["error"] = "provider failed"
    elif failure == "bad-key":
        schemas["OTHER"] = schemas.pop("SLACK_SEARCH_MESSAGES")
    elif failure == "bad-schema":
        schemas["SLACK_SEARCH_MESSAGES"]["input_schema"] = []
    elif failure == "partial-member":
        schemas["OTHER"] = {}
    else:
        schemas["SLACK_SEARCH_MESSAGES"]["input_schema"]["cycle"] = schemas
    assert composio_discovered_actions(_TOOL, value) is None


def test_tool_results_cannot_impersonate_host_inventory_or_discovery() -> None:
    assert composio_discovered_actions("composio_multi_execute_tool", _result()) is None
    assert composio_discovered_actions(_TOOL, {"result": _result()}) is None
    assert composio_discovered_actions(_TOOL, {"isError": True, "structuredContent": _result()}) is None
    assert composio_discovered_actions(_TOOL, {"isError": "false", "structuredContent": _result()}) is None
    assert (
        composio_discovered_actions(
            _TOOL,
            {
                "content": [{"type": "text", "text": '{"successful": false, "successful": true}'}],
            },
        )
        is None
    )


def test_partial_schema_is_metadata_without_complete_authority() -> None:
    value = _result()
    value["data"]["tool_schemas"]["SLACK_SEARCH_MESSAGES"]["hasFullSchema"] = False
    assert composio_discovered_actions(_TOOL, value)[0].full_schema is False


def test_discovery_metadata_limits_are_bounded() -> None:
    value = _result()
    schema = value["data"]["tool_schemas"]["SLACK_SEARCH_MESSAGES"]["input_schema"]
    schema["description"] = "x" * 1_000_001
    assert composio_discovered_actions(_TOOL, value) is None
