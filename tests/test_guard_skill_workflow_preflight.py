import json

import pytest

from codex_plugin_scanner.guard.runtime.skill_workflow_preflight import (
    parse_guard_skill_dependencies,
    preflight_skill_dependencies,
)


def _manifest(tools):
    return {
        "metadata": {
            "hol-guard.dependencies": json.dumps(
                {
                    "schema_version": "guard.skill-dependencies.v1",
                    "tools": tools,
                }
            )
        }
    }


@pytest.mark.parametrize(
    "tools",
    [
        [{"connection_id": "local-cli.fixture", "tool_name": "*"}],
        [{"connection_id": "*", "tool_name": "read"}],
        [{"connection_id": "local-cli.fixture", "tool_name": "read", "auto_allow": True}],
        [{"connection_id": "local-cli.fixture", "tool_name": "read"}] * 2,
        [{"connection_id": "local-cli.fixture", "tool_name": "read"}] * 51,
    ],
)
def test_guard_manifest_rejects_implicit_and_duplicate_authority(tools):
    assert parse_guard_skill_dependencies(_manifest(tools)) == {
        "source": "guard-extension",
        "status": "invalid",
        "tools": [],
    }


def test_manifest_duplicate_json_keys_and_nonfinite_fail_closed():
    for raw in (
        '{"schema_version":"guard.skill-dependencies.v1","tools":[],"tools":[]}',
        '{"schema_version":"guard.skill-dependencies.v1","tools":NaN}',
    ):
        result = parse_guard_skill_dependencies({"metadata": {"hol-guard.dependencies": raw}})
        assert result["status"] == "invalid"
    assert parse_guard_skill_dependencies({"allowed-tools": "*"})["status"] == "absent"


def test_preflight_connections_denies_unknown_tools_and_wrappers_stay_separate():
    names = ["read", "denied", "unknown", "mcp__codex_apps__composio__composio_execute_tool"]
    dependencies = parse_guard_skill_dependencies(
        _manifest(
            [{"connection_id": "local-cli.fixture", "tool_name": name} for name in names]
            + [{"connection_id": "local-cli.missing", "tool_name": "read"}]
        )
    )
    item = {
        "cli_id": "local-cli.fixture",
        "identity_hash": "a" * 64,
        "state": "allowed",
        "stale": False,
        "commands": [
            {"usage": name, "state": "block" if name == "denied" else "allow"} for name in names if name != "unknown"
        ],
    }
    original = json.dumps(item)
    plan = preflight_skill_dependencies(dependencies, [item], revision=7)
    assert [requirement["state"] for requirement in plan["requirements"]] == [
        "saved-allow",
        "deny",
        "unresolved",
        "ask",
        "unresolved",
    ]
    assert plan["permissions_granted"] is False
    assert plan["requirements_complete"] is False
    assert plan["runtime_checks_required"] is True
    assert plan["dependency_source"] == "guard-extension"
    assert json.dumps(item) == original
    # An identical tool label on another connection cannot satisfy this plan.
    assert all(
        requirement["state"] == "unresolved"
        for requirement in preflight_skill_dependencies(
            dependencies,
            [{**item, "cli_id": "local-cli.other"}],
            revision=7,
        )["requirements"]
    )
