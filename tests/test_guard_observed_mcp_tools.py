from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.observed_mcp_tools import (
    MAX_OBSERVED_MCP_TOOLS,
    discover_observed_mcp_tools,
    native_observed_mcp_tool_actions,
    observed_mcp_tool,
    tools_from_receipts,
)
from codex_plugin_scanner.guard.store import GuardStore


def test_observed_connector_enrollment_uses_stored_catalog_and_requires_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    qualified_name = "mcp__codex_apps__composio__composio_search_tools"
    monkeypatch.setattr(store, "list_receipts", lambda limit: [
        {"harness": "codex", "raw_command_text": "tool:" + qualified_name},
    ])
    discover_observed_mcp_tools(store, seen_at="2026-01-01T00:00:00Z")
    tool = observed_mcp_tool("codex", qualified_name)
    assert tool is not None
    service = LocalCliApiService(store=store)
    monkeypatch.setattr(service, "_observe_harness_mcp_servers", lambda: [])
    result = service.recognize({"command": tool.identity.example_label, "cli_id": tool.identity.cli_id})
    item = result["item"]
    assert item["cli_id"] == tool.identity.cli_id
    assert item["commands"][0]["command_id"] == tool.command_id
    assert result["help_status"] == "ok"
    payload = {
        "cli_id": item["cli_id"], "identity_hash": item["identity_hash"],
        "name": item["name"], "kind": item["kind"], "example_label": item["example_label"],
        "state": "allowed", "previous_revision": 0, "session_nonce": "test-enrollment",
        "commands": [{"command_id": tool.command_id, "state": "allow"}],
    }
    assert service.preview(payload)["next_revision"] == 1
    with pytest.raises(LocalCliApiError):
        service.apply(payload)
    assert store.read_local_cli_revision() == 0
    assert native_observed_mcp_tool_actions(store) == {}


def test_composio_keeps_its_connector_namespace() -> None:
    tool = observed_mcp_tool("codex", "mcp__codex_apps__composio__composio_search_tools")
    assert tool is not None
    assert tool.server_name == "composio"
    assert tool.namespace == "mcp__codex_apps__composio__"
    assert tool.name == "composio_search_tools"
    other = observed_mcp_tool("codex", "mcp__codex_apps__github__search")
    assert other is not None
    assert other.identity.identity_hash != tool.identity.identity_hash
    claude = observed_mcp_tool("claude", tool.qualified_name)
    assert claude is not None
    assert claude.identity.identity_hash != tool.identity.identity_hash


@pytest.mark.parametrize("name", [
    "composio", "mcp__", "mcp__server__", "mcp__server__tool; rm", "mcp__server__tool\n",
    "mcp__codex_apps____tool", "mcp__server__" + "a" * 150,
])
def test_malformed_or_unbounded_names_are_not_discovered(name: str) -> None:
    assert observed_mcp_tool("codex", name) is None


def test_receipt_discovery_uses_labels_only_and_keeps_exact_tool_names() -> None:
    tools = tools_from_receipts([
        {"harness": "codex", "raw_command_text": "tool:mcp__server__read_file"},
        {"harness": "codex", "artifact_name": "mcp__server__read-file"},
        {"harness": "codex", "raw_command_text": "tool:mcp__server__read_file"},
        {"harness": "codex", "raw_command_text": "echo mcp__server__fake"},
    ])
    assert len(tools) == 2
    assert tools[0].identity.identity_hash == tools[1].identity.identity_hash
    assert tools[0].command_id != tools[1].command_id


def test_discovery_preserves_choices_and_never_approves_new_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipts = [{"harness": "codex", "raw_command_text": "tool:mcp__codex_apps__composio__search"}]
    monkeypatch.setattr(store, "list_receipts", lambda limit: receipts)
    discover_observed_mcp_tools(store, seen_at="2026-01-01T00:00:00Z")
    tool = observed_mcp_tool("codex", "mcp__codex_apps__composio__search")
    assert tool is not None
    assert native_observed_mcp_tool_actions(store) == {}
    store.upsert_local_cli_grant(
        identity=tool.identity,
        state="allowed",
        expected_revision=0,
        updated_at="2026-01-01T00:00:01Z",
        command_states={tool.command_id: "allow"},
    )
    receipts.append({"harness": "codex", "raw_command_text": "tool:mcp__codex_apps__composio__execute"})
    discover_observed_mcp_tools(store, seen_at="2026-01-01T00:00:02Z")
    assert store.read_local_cli_command_states(tool.identity.cli_id)[tool.command_id] == "allow"
    assert native_observed_mcp_tool_actions(store) == {"codex:" + tool.qualified_name: "allow"}
    assert store.read_local_cli_revision() == 1
    from codex_plugin_scanner.guard.local_cli_trust import matching_local_mcp_grant
    from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact

    def artifact(name: str):
        return build_tool_call_artifact(
            harness="codex", server_name="codex_apps", tool_name=name,
            source_scope="global", config_path="", transport="observed",
        )

    assert matching_local_mcp_grant(
        store=store, artifact=artifact(tool.qualified_name), current_action="review",
    ) == "allowed"
    assert matching_local_mcp_grant(
        store=store, artifact=artifact(tool.qualified_name), current_action="require-reapproval",
    ) is None
    assert matching_local_mcp_grant(
        store=store, artifact=artifact("mcp__codex_apps__composio__execute"), current_action="review",
    ) is None


def test_server_deny_is_scoped_to_its_harness_and_connector(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "list_receipts", lambda limit: [
        {"harness": "codex", "raw_command_text": "tool:mcp__codex_apps__composio__execute"},
    ])
    discover_observed_mcp_tools(store, seen_at="2026-01-01T00:00:00Z")
    tool = observed_mcp_tool("codex", "mcp__codex_apps__composio__execute")
    assert tool is not None
    store.upsert_local_cli_grant(
        identity=tool.identity, state="blocked", expected_revision=0, updated_at="2026-01-01T00:00:01Z",
    )
    assert native_observed_mcp_tool_actions(store) == {"codex:mcp__codex_apps__composio__*": "block"}


def test_paused_native_requests_discover_connectors_without_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "list_receipts", lambda limit: [])
    monkeypatch.setattr(store, "list_approval_requests", lambda status, limit: [
        {"harness": "codex", "raw_command_text": "tool:mcp__codex_apps__composio__composio_search_tools"},
    ])
    discover_observed_mcp_tools(store, seen_at="2026-01-01T00:00:00Z")
    items = store.list_local_cli_items()
    assert len(items) == 1
    assert items[0]["name"] == "composio"
    assert native_observed_mcp_tool_actions(store) == {}


def test_concurrent_catalog_growth_preserves_all_tools(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand

    store = GuardStore(tmp_path / "guard-home")
    tools = [observed_mcp_tool("codex", f"mcp__server__tool_{index}") for index in range(8)]
    first = tools[0]
    assert first is not None

    def add(tool):
        assert tool is not None
        store.merge_local_cli_commands(
            first.identity.cli_id,
            [LocalCliCommand(command_id=tool.command_id, name=tool.name, usage=tool.qualified_name,
                             description="Observed tool")],
            limit=128,
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(add, tools))
    assert len(store.read_local_cli_command_catalog(first.identity.cli_id)) == len(tools)


def test_duplicate_sources_do_not_consume_catalog_capacity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    records = [{"harness": "codex", "raw_command_text": f"tool:mcp__server__tool_{index}"} for index in range(128)]
    monkeypatch.setattr(store, "list_approval_requests", lambda status, limit: records[:64])
    monkeypatch.setattr(store, "list_receipts", lambda limit: records)
    discover_observed_mcp_tools(store, seen_at="2026-01-01T00:00:00Z")
    tool = observed_mcp_tool("codex", "mcp__server__tool_0")
    assert tool is not None
    assert len(store.read_local_cli_command_catalog(tool.identity.cli_id)) == MAX_OBSERVED_MCP_TOOLS


def test_large_tool_catalog_is_authenticated_in_native_snapshot(tmp_path: Path) -> None:
    import hashlib
    import hmac
    import json

    from codex_plugin_scanner.guard.native_policy_snapshot import (
        POLICY_SNAPSHOT_INTEGRITY_DOMAIN,
        build_policy_snapshot_v3,
    )
    from tests.native_policy_snapshot_test_fixtures import _config

    actions = {f"codex:mcp__server__tool_{index}": "allow" for index in range(300)}
    snapshot = build_policy_snapshot_v3(
        config={**_config(), "mcp_tool_actions": actions}, guard_home=tmp_path,
        runtime_identity="a" * 64, rule_digest="b" * 64, verifier_key=b"k" * 32,
        generation=1, issued_at_ms=100, expires_at_ms=200,
    )
    assert snapshot["effective_policy"]["mcp_tool_actions"] == actions
    signing = dict(snapshot)
    integrity = signing.pop("integrity")
    message = json.dumps(signing, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(b"k" * 32, POLICY_SNAPSHOT_INTEGRITY_DOMAIN + message, hashlib.sha256).hexdigest()
    assert expected in integrity.values()
    signing["effective_policy"]["mcp_tool_actions"]["codex:mcp__server__tool_0"] = "block"
    changed = json.dumps(signing, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    assert hmac.new(b"k" * 32, POLICY_SNAPSHOT_INTEGRITY_DOMAIN + changed, hashlib.sha256).hexdigest() != expected


def test_native_policy_never_accepts_namespace_wide_allow() -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
    from codex_plugin_scanner.guard.native_policy_snapshot_policy import _observed_mcp_action_map

    with pytest.raises(NativePolicySnapshotError):
        _observed_mcp_action_map({"codex:mcp__server__*": "allow"})
