from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.approvals import (
    ApprovalRequestAlreadyResolvedError,
    _refresh_queue_result,
    apply_approval_resolution,
)
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.models import GuardAction, GuardApprovalRequest
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.temporary_mcp_approvals import temporary_mcp_grant_selector


def _request(request_id: str, *, tool_name: str, policy_action: GuardAction = "review") -> GuardApprovalRequest:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npx",
        args=("-y", "chrome-devtools-mcp@latest"),
        transport="stdio",
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="chrome-devtools",
        tool_name=tool_name,
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
    )
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        artifact_type="tool_call",
        artifact_hash=f"{request_id}-hash",
        policy_action=policy_action,
        recommended_scope="artifact",
        changed_fields=("runtime_browser_tool_call",),
        source_scope="project",
        config_path=".mcp.json",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1/requests/{request_id}",
        browser_intent={
            "intent": "browser.inspect",
            "mcp_server_identity_hash": identity.identity_hash,
            "mcp_server_name": "chrome-devtools",
            "risk_categories": ["browser_inspection"],
        },
    )


def _add(store: GuardStore, request_id: str, *, tool_name: str, policy_action: GuardAction = "review") -> None:
    store.add_approval_request(
        _request(request_id, tool_name=tool_name, policy_action=policy_action),
        "2026-07-21T12:00:00+00:00",
    )


def _grant(store: GuardStore, request_id: str) -> dict[str, object]:
    return apply_approval_resolution(
        store=store,
        request_id=request_id,
        action="allow",
        scope="artifact",
        workspace=None,
        reason="temporary browser QA",
        now="2026-07-21T12:01:00+00:00",
        mcp_grant_target="server",
        mcp_grant_duration="5h",
        return_queue_result=True,
    )


def test_server_grant_keeps_contract_invalid_matching_request_pending(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _add(store, "grant-source", tool_name="click")
    _add(store, "terminal-request", tool_name="take_screenshot", policy_action="block")

    _grant(store, "grant-source")

    terminal = store.get_approval_request("terminal-request")
    assert terminal is not None
    assert terminal["status"] == "pending"


def test_server_grant_resolves_every_matching_pending_request(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _add(store, "grant-source", tool_name="click")
    _add(store, "routine-request", tool_name="take_screenshot")
    source = store.get_approval_request("grant-source")
    assert source is not None
    browser_intent = source["browser_intent"]
    assert isinstance(browser_intent, dict)
    identity_hash = str(browser_intent["mcp_server_identity_hash"])

    result = _grant(store, "grant-source")

    assert result["resolved"] is True
    for request_id in ("grant-source", "routine-request"):
        row = store.get_approval_request(request_id)
        assert row is not None
        assert row["status"] == "resolved"
    lookup = store.resolve_policy_decision_lookup(
        "codex",
        temporary_mcp_grant_selector(identity_hash),
        now="2026-07-21T12:02:00+00:00",
        consume_one_shot=False,
    )
    assert lookup["decision"] is not None


def test_raced_source_resolution_does_not_create_grant_or_clear_matching_request(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _add(store, "grant-source", tool_name="click")
    _add(store, "routine-request", tool_name="take_screenshot")
    source = store.get_approval_request("grant-source")
    assert source is not None
    browser_intent = source["browser_intent"]
    assert isinstance(browser_intent, dict)
    identity_hash = str(browser_intent["mcp_server_identity_hash"])
    original = store.apply_temporary_mcp_grant_resolution

    def race(**kwargs):
        store.resolve_approval_request(
            "grant-source",
            resolution_action="allow",
            resolution_scope="artifact",
            reason="competing resolution",
            resolved_at="2026-07-21T12:00:30+00:00",
        )
        return original(**kwargs)

    monkeypatch.setattr(store, "apply_temporary_mcp_grant_resolution", race)

    with pytest.raises(ApprovalRequestAlreadyResolvedError, match="already resolved"):
        _grant(store, "grant-source")

    routine = store.get_approval_request("routine-request")
    assert routine is not None
    assert routine["status"] == "pending"
    lookup = store.resolve_policy_decision_lookup(
        "codex",
        temporary_mcp_grant_selector(identity_hash),
        now="2026-07-21T12:02:00+00:00",
        consume_one_shot=False,
    )
    assert lookup["decision"] is None


def test_queue_refresh_unions_existing_and_new_scope_ids(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    result: dict[str, object] = {"resolved_scope_ids": ["artifact-match"]}

    _refresh_queue_result(store, result, ["server-match", "artifact-match"])

    assert result["resolved_scope_ids"] == ["artifact-match", "server-match"]
