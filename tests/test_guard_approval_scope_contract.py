"""Action-aware approval-scope contract and resolution regressions."""

from __future__ import annotations

import json
import sqlite3
import threading
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_scope_support import (
    APPROVAL_SCOPE_CONTRACT_VERSION,
    request_scope_contract,
    supported_request_scopes,
)
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardAction, GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


def _request(
    request_id: str,
    *,
    artifact_id: str | None = None,
    artifact_type: str = "tool_action_request",
    policy_action: GuardAction = "require-reapproval",
    action_type: str = "shell_command",
    decision_scopes: list[str] | None = None,
    publisher: str | None = "publisher-a",
    artifact_hash: str | None = None,
) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=artifact_id or f"codex:project:tool-action:{request_id}",
        artifact_name="Scoped action",
        artifact_type=artifact_type,
        artifact_hash=artifact_hash or f"hash-{request_id}",
        publisher=publisher,
        policy_action=policy_action,
        recommended_scope="global",
        changed_fields=("command",),
        source_scope="project",
        config_path="/workspace/repo/.guard/config.toml",
        workspace="/workspace/repo",
        launch_target="echo test",
        action_envelope_json={"action_type": action_type, "command": "echo test"},
        decision_v2_json={
            "action": "block" if policy_action == "block" else "ask",
            "approval_scopes": decision_scopes or ["global"],
        },
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/approvals/{request_id}",
    )


def _store_request(store: GuardStore, request: GuardApprovalRequest) -> dict[str, object]:
    store.add_approval_request(request, "2026-07-19T00:00:00+00:00")
    row = store.get_approval_request(request.request_id)
    assert row is not None
    return row


def _post(
    daemon: GuardDaemonServer,
    path: str,
    payload: Mapping[str, object],
) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        data=json.dumps(dict(payload)).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def _v2_selection(row: Mapping[str, object], scope: str) -> dict[str, object]:
    return {
        "scope": scope,
        "scope_contract_version": row["scope_contract_version"],
        "scope_contract_digest": row["scope_contract_digest"],
    }


def _mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    assert all(isinstance(key, str) for key in value)
    return value


@pytest.mark.parametrize(
    ("policy_action", "expected_allow"),
    [
        ("require-reapproval", ("artifact",)),
        ("review", ("artifact",)),
        ("sandbox-required", ()),
        ("block", ()),
    ],
)
def test_scope_contract_is_action_aware(policy_action: GuardAction, expected_allow: tuple[str, ...]) -> None:
    contract = request_scope_contract(_request("matrix", policy_action=policy_action).to_dict())

    assert contract.allow_scopes == expected_allow
    assert contract.block_scopes == ("artifact", "workspace", "publisher", "harness", "global")
    assert contract.task_capability_eligible is False


def test_guard_control_cannot_be_browser_allowed() -> None:
    contract = request_scope_contract(_request("guard-control", action_type="guard_control").to_dict())

    assert contract.allow_scopes == ()
    assert "current_action_not_overridable" in contract.restrictions


@pytest.mark.parametrize("policy_action", ["block", "sandbox-required"])
def test_terminal_policy_action_cannot_be_browser_allowed(tmp_path: Path, policy_action: GuardAction) -> None:
    store = GuardStore(tmp_path / "guard-home")
    row = _store_request(store, _request("terminal", policy_action=policy_action))
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, response = _post(daemon, "/v1/requests/terminal/approve", _v2_selection(row, "artifact"))
    finally:
        daemon.stop()

    assert status == 422
    assert response["error"] == "ineligible_request_scope"
    stored = store.get_approval_request("terminal")
    assert stored is not None
    assert stored["status"] == "pending"


def test_artifact_family_text_cannot_spoof_canonical_broad_deny() -> None:
    request = _request(
        "spoofed",
        artifact_id="codex:project:tool-action:spoofed",
        artifact_type="mcp_server",
    ).to_dict()

    assert request_scope_contract(request).block_scopes == ("artifact",)


def test_package_context_never_invents_workspace_allow() -> None:
    request = _request(
        "package",
        artifact_id="codex:project:package-request:package",
        artifact_type="package_request",
    ).to_dict()
    request["scanner_evidence"] = [{"portable": True, "schema_version": "package-execution-context.v1"}]

    assert supported_request_scopes(request) == ("artifact",)


@pytest.mark.parametrize(
    ("artifact_type", "family", "action_type"),
    [
        ("file_read_request", "file-read", "file_read"),
        ("mcp_server", "mcp", "mcp_tool_call"),
        ("package_request", "package-request", "package_install"),
        ("prompt_request", "prompt", "prompt_submit"),
        ("tool_action_request", "tool-action", "workspace_write"),
        ("tool_action_request", "tool-action", "network_write"),
        ("tool_action_request", "tool-action", "remote_state_mutation"),
        ("tool_action_request", "tool-action", "destructive_operation"),
        ("tool_action_request", "tool-action", "dynamic_unknown"),
    ],
)
def test_request_type_matrix_never_infers_broad_allow(
    artifact_type: str,
    family: str,
    action_type: str,
) -> None:
    request = _request(
        "request-matrix",
        artifact_id=f"codex:project:{family}:request-matrix",
        artifact_type=artifact_type,
        action_type=action_type,
    ).to_dict()

    assert request_scope_contract(request).allow_scopes == ("artifact",)


def test_contract_digest_is_deterministic_and_binds_security_fields() -> None:
    request = _request("digest").to_dict()
    first = request_scope_contract(request)
    reordered = dict(reversed(tuple(request.items())))

    assert request_scope_contract(reordered).digest == first.digest
    assert request_scope_contract({**request, "policy_action": "block"}).digest != first.digest
    assert request_scope_contract({**request, "workspace": "/workspace/other"}).digest != first.digest
    assert request_scope_contract({**request, "artifact_hash": "different"}).digest != first.digest
    assert (
        request_scope_contract(
            {**request, "action_envelope_json": {"action_type": "shell_command", "command": "echo changed"}}
        ).digest
        != first.digest
    )


def test_deduped_request_identity_change_invalidates_scope_contract(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    row = _store_request(store, _request("deduped", artifact_hash="hash-old"))
    stale_selection = _v2_selection(row, "artifact")

    replacement = _request("replacement", artifact_hash="hash-new")
    replacement = replace(replacement, artifact_id="codex:project:tool-action:deduped")
    persisted_request_id = store.add_approval_request(replacement, "2026-07-19T00:00:01+00:00")
    assert persisted_request_id == "deduped"
    current = store.get_approval_request("deduped")
    assert current is not None
    assert current["artifact_hash"] == "hash-new"
    assert current["scope_contract_digest"] != row["scope_contract_digest"]

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, response = _post(daemon, "/v1/requests/deduped/approve", stale_selection)
    finally:
        daemon.stop()

    assert status == 409
    assert response["error"] == "stale_scope_contract"
    assert response["scope_contract_digest"] == current["scope_contract_digest"]
    stored = store.get_approval_request("deduped")
    assert stored is not None
    assert stored["status"] == "pending"
    assert store.list_policy_decisions() == []
    assert store.list_events(event_name="approval.resolved") == []


def test_stored_payload_overrides_untrusted_decision_scope_advertisement(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    row = _store_request(store, _request("sanitize", decision_scopes=["artifact", "global"]))

    assert row["allowed_scopes"] == ["artifact"]
    assert row["allowed_scopes_by_action"] == {
        "allow": ["artifact"],
        "block": ["artifact", "workspace", "publisher", "harness", "global"],
    }
    assert _mapping(row["decision_v2_json"])["approval_scopes"] == ["artifact"]


@pytest.mark.parametrize(
    "payload",
    [
        {"scope": "not-a-scope"},
        {"scope": "artifact", "scope_contract_version": APPROVAL_SCOPE_CONTRACT_VERSION},
        {"scope": "artifact", "scope_contract_digest": "0" * 64},
        {"scope": "artifact", "scope_contract_version": 2, "scope_contract_digest": "0" * 64},
        {
            "scope": "artifact",
            "scope_contract_version": APPROVAL_SCOPE_CONTRACT_VERSION,
            "scope_contract_digest": "not-a-digest",
        },
    ],
)
def test_malformed_resolution_contract_returns_400(tmp_path: Path, payload: dict[str, object]) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _store_request(store, _request("malformed"))
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, response = _post(daemon, "/v1/requests/malformed/approve", payload)
    finally:
        daemon.stop()

    assert status == 400
    assert response["resolved"] is False
    stored = store.get_approval_request("malformed")
    assert stored is not None
    assert stored["status"] == "pending"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scope_contract_version", "guard.approval-scopes.v1"),
        ("scope_contract_version", f"{APPROVAL_SCOPE_CONTRACT_VERSION}0"),
        ("scope_contract_digest", "0" * 64),
    ],
)
def test_stale_contract_returns_409_with_fresh_contract(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    row = _store_request(store, _request("stale"))
    payload = _v2_selection(row, "artifact")
    payload[field] = value
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, response = _post(daemon, "/v1/requests/stale/approve", payload)
    finally:
        daemon.stop()

    assert status == 409
    assert response["error"] == "stale_scope_contract"
    assert response["scope_contract_digest"] == row["scope_contract_digest"]
    stored = store.get_approval_request("stale")
    assert stored is not None
    assert stored["status"] == "pending"


def test_v2_ineligible_scope_returns_422_without_policy_or_resolution(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    row = _store_request(store, _request("ineligible"))
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, response = _post(
            daemon,
            "/v1/requests/ineligible/approve",
            _v2_selection(row, "global"),
        )
    finally:
        daemon.stop()

    assert status == 422
    assert response["error"] == "ineligible_request_scope"
    assert _mapping(response["allowed_scopes_by_action"])["allow"] == ["artifact"]
    stored = store.get_approval_request("ineligible")
    assert stored is not None
    assert stored["status"] == "pending"
    assert store.list_policy_decisions() == []


def test_v2_saved_artifact_allow_is_rejected_as_ineligible(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    row = _store_request(store, _request("saved-allow"))
    payload = {**_v2_selection(row, "artifact"), "persist_policy": True}
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, response = _post(daemon, "/v1/requests/saved-allow/approve", payload)
    finally:
        daemon.stop()

    assert status == 422
    assert response["error"] == "saved_allow_scope_ineligible"
    stored = store.get_approval_request("saved-allow")
    assert stored is not None
    assert stored["status"] == "pending"


def test_legacy_unknown_broad_deny_is_not_silently_narrowed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _store_request(
        store,
        _request(
            "unknown-deny",
            artifact_id="codex:project:unknown:unknown-deny",
            artifact_type="unknown_request",
        ),
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, response = _post(
            daemon,
            "/v1/requests/unknown-deny/block",
            {"scope": "global"},
        )
    finally:
        daemon.stop()

    assert status == 422
    assert response["error"] == "ineligible_request_scope"


def test_legacy_global_allow_narrows_to_artifact_once(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _store_request(store, _request("legacy"))
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, response = _post(
            daemon,
            "/v1/requests/legacy/approve",
            {"scope": "global", "persist_policy": True},
        )
    finally:
        daemon.stop()

    assert status == 200
    assert response["requested_scope"] == "global"
    assert response["applied_scope"] == "artifact"
    assert response["scope_warning"] == "legacy_scope_narrowed_to_artifact"
    assert _mapping(response["resolved_request"])["resolution_scope"] == "artifact"
    decisions = store.list_policy_decisions()
    assert decisions == []
    with sqlite3.connect(store.path) as connection:
        stored_scope = connection.execute("select scope from policy_decisions").fetchone()
    assert stored_scope == ("artifact",)


def test_same_resolution_replay_is_idempotent_and_conflict_is_409(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    row = _store_request(store, _request("replay"))
    payload = _v2_selection(row, "artifact")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        first_status, _ = _post(daemon, "/v1/requests/replay/approve", payload)
        replay_status, replay = _post(daemon, "/v1/requests/replay/approve", payload)
        conflict_status, conflict = _post(daemon, "/v1/requests/replay/block", payload)
    finally:
        daemon.stop()

    assert first_status == 200
    assert replay_status == 200
    assert replay["idempotent"] is True
    assert conflict_status == 409
    assert conflict["error"] == "already_resolved"


@pytest.mark.parametrize(
    "case",
    [
        ("artifact", True, "require-reapproval", "changed", 409, "stale_scope_contract"),
        ("global", False, "sandbox-required", None, 422, "request_action_not_overridable"),
    ],
)
def test_raced_completed_replay_maps_scope_contract_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[str, bool, GuardAction, str | None, int, str],
) -> None:
    payload_scope, use_contract, third_policy_action, third_hash, expected_status, expected_error = case
    store = GuardStore(tmp_path / "guard-home")
    row = _store_request(store, _request("replay-race"))
    store.resolve_approval_request(
        "replay-race",
        resolution_action="allow",
        resolution_scope="artifact",
        reason=None,
        resolved_at="2026-07-19T00:00:01+00:00",
    )
    original_get = store.get_approval_request
    call_count = 0

    def raced_get(request_id: str) -> dict[str, object] | None:
        nonlocal call_count
        call_count += 1
        current = original_get(request_id)
        if current is None:
            return None
        if call_count == 1:
            return {**current, "status": "pending"}
        if call_count >= 3:
            return {
                **current,
                "policy_action": third_policy_action,
                "artifact_hash": third_hash or current["artifact_hash"],
            }
        return current

    monkeypatch.setattr(store, "get_approval_request", raced_get)
    payload = _v2_selection(row, payload_scope) if use_contract else {"scope": payload_scope}
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, response = _post(daemon, "/v1/requests/replay-race/approve", payload)
    finally:
        daemon.stop()
    assert status == expected_status
    assert response["error"] == expected_error


def test_concurrent_same_resolution_has_one_effect_and_two_successes(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    row = _store_request(store, _request("race"))
    payload = _v2_selection(row, "artifact")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    results: list[tuple[int, dict[str, object]]] = []

    def resolve() -> None:
        results.append(_post(daemon, "/v1/requests/race/approve", payload))

    threads = [threading.Thread(target=resolve) for _ in range(2)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
    finally:
        daemon.stop()
    assert sorted(status for status, _ in results) == [200, 200], results
    assert len(store.list_events(event_name="approval.resolved")) == 1
