"""Guard queue API contract tests."""

from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


def _request(
    request_id: str,
    *,
    harness: str = "codex",
    command: str = "cat ~/.npmrc",
    prompt_excerpt: str | None = None,
    mcp_server: str | None = None,
    mcp_tool: str | None = None,
    workspace: str = "workspace-a",
) -> GuardApprovalRequest:
    action_envelope = {
        "action_type": "mcp_tool_call" if mcp_tool else "shell_command",
        "tool_name": "mcp" if mcp_tool else "Bash",
        "command": command,
        "prompt_excerpt": prompt_excerpt,
        "target_paths": ["~/.npmrc"] if "npmrc" in command else [],
        "network_hosts": [],
        "mcp_server": mcp_server,
        "mcp_tool": mcp_tool,
    }
    return GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id=f"{harness}:project:{request_id}",
        artifact_name=request_id,
        artifact_hash=f"hash-{request_id}",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("args",),
        source_scope="project",
        config_path=f"/{workspace}/.config/guard.toml",
        workspace=workspace,
        launch_target=command,
        action_envelope_json=action_envelope,
        decision_v2_json={"dashboard_primary_detail": prompt_excerpt} if prompt_excerpt else None,
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1/pending/{request_id}",
    )


def _populate(store: GuardStore, requests: list[GuardApprovalRequest]) -> None:
    for index, request in enumerate(requests):
        store.add_approval_request(request, f"2026-05-08T10:0{index}:00+00:00")


def _force_duplicate_row(store: GuardStore, request_id: str, source_request_id: str) -> None:
    connection = sqlite3.connect(store.path)
    try:
        connection.execute(
            """
            insert into approval_requests (
              request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
              recommended_scope, changed_fields_json, source_scope, config_path, workspace,
              launch_target, normalized_identity_key, action_identity, queue_group_id, dedupe_count, last_seen_at,
              transport, risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, why_now,
              launch_summary, risk_headline, action_envelope_json, decision_v2_json, fallback_cli_command,
              review_command, approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at
            )
            select ?, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
              recommended_scope, changed_fields_json, source_scope, config_path, workspace,
              launch_target, normalized_identity_key, action_identity, queue_group_id, 1, last_seen_at,
              transport, risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, why_now,
              launch_summary, risk_headline, action_envelope_json, decision_v2_json, fallback_cli_command,
              ?, ?, status, resolution_action, resolution_scope, reason, created_at, resolved_at
            from approval_requests
            where request_id = ?
            """,
            (
                request_id,
                f"hol-guard approvals approve {request_id}",
                f"http://127.0.0.1/pending/{request_id}",
                source_request_id,
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _get_json(port: int, path: str) -> dict[str, object]:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _post_json(port: int, token: str, path: str, payload: dict[str, object]) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _post_error(port: int, token: str, path: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))
    raise AssertionError("expected HTTPError")


def test_resolving_active_item_with_two_remaining_returns_next_hint(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(
        store,
        [
            _request("req-old", command="cat ~/.npmrc"),
            _request("req-active", command="cat ~/.pypirc"),
            _request("req-newest", command="curl https://metadata.example/health"),
        ],
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-active/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert payload["remaining_pending_count"] == 2
    assert payload["next_selectable_request_id"] == "req-newest"
    assert {item["request_id"] for item in payload["remaining_pending_summaries"]} == {"req-newest", "req-old"}


def test_resolving_last_item_returns_empty_queue_hint(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-only")])
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-only/block",
            {"scope": "artifact", "reason": "blocked"},
        )
    finally:
        daemon.stop()

    assert payload["remaining_pending_count"] == 0
    assert payload["next_selectable_request_id"] is None
    assert payload["remaining_pending_summaries"] == []


def test_resolving_duplicate_group_reports_collapsed_ids(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-active"), _request("req-unrelated", command="cat ~/.pypirc")])
    _force_duplicate_row(store, "req-duplicate", "req-active")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-active/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert payload["resolved_duplicate_ids"] == ["req-duplicate"]
    assert payload["remaining_pending_count"] == 1
    assert payload["next_selectable_request_id"] == "req-unrelated"


def test_broad_scope_resolution_refreshes_queue_envelope(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-active"), _request("req-covered", command="cat ~/.pypirc")])
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-active/approve",
            {"scope": "harness", "reason": "trust this harness"},
        )
    finally:
        daemon.stop()

    assert payload["remaining_pending_count"] == 0
    assert payload["next_selectable_request_id"] is None
    assert payload["resolved_scope_ids"] == ["req-covered"]


def test_resolving_stale_item_returns_recovery_payload(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-stale")])
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-stale/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
        status, payload = _post_error(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-stale/approve",
            {"scope": "artifact", "reason": "reviewed again"},
        )
    finally:
        daemon.stop()

    assert status == 409
    assert payload["error"] == "already_resolved"
    assert payload["recovery"]["code"] == "request_resolved"


def test_resolving_missing_item_returns_recovery_payload(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        status, payload = _post_error(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/missing/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert status == 404
    assert payload["error"] == "not_found"
    assert payload["recovery"]["code"] == "request_unknown"


def test_request_resolution_without_auth_returns_session_recovery(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-auth")])
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/requests/req-auth/approve",
            data=json.dumps({"scope": "artifact"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as error:
            status = error.code
            payload = json.loads(error.read().decode("utf-8"))
        else:
            raise AssertionError("expected HTTPError")
    finally:
        daemon.stop()

    assert status == 401
    assert payload["error"] == "unauthorized"
    assert payload["recovery"]["code"] == "session_stale"
    assert "Request failed with 401" not in json.dumps(payload)


def test_request_list_status_filter_includes_resolved_items(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-resolved"), _request("req-pending")])
    store.resolve_approval_request(
        "req-resolved",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="reviewed",
        resolved_at="2026-05-08T10:03:00+00:00",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        resolved_page = _get_json(daemon.port, "/v1/requests?status=resolved")
        all_page = _get_json(daemon.port, "/v1/requests?status=all")
    finally:
        daemon.stop()

    assert [item["request_id"] for item in resolved_page["items"]] == ["req-resolved"]
    assert {item["request_id"] for item in all_page["items"]} == {"req-pending", "req-resolved"}


def test_request_list_limit_cursor_search_and_harness_filters(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(
        store,
        [
            _request("req-codex-command", command="cat ~/.npmrc"),
            _request("req-codex-prompt", command="", prompt_excerpt="Review plugin prompt excerpt"),
            _request("req-codex-mcp", command="", mcp_server="filesystem", mcp_tool="read_secret"),
            _request("req-copilot", harness="copilot", command="cat ~/.npmrc"),
        ],
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        first_page = _get_json(daemon.port, "/v1/requests?limit=2")
        second_page = _get_json(
            daemon.port,
            f"/v1/requests?limit=2&cursor={urllib.parse.quote(str(first_page['next_cursor']))}",
        )
        command_match = _get_json(daemon.port, "/v1/requests?search=npmrc&harness=codex")
        prompt_match = _get_json(daemon.port, "/v1/requests?search=plugin%20prompt")
        mcp_match = _get_json(daemon.port, "/v1/requests?search=read_secret")
        harness_match = _get_json(daemon.port, "/v1/requests?harness=copilot")
        bad_limit_status = None
        try:
            _get_json(daemon.port, "/v1/requests?limit=banana")
        except urllib.error.HTTPError as error:
            bad_limit_status = error.code
    finally:
        daemon.stop()

    assert [item["request_id"] for item in first_page["items"]] == ["req-copilot", "req-codex-mcp"]
    assert [item["request_id"] for item in second_page["items"]] == ["req-codex-prompt", "req-codex-command"]
    assert {item["request_id"] for item in command_match["items"]} == {"req-codex-command"}
    assert {item["request_id"] for item in prompt_match["items"]} == {"req-codex-prompt"}
    assert {item["request_id"] for item in mcp_match["items"]} == {"req-codex-mcp"}
    assert {item["request_id"] for item in harness_match["items"]} == {"req-copilot"}
    assert bad_limit_status == 400
