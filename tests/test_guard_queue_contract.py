"""Guard approval queue continuity contract tests."""

from __future__ import annotations

import json
import sqlite3
import urllib.parse
import urllib.request
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store as store_module
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_approvals import (
    InvalidApprovalCursorError,
    add_approval_request,
    approval_index_statements,
    approval_schema_statement,
    list_approval_requests,
    list_pending_approval_summaries,
    resolve_request_with_queue_result,
)


def _connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(approval_schema_statement())
    for statement in approval_index_statements():
        connection.execute(statement)
    return connection


def _request(
    request_id: str,
    *,
    artifact_id: str = "codex:project:tool",
    workspace: str = "workspace-a",
    command: str = "cat ~/.npmrc",
    target_paths: tuple[str, ...] = ("~/.npmrc",),
    network_hosts: tuple[str, ...] = (),
    mcp_server: str | None = None,
    mcp_tool: str | None = None,
    created_path: Path | None = None,
) -> GuardApprovalRequest:
    action_envelope = {
        "action_type": "mcp_tool_call" if mcp_tool else "shell_command",
        "tool_name": "mcp" if mcp_tool else "Bash",
        "command": command,
        "target_paths": list(target_paths),
        "network_hosts": list(network_hosts),
        "mcp_server": mcp_server,
        "mcp_tool": mcp_tool,
    }
    config_path = str((created_path or Path("/workspace")) / ".codex" / "config.toml")
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=artifact_id,
        artifact_name=artifact_id.rsplit(":", maxsplit=1)[-1],
        artifact_hash=f"hash-{request_id}",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("args",),
        source_scope="project",
        config_path=config_path,
        workspace=workspace,
        launch_target=command,
        action_envelope_json=action_envelope,
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1/pending/{request_id}",
    )


def _post_json(port: int, token: str, path: str, payload: dict[str, object]) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _get_json(port: int, path: str, *, token: str | None = None) -> dict[str, object]:
    headers: dict[str, str] = {}
    if token is not None:
        headers["X-Guard-Token"] = token
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def test_duplicate_requeue_preserves_first_seen_and_increments_dedupe_count() -> None:
    connection = _connection()
    first = _request("req-first")
    duplicate = _request("req-duplicate")

    first_id = add_approval_request(connection, first, "2026-05-08T10:00:00+00:00")
    second_id = add_approval_request(connection, duplicate, "2026-05-08T10:01:00+00:00")
    rows = list_approval_requests(connection, status="pending", limit=None)

    assert first_id == "req-first"
    assert second_id == "req-first"
    assert len(rows) == 1
    assert rows[0]["request_id"] == "req-first"
    assert rows[0]["dedupe_count"] == 2
    assert rows[0]["created_at"] == "2026-05-08T10:00:00+00:00"
    assert rows[0]["last_seen_at"] == "2026-05-08T10:01:00+00:00"
    assert isinstance(rows[0]["action_identity"], str)
    assert str(rows[0]["queue_group_id"]).startswith("approval-group:v1:")


def test_distinct_sensitive_paths_do_not_collapse() -> None:
    connection = _connection()
    npm = _request("req-npm", command="cat ~/.npmrc", target_paths=("~/.npmrc",))
    pypi = _request("req-pypi", command="cat ~/.pypirc", target_paths=("~/.pypirc",))

    add_approval_request(connection, npm, "2026-05-08T10:00:00+00:00")
    add_approval_request(connection, pypi, "2026-05-08T10:01:00+00:00")
    rows = list_approval_requests(connection, status="pending", limit=None)

    assert {row["request_id"] for row in rows} == {"req-npm", "req-pypi"}
    assert len({row["queue_group_id"] for row in rows}) == 2


def test_distinct_mcp_tools_do_not_collapse() -> None:
    connection = _connection()
    read_tool = _request(
        "req-read",
        command="",
        target_paths=(),
        mcp_server="local-tools",
        mcp_tool="read_secret",
    )
    write_tool = _request(
        "req-write",
        command="",
        target_paths=(),
        mcp_server="local-tools",
        mcp_tool="write_file",
    )

    add_approval_request(connection, read_tool, "2026-05-08T10:00:00+00:00")
    add_approval_request(connection, write_tool, "2026-05-08T10:01:00+00:00")
    rows = list_approval_requests(connection, status="pending", limit=None)

    assert {row["request_id"] for row in rows} == {"req-read", "req-write"}
    assert len({row["action_identity"] for row in rows}) == 2


def test_distinct_network_destinations_do_not_collapse() -> None:
    connection = _connection()
    first = _request(
        "req-api",
        command="curl https://api.example.test/health",
        target_paths=(),
        network_hosts=("api.example.test",),
    )
    second = _request(
        "req-webhook",
        command="curl https://webhook.example.test/health",
        target_paths=(),
        network_hosts=("webhook.example.test",),
    )

    add_approval_request(connection, first, "2026-05-08T10:00:00+00:00")
    add_approval_request(connection, second, "2026-05-08T10:01:00+00:00")
    rows = list_approval_requests(connection, status="pending", limit=None)

    assert {row["request_id"] for row in rows} == {"req-api", "req-webhook"}
    assert len({row["queue_group_id"] for row in rows}) == 2


def _force_duplicate_row(connection: sqlite3.Connection, request_id: str, source_request_id: str) -> None:
    connection.execute(
        """
        insert into approval_requests (
          request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
          recommended_scope, changed_fields_json, source_scope, oauth_source, config_path, workspace,
          launch_target, normalized_identity_key, action_identity, queue_group_id, dedupe_count, last_seen_at,
          transport, risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, why_now,
          launch_summary, risk_headline, action_envelope_json, decision_v2_json, fallback_cli_command,
          review_command, approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at
        )
        select ?, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
          recommended_scope, changed_fields_json, source_scope, oauth_source, config_path, workspace,
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


def test_resolve_queue_result_keeps_unrelated_pending_and_selects_next() -> None:
    connection = _connection()
    add_approval_request(connection, _request("req-old", command="cat ~/.npmrc"), "2026-05-08T10:00:00+00:00")
    add_approval_request(connection, _request("req-active", command="cat ~/.pypirc"), "2026-05-08T10:01:00+00:00")
    add_approval_request(
        connection,
        _request("req-newest", command="curl https://metadata.example/health", network_hosts=("metadata.example",)),
        "2026-05-08T10:02:00+00:00",
    )

    result = resolve_request_with_queue_result(
        connection,
        "req-active",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="reviewed",
        resolved_at="2026-05-08T10:03:00+00:00",
    )

    assert result["resolved"] is True
    assert result["item"]["request_id"] == "req-active"
    assert result["remaining_pending_count"] == 2
    assert result["next_selectable_request_id"] == "req-newest"
    assert result["resolved_duplicate_ids"] == []
    assert {item["request_id"] for item in result["remaining_pending_summaries"]} == {"req-newest", "req-old"}


def test_resolve_queue_result_returns_no_next_when_queue_empty() -> None:
    connection = _connection()
    add_approval_request(connection, _request("req-only"), "2026-05-08T10:00:00+00:00")

    result = resolve_request_with_queue_result(
        connection,
        "req-only",
        resolution_action="block",
        resolution_scope="artifact",
        reason="blocked",
        resolved_at="2026-05-08T10:03:00+00:00",
    )

    assert result["resolved"] is True
    assert result["remaining_pending_count"] == 0
    assert result["next_selectable_request_id"] is None
    assert result["remaining_pending_summaries"] == []


def test_resolve_queue_result_reports_duplicate_ids_without_unrelated_items() -> None:
    connection = _connection()
    add_approval_request(connection, _request("req-active"), "2026-05-08T10:00:00+00:00")
    _force_duplicate_row(connection, "req-duplicate", "req-active")
    add_approval_request(
        connection,
        _request("req-unrelated", command="cat ~/.pypirc", target_paths=("~/.pypirc",)),
        "2026-05-08T10:02:00+00:00",
    )

    result = resolve_request_with_queue_result(
        connection,
        "req-active",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="reviewed",
        resolved_at="2026-05-08T10:03:00+00:00",
    )

    assert result["resolved_duplicate_ids"] == ["req-duplicate"]
    assert result["remaining_pending_count"] == 1
    assert result["next_selectable_request_id"] == "req-unrelated"
    assert (
        connection.execute("select status from approval_requests where request_id = 'req-unrelated'").fetchone()[
            "status"
        ]
        == "pending"
    )


def test_duplicate_resolution_leaves_terminal_and_contract_invalid_rows_pending() -> None:
    connection = _connection()
    add_approval_request(connection, _request("req-active"), "2026-05-08T10:00:00+00:00")
    _force_duplicate_row(connection, "req-terminal", "req-active")
    _force_duplicate_row(connection, "req-malformed", "req-active")

    terminal_decision = list_approval_requests(connection, status="pending", limit=None)[0]["decision_v2_json"]
    assert isinstance(terminal_decision, dict)
    terminal_decision = {**terminal_decision, "guard_action": "block", "action": "block"}
    connection.execute(
        """
        update approval_requests
        set policy_action = 'block', decision_v2_json = ?
        where request_id = 'req-terminal'
        """,
        (json.dumps(terminal_decision),),
    )
    connection.execute(
        """
        update approval_requests
        set action_envelope_json = ?
        where request_id = 'req-malformed'
        """,
        (
            json.dumps(
                {
                    "action_type": "shell_command",
                    "pre_execution_result": "require-reapproval",
                    "preExecutionResult": "block",
                }
            ),
        ),
    )

    result = resolve_request_with_queue_result(
        connection,
        "req-active",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="reviewed",
        resolved_at="2026-05-08T10:03:00+00:00",
    )

    statuses = {
        str(row["request_id"]): str(row["status"])
        for row in connection.execute(
            "select request_id, status from approval_requests order by request_id"
        ).fetchall()
    }
    assert result["resolved"] is True
    assert result["resolved_duplicate_ids"] == []
    assert statuses == {
        "req-active": "resolved",
        "req-malformed": "pending",
        "req-terminal": "pending",
    }


def test_resolve_queue_result_reports_every_resolved_duplicate_id() -> None:
    connection = _connection()
    add_approval_request(connection, _request("req-active"), "2026-05-08T10:00:00+00:00")
    for index in range(205):
        _force_duplicate_row(connection, f"req-duplicate-{index:03d}", "req-active")

    result = resolve_request_with_queue_result(
        connection,
        "req-active",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="reviewed",
        resolved_at="2026-05-08T10:03:00+00:00",
    )
    pending_duplicates = connection.execute(
        """
        select count(*) as count
        from approval_requests
        where queue_group_id = (
          select queue_group_id from approval_requests where request_id = 'req-active'
        )
          and status = 'pending'
        """
    ).fetchone()

    assert len(result["resolved_duplicate_ids"]) == 205
    assert pending_duplicates["count"] == 0


def test_pending_summary_pagination_uses_stable_cursor() -> None:
    connection = _connection()
    for index in range(3):
        add_approval_request(
            connection,
            _request(f"req-{index}", artifact_id=f"codex:project:tool-{index}", command=f"run tool {index}"),
            f"2026-05-08T10:0{index}:00+00:00",
        )

    first_page = list_pending_approval_summaries(connection, limit=2)
    second_page = list_pending_approval_summaries(connection, limit=2, cursor=str(first_page["next_cursor"]))

    assert [item["request_id"] for item in first_page["items"]] == ["req-2", "req-1"]
    assert [item["request_id"] for item in second_page["items"]] == ["req-0"]
    assert second_page["next_cursor"] is None


def test_pending_summary_preserves_bounded_command_preview_and_category() -> None:
    connection = _connection()
    request = _request("req-compound", command="git status && bun test")
    envelope = dict(request.action_envelope_json or {})
    envelope["command_category"] = "command.git"
    request = replace(
        request,
        launch_target="Compound command findings: review required",
        action_envelope_json=envelope,
    )
    add_approval_request(connection, request, "2026-05-08T10:00:00+00:00")
    long_command = "x" * 600
    add_approval_request(
        connection,
        _request("req-long", command=long_command),
        "2026-05-08T10:01:00+00:00",
    )

    items = list_pending_approval_summaries(connection, limit=2)["items"]
    item = next(value for value in items if value["request_id"] == "req-compound")
    long_item = next(value for value in items if value["request_id"] == "req-long")

    assert item["queue_preview"] == "git status && bun test"
    assert item["queue_command_category"] == "command.git"
    assert "action_envelope_json" not in item
    assert len(long_item["queue_preview"]) == 512
    assert long_item["queue_preview"].endswith("…")


def test_pending_summary_rejects_invalid_cursor() -> None:
    connection = _connection()
    add_approval_request(connection, _request("req-only"), "2026-05-08T10:00:00+00:00")

    with pytest.raises(InvalidApprovalCursorError):
        list_pending_approval_summaries(connection, limit=2, cursor="not-a-valid-cursor")


def test_before_cursor_uses_last_seen_sort_order() -> None:
    connection = _connection()
    add_approval_request(connection, _request("req-old", command="cat ~/.npmrc"), "2026-05-08T10:00:00+00:00")
    add_approval_request(connection, _request("req-middle", command="cat ~/.pypirc"), "2026-05-08T10:01:00+00:00")
    add_approval_request(
        connection,
        _request("req-new", command="cat ~/.ssh/id_rsa", target_paths=("~/.ssh/id_rsa",)),
        "2026-05-08T10:02:00+00:00",
    )
    add_approval_request(connection, _request("req-old-again", command="cat ~/.npmrc"), "2026-05-08T10:05:00+00:00")

    rows = list_approval_requests(connection, limit=None, before_cursor="2026-05-08T10:02:00+00:00")

    assert [row["request_id"] for row in rows] == ["req-middle"]


def test_guard_store_migrates_database_missing_queue_columns(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    connection = sqlite3.connect(guard_home / "guard.db")
    try:
        connection.execute(
            """
            create table approval_requests (
              request_id text primary key,
              harness text not null,
              artifact_id text not null,
              artifact_name text not null,
              artifact_type text not null,
              artifact_hash text not null,
              publisher text,
              policy_action text not null,
              recommended_scope text not null,
              changed_fields_json text not null,
              source_scope text not null,
              config_path text not null,
              workspace text,
              launch_target text,
              normalized_identity_key text,
              transport text,
              risk_summary text,
              risk_signals_json text not null default '[]',
              artifact_label text,
              source_label text,
              trigger_summary text,
              why_now text,
              launch_summary text,
              risk_headline text,
              action_envelope_json text,
              decision_v2_json text,
              fallback_cli_command text,
              review_command text not null,
              approval_url text not null,
              status text not null,
              resolution_action text,
              resolution_scope text,
              reason text,
              created_at text not null,
              resolved_at text
            )
            """
        )
        connection.execute(
            """
            insert into approval_requests (
              request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher,
              policy_action, recommended_scope, changed_fields_json, source_scope, config_path, workspace,
              launch_target, normalized_identity_key, transport, risk_summary, risk_signals_json,
              artifact_label, source_label, trigger_summary, why_now, launch_summary, risk_headline,
              action_envelope_json, decision_v2_json, fallback_cli_command, review_command, approval_url,
              status, resolution_action, resolution_scope, reason, created_at, resolved_at
            )
            values (
              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                "req-old",
                "codex",
                "codex:project:tool",
                "tool",
                "mcp_server",
                "hash-old",
                None,
                "require-reapproval",
                "artifact",
                '["args"]',
                "project",
                str(tmp_path / "workspace" / ".codex" / "config.toml"),
                str(tmp_path / "workspace"),
                "cat ~/.npmrc",
                "cat ~/.npmrc",
                "stdio",
                "risk",
                "[]",
                None,
                None,
                None,
                None,
                None,
                None,
                '{"command":"cat ~/.npmrc","target_paths":["~/.npmrc"]}',
                None,
                None,
                "hol-guard approvals approve req-old",
                "http://127.0.0.1/pending/req-old",
                "pending",
                None,
                None,
                None,
                "2026-05-08T10:00:00+00:00",
                None,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    store = GuardStore(guard_home)
    migrated = store.get_approval_request("req-old")

    assert migrated is not None
    assert migrated["dedupe_count"] == 1
    assert migrated["last_seen_at"] == "2026-05-08T10:00:00+00:00"
    assert isinstance(migrated["action_identity"], str)
    assert str(migrated["queue_group_id"]).startswith("approval-group:v1:")


def test_queue_backfill_runs_once_per_schema_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    original = store_module.backfill_approval_queue_columns

    def recording_backfill(connection: sqlite3.Connection) -> None:
        calls.append("backfill")
        original(connection)

    monkeypatch.setattr(store_module, "backfill_approval_queue_columns", recording_backfill)

    guard_home = tmp_path / "guard-home"
    GuardStore(guard_home)
    GuardStore(guard_home)

    assert calls == ["backfill"]


def test_workspace_scope_resolution_matches_windows_paths(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(
        replace(
            _request("req-win", artifact_id="codex:project:win"),
            workspace=r"C:\repo",
            config_path=r"C:\repo\.codex\config.toml",
        ),
        "2026-05-08T10:00:00+00:00",
    )
    store.add_approval_request(
        replace(
            _request("req-win-other", artifact_id="codex:project:win-other"),
            workspace=r"C:\repo-other",
            config_path=r"C:\repo-other\.codex\config.toml",
        ),
        "2026-05-08T10:01:00+00:00",
    )

    resolved_ids = store.resolve_matching_approval_requests(
        harness="codex",
        scope="workspace",
        artifact_id=None,
        workspace=r"C:\repo",
        publisher=None,
        resolution_action="allow",
        resolution_scope="workspace",
        reason="trusted workspace",
        resolved_at="2026-05-08T10:03:00+00:00",
    )

    assert resolved_ids == ["req-win"]
    assert store.get_approval_request("req-win")["status"] == "resolved"
    assert store.get_approval_request("req-win-other")["status"] == "pending"


def test_workspace_scope_resolution_escapes_sql_wildcard_names(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(
        replace(
            _request("req-workspace", artifact_id="codex:project:wild"),
            workspace="/tmp/work_%",
            config_path="/tmp/work_%/.codex/config.toml",
        ),
        "2026-05-08T10:00:00+00:00",
    )
    store.add_approval_request(
        replace(
            _request("req-neighbor", artifact_id="codex:project:neighbor"),
            workspace="/tmp/work-A",
            config_path="/tmp/work-A/.codex/config.toml",
        ),
        "2026-05-08T10:01:00+00:00",
    )

    resolved_ids = store.resolve_matching_approval_requests(
        harness="codex",
        scope="workspace",
        artifact_id=None,
        workspace="/tmp/work_%",
        publisher=None,
        resolution_action="allow",
        resolution_scope="workspace",
        reason="trusted workspace",
        resolved_at="2026-05-08T10:03:00+00:00",
    )

    assert resolved_ids == ["req-workspace"]
    assert store.get_approval_request("req-workspace")["status"] == "resolved"
    assert store.get_approval_request("req-neighbor")["status"] == "pending"


def test_workspace_scope_resolution_preserves_root_workspace(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.add_approval_request(
        replace(
            _request("req-root", artifact_id="codex:project:root"),
            workspace="/",
            config_path="/repo/.codex/config.toml",
        ),
        "2026-05-08T10:00:00+00:00",
    )

    resolved_ids = store.resolve_matching_approval_requests(
        harness="codex",
        scope="workspace",
        artifact_id=None,
        workspace="/",
        publisher=None,
        resolution_action="allow",
        resolution_scope="workspace",
        reason="trusted root workspace",
        resolved_at="2026-05-08T10:03:00+00:00",
    )

    assert resolved_ids == ["req-root"]
    assert store.get_approval_request("req-root")["status"] == "resolved"


def test_broad_scope_resolution_leaves_terminal_and_contract_invalid_rows_pending(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    for index, request_id in enumerate(("req-valid", "req-terminal", "req-malformed")):
        store.add_approval_request(
            _request(request_id, artifact_id=f"codex:project:{request_id}"),
            f"2026-05-08T10:0{index}:00+00:00",
        )

    terminal = store.get_approval_request("req-terminal")
    assert terminal is not None
    terminal_decision = terminal["decision_v2_json"]
    assert isinstance(terminal_decision, dict)
    with store._connect() as connection:
        connection.execute(
            """
            update approval_requests
            set policy_action = 'sandbox-required', decision_v2_json = ?
            where request_id = 'req-terminal'
            """,
            (json.dumps({**terminal_decision, "guard_action": "sandbox-required", "action": "ask"}),),
        )
        connection.execute(
            """
            update approval_requests
            set action_envelope_json = ?
            where request_id = 'req-malformed'
            """,
            (
                json.dumps(
                    {
                        "action_type": "shell_command",
                        "pre_execution_result": "require-reapproval",
                        "preExecutionResult": "block",
                    }
                ),
            ),
        )

    resolved_ids = store.resolve_matching_approval_requests(
        harness=None,
        scope="global",
        artifact_id=None,
        workspace=None,
        publisher=None,
        resolution_action="allow",
        resolution_scope="global",
        reason="trusted globally",
        resolved_at="2026-05-08T10:04:00+00:00",
    )

    assert resolved_ids == ["req-valid"]
    assert store.get_approval_request("req-valid")["status"] == "resolved"
    assert store.get_approval_request("req-terminal")["status"] == "pending"
    assert store.get_approval_request("req-malformed")["status"] == "pending"


def test_daemon_resolution_envelope_and_request_filters(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    for index, command in enumerate(("cat ~/.npmrc", "cat ~/.pypirc", "curl https://metadata.example/health")):
        target_path = "~/.npmrc" if "npmrc" in command else "~/.pypirc" if "pypirc" in command else ""
        store.add_approval_request(
            _request(
                f"req-{index}",
                artifact_id=f"codex:project:tool-{index}",
                command=command,
                target_paths=(target_path,) if target_path else (),
                created_path=tmp_path / f"workspace-{index}",
            ),
            f"2026-05-08T10:0{index}:00+00:00",
        )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        result = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-2/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
        filtered = _get_json(
            daemon.port,
            f"/v1/requests?search={urllib.parse.quote('npmrc')}&harness=codex&limit=1",
            token=daemon._server.auth_token,
        )
        runtime = _get_json(daemon.port, "/v1/runtime?active_request_id=req-1", token=daemon._server.auth_token)
    finally:
        daemon.stop()

    assert result["resolved"] is True
    assert result["remaining_pending_count"] == 2
    assert result["next_selectable_request_id"] == "req-1"
    assert [item["request_id"] for item in filtered["items"]] == ["req-0"]
    assert filtered["total_pending_count"] == 1
    assert runtime["queue_summary"]["active_request_id"] == "req-1"
    assert runtime["queue_summary"]["next_request_id"] == "req-1"
