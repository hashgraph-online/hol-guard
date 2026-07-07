"""Phase 14 — approval store scale: indexes, cursor pagination, bulk ops, and migrations."""

from __future__ import annotations

import dataclasses
import sqlite3
import time
import uuid

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store_approvals import (
    add_approval_request,
    approval_index_statements,
    approval_schema_statement,
    bulk_resolve_approval_requests,
    clear_approval_requests_by_harness,
    clear_approval_requests_by_scope,
    clear_approval_requests_by_workspace,
    clear_resolved_approval_requests_before,
    compact_approval_requests,
    count_approval_requests,
    get_approval_request,
    list_approval_requests,
    list_pending_approval_summaries,
    resolve_approval_request,
    resolve_request_with_queue_result,
)


def _make_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("pragma journal_mode=wal")
    conn.execute(approval_schema_statement())
    for stmt in approval_index_statements():
        conn.execute(stmt)
    return conn


def _make_request(
    *,
    harness: str = "codex",
    workspace: str | None = "ws-a",
    artifact_id: str | None = None,
    policy_action: str = "require-reapproval",
    source_scope: str = "project",
) -> GuardApprovalRequest:
    aid = artifact_id or f"codex:project:tool-{uuid.uuid4().hex[:8]}"
    rid = str(uuid.uuid4())
    return GuardApprovalRequest(
        request_id=rid,
        harness=harness,
        artifact_id=aid,
        artifact_name="tool",
        artifact_type="mcp_server",
        artifact_hash="abc123",
        publisher=None,
        policy_action=policy_action,
        recommended_scope="session",
        changed_fields=frozenset(["args"]),
        source_scope=source_scope,
        config_path="/tmp/config.toml",
        workspace=workspace,
        launch_target=None,
        transport="stdio",
        risk_summary="risk",
        risk_signals=[],
        artifact_label=None,
        source_label=None,
        trigger_summary=None,
        why_now=None,
        launch_summary=None,
        risk_headline=None,
        action_envelope_json=None,
        decision_v2_json=None,
        review_command=f"hol-guard review {rid}",
        approval_url=f"http://localhost:4455/approve/{rid}",
    )


def _insert(conn: sqlite3.Connection, req: GuardApprovalRequest, now: str = "2026-01-01T00:00:00Z") -> str:
    return add_approval_request(conn, req, now)


def _bulk_insert_pending(conn: sqlite3.Connection, total: int) -> None:
    rows = []
    for index in range(total):
        timestamp = f"2026-01-01T00:00:00.{index:06d}Z"
        rows.append(
            (
                f"req-{index:06d}",
                "codex",
                f"codex:project:tool-{index:06d}",
                f"tool-{index:06d}",
                "mcp_server",
                f"hash-{index:06d}",
                None,
                "require-reapproval",
                "session",
                '["args"]',
                "project",
                "/tmp/config.toml",
                "ws-a",
                f"run tool {index:06d}",
                f"run tool {index:06d}",
                f"identity-{index:06d}",
                f"approval-group:v1:{index:064d}",
                1,
                timestamp,
                "stdio",
                "risk",
                "[]",
                None,
                None,
                None,
                None,
                None,
                None,
                f'{{"command":"run tool {index:06d}"}}',
                None,
                None,
                f"hol-guard review req-{index:06d}",
                f"http://localhost:4455/approve/req-{index:06d}",
                "pending",
                None,
                None,
                None,
                timestamp,
                None,
            )
        )
    conn.executemany(
        """
        insert into approval_requests (
          request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
          recommended_scope, changed_fields_json, source_scope, config_path, workspace,
          launch_target, normalized_identity_key, action_identity, queue_group_id, dedupe_count, last_seen_at,
          transport, risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, why_now,
          launch_summary, risk_headline, action_envelope_json, decision_v2_json, fallback_cli_command,
          review_command, approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at
        )
        values (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        rows,
    )


class TestApprovalIndexStatements:
    def test_index_statements_returns_nonempty_list(self) -> None:
        stmts = approval_index_statements()
        assert isinstance(stmts, list)
        assert len(stmts) >= 6

    def test_index_statements_are_create_index(self) -> None:
        for stmt in approval_index_statements():
            assert "create index" in stmt.lower()

    def test_indexes_execute_without_error(self) -> None:
        _make_conn()


class TestCursorPagination:
    def test_list_returns_all_when_no_cursor(self) -> None:
        conn = _make_conn()
        for i in range(5):
            _insert(conn, _make_request(), f"2026-01-0{i + 1}T00:00:00Z")
        rows = list_approval_requests(conn, status="pending", limit=10)
        assert len(rows) == 5

    def test_list_respects_limit(self) -> None:
        conn = _make_conn()
        for i in range(10):
            _insert(conn, _make_request(), f"2026-01-{i + 1:02d}T00:00:00Z")
        rows = list_approval_requests(conn, status="pending", limit=3)
        assert len(rows) == 3

    def test_cursor_after_skips_earlier_records(self) -> None:
        conn = _make_conn()
        for i in range(6):
            _insert(conn, _make_request(), f"2026-01-{i + 1:02d}T00:00:00Z")
        page1 = list_approval_requests(conn, status="pending", limit=3)
        assert len(page1) == 3
        cursor = page1[-1]["created_at"]
        page2 = list_approval_requests(conn, status="pending", limit=3, before_cursor=cursor)
        assert len(page2) == 3
        dates_p1 = {r["created_at"] for r in page1}
        dates_p2 = {r["created_at"] for r in page2}
        assert dates_p1.isdisjoint(dates_p2)

    def test_cursor_after_last_page_returns_empty(self) -> None:
        conn = _make_conn()
        for i in range(3):
            _insert(conn, _make_request(), f"2026-01-0{i + 1}T00:00:00Z")
        page1 = list_approval_requests(conn, status="pending", limit=3)
        cursor = page1[-1]["created_at"]
        page2 = list_approval_requests(conn, status="pending", limit=3, before_cursor=cursor)
        assert page2 == []


class TestQueueScaleTargets:
    def test_listing_first_queue_page_with_100k_rows_stays_under_100ms(self) -> None:
        conn = _make_conn()
        _bulk_insert_pending(conn, 100_000)

        started = time.perf_counter()
        page = list_pending_approval_summaries(conn, limit=25)
        elapsed = time.perf_counter() - started

        assert len(page["items"]) == 25
        assert page["total_pending_count"] == 100_000
        assert elapsed < 0.1

    def test_resolving_one_request_with_100k_rows_stays_under_100ms(self) -> None:
        conn = _make_conn()
        _bulk_insert_pending(conn, 100_000)

        started = time.perf_counter()
        result = resolve_request_with_queue_result(
            conn,
            "req-099999",
            resolution_action="allow",
            resolution_scope="artifact",
            reason="reviewed",
            resolved_at="2026-01-02T00:00:00Z",
        )
        elapsed = time.perf_counter() - started

        assert result["resolved"] is True
        assert result["remaining_pending_count"] == 99_999
        assert result["next_selectable_request_id"] == "req-099998"
        assert elapsed < 0.1

    def test_listing_queue_page_without_totals_skips_count_queries(self) -> None:
        conn = _make_conn()
        _bulk_insert_pending(conn, 50)

        page = list_pending_approval_summaries(conn, limit=10, include_totals=False)

        assert len(page["items"]) == 10
        assert "total_pending_count" not in page
        assert "total_count" not in page

    def test_listing_queue_page_without_totals_stays_under_50ms_with_100k_rows(self) -> None:
        conn = _make_conn()
        _bulk_insert_pending(conn, 100_000)

        started = time.perf_counter()
        page = list_pending_approval_summaries(conn, limit=25, include_totals=False)
        elapsed = time.perf_counter() - started

        assert len(page["items"]) == 25
        assert elapsed < 0.05


class TestSearchFilter:
    def test_search_matches_artifact_name(self) -> None:
        conn = _make_conn()
        req = _make_request()
        base = dataclasses.asdict(req)
        req2 = GuardApprovalRequest(
            **{
                **base,
                "request_id": str(uuid.uuid4()),
                "artifact_name": "special-tool",
                "artifact_id": "codex:project:special-tool",
                "changed_fields": ("args",),
            }
        )
        _insert(conn, req)
        _insert(conn, req2)
        results = list_approval_requests(conn, search="special")
        assert len(results) == 1
        assert results[0]["artifact_name"] == "special-tool"

    def test_search_is_case_insensitive(self) -> None:
        conn = _make_conn()
        req = _make_request()
        base = dataclasses.asdict(req)
        mod = GuardApprovalRequest(
            **{
                **base,
                "request_id": str(uuid.uuid4()),
                "artifact_name": "SpecialTool",
                "artifact_id": "codex:project:SpecialTool",
                "changed_fields": ("args",),
            }
        )
        _insert(conn, mod)
        results = list_approval_requests(conn, search="specialtool")
        assert len(results) == 1

    def test_search_matches_raw_command_text_in_queue_pages(self) -> None:
        conn = _make_conn()
        req = _make_request()
        base = dataclasses.asdict(req)
        mod = GuardApprovalRequest(
            **{
                **base,
                "request_id": str(uuid.uuid4()),
                "artifact_name": "Bash",
                "artifact_id": "codex:project:bash",
                "raw_command_text": "hol-guard approvals bulk allow once",
            }
        )
        _insert(conn, req)
        _insert(conn, mod)

        page = list_pending_approval_summaries(conn, search="bulk")

        assert page["total_count"] == 1
        assert page["items"][0]["request_id"] == mod.request_id
        assert page["items"][0]["raw_command_text"] == "hol-guard approvals bulk allow once"

    def test_search_matches_fallback_cli_command(self) -> None:
        conn = _make_conn()
        req = _make_request()
        base = dataclasses.asdict(req)
        mod = GuardApprovalRequest(
            **{
                **base,
                "request_id": str(uuid.uuid4()),
                "artifact_name": "Bash",
                "artifact_id": "codex:project:bash",
                "fallback_cli_command": "hol-guard approvals approve --reason bulk-import",
            }
        )
        _insert(conn, req)
        _insert(conn, mod)

        results = list_approval_requests(conn, search="bulk-import")

        assert len(results) == 1
        assert results[0]["request_id"] == mod.request_id

    def test_search_no_match_returns_empty(self) -> None:
        conn = _make_conn()
        _insert(conn, _make_request())
        results = list_approval_requests(conn, search="xyznotfound")
        assert results == []


class TestStatusFilterList:
    def test_multiple_statuses_returned(self) -> None:
        conn = _make_conn()
        req1 = _make_request()
        req2 = _make_request()
        _insert(conn, req1)
        _insert(conn, req2)
        resolve_approval_request(
            conn,
            req1.request_id,
            resolution_action="allow",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-01-02T00:00:00Z",
        )
        rows = list_approval_requests(conn, status=None)
        statuses = {r["status"] for r in rows}
        assert "pending" in statuses
        assert "resolved" in statuses

    def test_status_list_filters_correctly(self) -> None:
        conn = _make_conn()
        req = _make_request()
        _insert(conn, req)
        resolve_approval_request(
            conn,
            req.request_id,
            resolution_action="allow",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-01-02T00:00:00Z",
        )
        rows = list_approval_requests(conn, status="pending")
        assert rows == []
        rows = list_approval_requests(conn, status="resolved")
        assert len(rows) == 1


class TestHarnessFilter:
    def test_harness_filter_excludes_other_harnesses(self) -> None:
        conn = _make_conn()
        _insert(conn, _make_request(harness="codex"))
        _insert(conn, _make_request(harness="claude"))
        rows = list_approval_requests(conn, harness="codex")
        assert all(r["harness"] == "codex" for r in rows)
        assert len(rows) == 1


class TestDateRangeFilter:
    def test_after_filter_excludes_older_rows(self) -> None:
        conn = _make_conn()
        _insert(conn, _make_request(), "2026-01-01T00:00:00Z")
        _insert(conn, _make_request(), "2026-03-01T00:00:00Z")
        rows = list_approval_requests(conn, created_after="2026-02-01T00:00:00Z")
        assert len(rows) == 1
        assert rows[0]["created_at"] == "2026-03-01T00:00:00Z"

    def test_before_filter_excludes_newer_rows(self) -> None:
        conn = _make_conn()
        _insert(conn, _make_request(), "2026-01-01T00:00:00Z")
        _insert(conn, _make_request(), "2026-03-01T00:00:00Z")
        rows = list_approval_requests(conn, created_before="2026-02-01T00:00:00Z")
        assert len(rows) == 1
        assert rows[0]["created_at"] == "2026-01-01T00:00:00Z"


class TestCountFilter:
    def test_count_matches_status_filter(self) -> None:
        conn = _make_conn()
        req1 = _make_request()
        req2 = _make_request()
        _insert(conn, req1)
        _insert(conn, req2)
        resolve_approval_request(
            conn,
            req1.request_id,
            resolution_action="allow",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-01-02T00:00:00Z",
        )
        pending_count = count_approval_requests(conn, status="pending")
        resolved_count = count_approval_requests(conn, status="resolved")
        assert pending_count == 1
        assert resolved_count == 1

    def test_count_with_harness_filter(self) -> None:
        conn = _make_conn()
        _insert(conn, _make_request(harness="codex"))
        _insert(conn, _make_request(harness="claude"))
        assert count_approval_requests(conn, status="pending", harness="codex") == 1
        assert count_approval_requests(conn, status="pending", harness="claude") == 1


class TestBulkResolve:
    def test_bulk_resolve_marks_multiple_pending_resolved(self) -> None:
        conn = _make_conn()
        reqs = [_make_request() for _ in range(4)]
        for r in reqs:
            _insert(conn, r)
        ids = [reqs[0].request_id, reqs[1].request_id]
        bulk_resolve_approval_requests(
            conn,
            ids,
            resolution_action="allow",
            resolution_scope="session",
            reason="bulk",
            resolved_at="2026-01-10T00:00:00Z",
        )
        for rid in ids:
            row = get_approval_request(conn, rid)
            assert row is not None
            assert row["status"] == "resolved"
        assert get_approval_request(conn, reqs[2].request_id)["status"] == "pending"

    def test_bulk_resolve_empty_list_is_noop(self) -> None:
        conn = _make_conn()
        bulk_resolve_approval_requests(
            conn,
            [],
            resolution_action="allow",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-01-01T00:00:00Z",
        )
        assert count_approval_requests(conn) == 0


class TestClearByHarness:
    def test_clear_by_harness_removes_resolved_only(self) -> None:
        conn = _make_conn()
        pending = _make_request(harness="codex")
        resolved = _make_request(harness="codex")
        _insert(conn, pending)
        _insert(conn, resolved)
        resolve_approval_request(
            conn,
            resolved.request_id,
            resolution_action="allow",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-01-02T00:00:00Z",
        )
        deleted = clear_approval_requests_by_harness(conn, "codex")
        assert deleted == 1
        assert get_approval_request(conn, pending.request_id) is not None
        assert get_approval_request(conn, resolved.request_id) is None

    def test_clear_by_harness_does_not_touch_other_harness(self) -> None:
        conn = _make_conn()
        req = _make_request(harness="claude")
        _insert(conn, req)
        resolve_approval_request(
            conn,
            req.request_id,
            resolution_action="allow",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-01-02T00:00:00Z",
        )
        deleted = clear_approval_requests_by_harness(conn, "codex")
        assert deleted == 0
        assert get_approval_request(conn, req.request_id) is not None


class TestClearByWorkspace:
    def test_clear_by_workspace_removes_resolved_for_that_workspace(self) -> None:
        conn = _make_conn()
        req_a = _make_request(workspace="ws-a")
        req_b = _make_request(workspace="ws-b")
        _insert(conn, req_a)
        _insert(conn, req_b)
        resolve_approval_request(
            conn,
            req_a.request_id,
            resolution_action="allow",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-01-02T00:00:00Z",
        )
        resolve_approval_request(
            conn,
            req_b.request_id,
            resolution_action="allow",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-01-02T00:00:00Z",
        )
        deleted = clear_approval_requests_by_workspace(conn, "ws-a")
        assert deleted == 1
        assert get_approval_request(conn, req_a.request_id) is None
        assert get_approval_request(conn, req_b.request_id) is not None


class TestClearByScope:
    def test_clear_by_scope_removes_resolved_for_that_scope(self) -> None:
        conn = _make_conn()
        req_proj = _make_request(source_scope="project")
        req_home = _make_request(source_scope="home")
        _insert(conn, req_proj)
        _insert(conn, req_home)
        resolve_approval_request(
            conn,
            req_proj.request_id,
            resolution_action="allow",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-01-02T00:00:00Z",
        )
        resolve_approval_request(
            conn,
            req_home.request_id,
            resolution_action="allow",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-01-02T00:00:00Z",
        )
        deleted = clear_approval_requests_by_scope(conn, "project")
        assert deleted == 1
        assert get_approval_request(conn, req_proj.request_id) is None
        assert get_approval_request(conn, req_home.request_id) is not None


class TestClearResolvedBefore:
    def test_clear_before_date_removes_old_resolved(self) -> None:
        conn = _make_conn()
        old = _make_request()
        new = _make_request()
        _insert(conn, old)
        _insert(conn, new)
        resolve_approval_request(
            conn,
            old.request_id,
            resolution_action="allow",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-01-01T00:00:00Z",
        )
        resolve_approval_request(
            conn,
            new.request_id,
            resolution_action="allow",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-06-01T00:00:00Z",
        )
        deleted = clear_resolved_approval_requests_before(conn, "2026-03-01T00:00:00Z")
        assert deleted == 1
        assert get_approval_request(conn, old.request_id) is None
        assert get_approval_request(conn, new.request_id) is not None


class TestCompaction:
    def test_compaction_keeps_latest_per_artifact_id(self) -> None:
        conn = _make_conn()
        aid = "codex:project:shared-tool"
        req1 = _make_request(artifact_id=aid)
        req2 = _make_request(artifact_id=aid)
        _insert(conn, req1, "2026-01-01T00:00:00Z")
        resolve_approval_request(
            conn,
            req1.request_id,
            resolution_action="allow",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-01-02T00:00:00Z",
        )
        _insert(conn, req2, "2026-02-01T00:00:00Z")
        resolve_approval_request(
            conn,
            req2.request_id,
            resolution_action="deny",
            resolution_scope="session",
            reason=None,
            resolved_at="2026-02-02T00:00:00Z",
        )
        removed = compact_approval_requests(conn)
        assert removed == 1
        assert get_approval_request(conn, req1.request_id) is None
        assert get_approval_request(conn, req2.request_id) is not None

    def test_compaction_does_not_remove_pending(self) -> None:
        conn = _make_conn()
        aid = "codex:project:pending-tool"
        req = _make_request(artifact_id=aid)
        _insert(conn, req)
        removed = compact_approval_requests(conn)
        assert removed == 0
        assert get_approval_request(conn, req.request_id) is not None


class TestMigrationFromOldSchema:
    def test_migration_from_schema_without_indexes(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(approval_schema_statement())
        req = _make_request()
        add_approval_request(conn, req, "2026-01-01T00:00:00Z")
        for stmt in approval_index_statements():
            conn.execute(stmt)
        rows = list_approval_requests(conn, status="pending")
        assert len(rows) == 1

    def test_migration_idempotent_double_index_creation(self) -> None:
        conn = _make_conn()
        for stmt in approval_index_statements():
            conn.execute(stmt)


class TestCorruptionRecovery:
    def test_malformed_risk_signals_json_falls_back_gracefully(self) -> None:
        conn = _make_conn()
        req = _make_request()
        _insert(conn, req)
        conn.execute(
            "update approval_requests set risk_signals_json = ? where request_id = ?",
            ("not-valid-json", req.request_id),
        )
        row = get_approval_request(conn, req.request_id)
        assert row is not None
        assert isinstance(row["risk_signals"], list)

    def test_malformed_changed_fields_json_falls_back_gracefully(self) -> None:
        conn = _make_conn()
        req = _make_request()
        _insert(conn, req)
        conn.execute(
            "update approval_requests set changed_fields_json = ? where request_id = ?",
            ("{bad json}", req.request_id),
        )
        row = get_approval_request(conn, req.request_id)
        assert row is not None
        assert isinstance(row["changed_fields"], list)
