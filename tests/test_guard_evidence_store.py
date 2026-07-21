"""Phase 15: Evidence store scale — TDD tests."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from codex_plugin_scanner.guard.store_evidence import (
    EvidenceRecord,
    _sanitize_csv_formula_cell,
    compact_evidence,
    count_evidence,
    evidence_index_statements,
    evidence_schema_statement,
    export_evidence_csv,
    export_evidence_json,
    list_evidence,
    search_evidence,
    store_evidence,
)


def _db(tmp_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(tmp_path / "guard.db"))
    conn.row_factory = sqlite3.Row
    conn.execute("pragma journal_mode=wal")
    conn.execute(evidence_schema_statement())
    for stmt in evidence_index_statements():
        conn.execute(stmt)
    conn.commit()
    return conn


def _rec(**kw: object) -> EvidenceRecord:
    defaults: dict[str, object] = {
        "evidence_id": "e1",
        "action_id": "a1",
        "request_id": "r1",
        "harness": "codex",
        "workspace": "/ws",
        "signal_id": "s1",
        "category": "exfiltration",
        "severity": "high",
        "confidence": 0.9,
        "summary": "secret leaked",
        "details": {"key": "val"},
    }
    defaults.update(kw)
    return EvidenceRecord(**defaults)  # type: ignore[arg-type]


class TestSchema:
    def test_schema_creates_table(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        rows = conn.execute("select name from sqlite_master where type='table' and name='guard_evidence'").fetchall()
        assert rows

    def test_schema_idempotent(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        conn.execute(evidence_schema_statement())
        rows = conn.execute("select name from sqlite_master where type='table' and name='guard_evidence'").fetchall()
        assert len(rows) == 1

    def test_indexes_created(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        names = {r[0] for r in conn.execute("select name from sqlite_master where type='index'")}
        assert "idx_evidence_created" in names
        assert "idx_evidence_request" in names
        assert "idx_evidence_action" in names
        assert "idx_evidence_category_severity" in names
        assert "idx_evidence_harness_workspace" in names
        assert "idx_evidence_identity" in names
        assert "idx_evidence_request_created" in names
        assert "idx_evidence_identity_created" in names
        assert "idx_evidence_harness_created" in names
        assert "idx_evidence_category_severity_created" in names
        assert "idx_evidence_harness_category_severity_created" in names

    def test_indexes_idempotent(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for stmt in evidence_index_statements():
            conn.execute(stmt)
        names = [
            r[0]
            for r in conn.execute("select name from sqlite_master where type='index' and name like 'idx_evidence%'")
        ]
        assert len(names) == len(set(names))


class TestStoreEvidence:
    def test_store_basic(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec())
        rows = conn.execute("select * from guard_evidence").fetchall()
        assert len(rows) == 1

    def test_store_returns_record(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        result = store_evidence(conn, _rec(evidence_id="ev-999"))
        assert result.evidence_id == "ev-999"

    def test_store_details_serialized(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(details={"x": 1, "y": [2, 3]}))
        row = conn.execute("select details_json from guard_evidence").fetchone()
        assert json.loads(row[0]) == {"x": 1, "y": [2, 3]}

    def test_store_multiple(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for i in range(5):
            store_evidence(conn, _rec(evidence_id=f"e{i}", action_id=f"a{i}"))
        assert count_evidence(conn) == 5


class TestListEvidence:
    def test_list_all(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for i in range(3):
            store_evidence(conn, _rec(evidence_id=f"e{i}", action_id=f"a{i}"))
        records = list_evidence(conn)
        assert len(records) == 3

    def test_list_limit(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for i in range(10):
            store_evidence(conn, _rec(evidence_id=f"e{i}", action_id=f"a{i}"))
        records = list_evidence(conn, limit=3)
        assert len(records) == 3

    def test_list_filter_harness(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e1", harness="codex"))
        store_evidence(conn, _rec(evidence_id="e2", harness="claude"))
        records = list_evidence(conn, harness="codex")
        assert len(records) == 1
        assert records[0].harness == "codex"

    def test_list_filter_category(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e1", category="exfiltration"))
        store_evidence(conn, _rec(evidence_id="e2", category="injection"))
        records = list_evidence(conn, category="injection")
        assert len(records) == 1
        assert records[0].category == "injection"

    def test_list_filter_severity(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e1", severity="high"))
        store_evidence(conn, _rec(evidence_id="e2", severity="low"))
        records = list_evidence(conn, severity="high")
        assert len(records) == 1

    def test_list_cursor_pagination(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for i in range(10):
            store_evidence(conn, _rec(evidence_id=f"e{i:02d}", action_id=f"a{i}"))
            time.sleep(0.01)
        page1 = list_evidence(conn, limit=5)
        assert len(page1) == 5
        cursor = page1[-1].created_at
        page2 = list_evidence(conn, limit=10, before_cursor=cursor)
        assert len(page2) == 5
        combined_ids = {r.evidence_id for r in page1} | {r.evidence_id for r in page2}
        assert len(combined_ids) == 10

    def test_list_filter_request_id(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e1", request_id="req-A"))
        store_evidence(conn, _rec(evidence_id="e2", request_id="req-B"))
        records = list_evidence(conn, request_id="req-A")
        assert len(records) == 1

    def test_list_can_skip_details_json_for_redacted_api_rows(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e1", details={"secret": "not loaded"}))

        records = list_evidence(conn, include_details=False)

        assert len(records) == 1
        assert records[0].details == {}

    def test_list_order_desc(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for i in range(5):
            store_evidence(conn, _rec(evidence_id=f"e{i}", action_id=f"a{i}"))
            time.sleep(0.01)
        records = list_evidence(conn)
        created_ats = [r.created_at for r in records]
        assert created_ats == sorted(created_ats, reverse=True)


class TestSearchEvidence:
    def test_search_by_summary(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e1", summary="secret key leaked"))
        store_evidence(conn, _rec(evidence_id="e2", summary="benign output"))
        results = search_evidence(conn, "secret")
        assert len(results) == 1
        assert results[0].evidence_id == "e1"

    def test_search_case_insensitive(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e1", summary="Secret Token Found"))
        results = search_evidence(conn, "secret")
        assert len(results) == 1

    def test_search_no_match(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e1", summary="benign output"))
        results = search_evidence(conn, "malware")
        assert len(results) == 0

    def test_search_does_not_expose_details_json(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e1", summary="clean", details={"password": "s3cr3t"}))
        results = search_evidence(conn, "s3cr3t")
        assert len(results) == 0


class TestCountEvidence:
    def test_count_zero(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        assert count_evidence(conn) == 0

    def test_count_with_records(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for i in range(7):
            store_evidence(conn, _rec(evidence_id=f"e{i}", action_id=f"a{i}"))
        assert count_evidence(conn) == 7

    def test_count_filter_harness(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e1", harness="codex"))
        store_evidence(conn, _rec(evidence_id="e2", harness="claude"))
        store_evidence(conn, _rec(evidence_id="e3", harness="codex"))
        assert count_evidence(conn, harness="codex") == 2

    def test_count_filter_category(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e1", category="exfiltration"))
        store_evidence(conn, _rec(evidence_id="e2", category="injection"))
        assert count_evidence(conn, category="exfiltration") == 1

    def test_count_filter_harness_category_severity(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e1", harness="codex", category="secret", severity="high"))
        store_evidence(conn, _rec(evidence_id="e2", harness="codex", category="secret", severity="low"))
        store_evidence(conn, _rec(evidence_id="e3", harness="claude", category="secret", severity="high"))

        assert count_evidence(conn, harness="codex", category="secret", severity="high") == 1


class TestExportEvidence:
    def test_export_returns_privacy_envelope(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for i in range(3):
            store_evidence(conn, _rec(evidence_id=f"e{i}", action_id=f"a{i}"))
        exported = export_evidence_json(conn)
        data = json.loads(exported)
        assert data["privacy_warning"]
        assert data["total_rows"] == 3
        assert len(data["items"]) == 3

    def test_export_fields_present(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="ev-X", category="exfil", summary="found token"))
        data = json.loads(export_evidence_json(conn))
        record = data["items"][0]
        assert record["evidence_id"] == "ev-X"
        assert record["category"] == "exfil"
        assert record["summary"] == "found token"

    def test_export_limit(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for i in range(20):
            store_evidence(conn, _rec(evidence_id=f"e{i}", action_id=f"a{i}"))
        data = json.loads(export_evidence_json(conn, limit=5))
        assert data["total_rows"] == 5
        assert len(data["items"]) == 5

    def test_export_csv_includes_warning_and_redacted_rows(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(
            conn,
            _rec(
                evidence_id="csv-1",
                workspace="/Users/alice/private/project",
                summary="token sk-live-secret-value in /Users/alice/private/project/.env",
            ),
        )
        exported = export_evidence_csv(conn)
        assert "privacy_warning" in exported
        assert "sk-live-secret-value" not in exported
        assert "/Users/alice" not in exported
        assert "csv-1" in exported

    def test_export_csv_sanitizes_formula_prefixed_cells(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(
            conn,
            _rec(
                evidence_id="csv-formula-1",
                summary='=HYPERLINK("https://evil.example")',
                category="@formula",
                signal_id="\tsecret-tab",
            ),
        )

        exported = export_evidence_csv(conn)

        assert "'=HYPERLINK(" in exported
        assert "'@formula" in exported
        assert "'\tsecret-tab" in exported
        assert ",=HYPERLINK(" not in exported
        for dangerous_value in (
            "+cmd",
            "-cmd",
            "\n=FORMULA()",
        ):
            assert f"'{dangerous_value}" == _sanitize_csv_formula_cell(dangerous_value)


class TestCompactEvidence:
    def test_compact_removes_old(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="old"))
        conn.execute("update guard_evidence set created_at = '2020-01-01T00:00:00Z' where evidence_id = 'old'")
        conn.commit()
        store_evidence(conn, _rec(evidence_id="new", action_id="a2"))
        removed = compact_evidence(conn, retain_days=30)
        assert removed >= 1
        remaining = count_evidence(conn)
        assert remaining == 1

    def test_compact_keeps_recent(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for i in range(5):
            store_evidence(conn, _rec(evidence_id=f"e{i}", action_id=f"a{i}"))
        removed = compact_evidence(conn, retain_days=90)
        assert removed == 0
        assert count_evidence(conn) == 5

    def test_compact_idempotent(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e1"))
        conn.execute("update guard_evidence set created_at = '2020-01-01T00:00:00Z'")
        conn.commit()
        compact_evidence(conn, retain_days=30)
        removed2 = compact_evidence(conn, retain_days=30)
        assert removed2 == 0


class TestActionIdentityField:
    def test_store_and_retrieve_action_identity(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        rec = _rec(evidence_id="e-ai-1", action_identity="codex:tool:bash")
        store_evidence(conn, rec)
        results = list_evidence(conn, action_identity="codex:tool:bash")
        assert len(results) == 1
        assert results[0].action_identity == "codex:tool:bash"

    def test_action_identity_none_by_default(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e-ai-2"))
        results = list_evidence(conn)
        assert results[0].action_identity is None

    def test_filter_by_action_identity_excludes_others(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="e-ai-3", action_identity="tool:a"))
        store_evidence(conn, _rec(evidence_id="e-ai-4", action_identity="tool:b"))
        results = list_evidence(conn, action_identity="tool:a")
        assert len(results) == 1
        assert results[0].evidence_id == "e-ai-3"


class TestLargeScalePagination:
    def test_filtered_evidence_pages_use_ordered_indexes(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        query_prefix = (
            "select evidence_id, action_id, request_id, harness, workspace, signal_id, category, severity, "
            "confidence, summary, action_identity, created_at from guard_evidence "
        )
        cases = [
            (
                "harness",
                query_prefix + "where harness = ? order by created_at desc limit ?",
                ("codex", 100),
                "idx_evidence_harness_created",
            ),
            (
                "category/severity",
                query_prefix + "where category = ? and severity = ? order by created_at desc limit ?",
                ("secret", "high", 100),
                "idx_evidence_category_severity_created",
            ),
            (
                "harness/category/severity",
                query_prefix + "where harness = ? and category = ? and severity = ? order by created_at desc limit ?",
                ("codex", "secret", "high", 100),
                "idx_evidence_harness_category_severity_created",
            ),
            (
                "request",
                query_prefix + "where request_id = ? order by created_at desc limit ?",
                ("req-1", 100),
                "idx_evidence_request_created",
            ),
            (
                "identity",
                query_prefix + "where action_identity = ? order by created_at desc limit ?",
                ("codex:tool:bash", 100),
                "idx_evidence_identity_created",
            ),
        ]
        for label, query, params, index_name in cases:
            plan = conn.execute(f"explain query plan {query}", params).fetchall()
            detail = " ".join(str(row["detail"]) for row in plan)
            assert index_name in detail, f"{label} plan did not use {index_name}: {detail}"
            assert "USE TEMP B-TREE" not in detail, f"{label} plan sorted in a temp b-tree: {detail}"

    def test_first_page_reads_bounded_slice_from_100k_records(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        total = 100_000
        rows = [
            (
                f"bulk-{i:06d}",
                f"action-{i:06d}",
                f"request-{i:06d}",
                "codex",
                "/ws",
                "signal",
                "secret",
                "high",
                0.9,
                "secret read stopped",
                "{}",
                None,
                f"2024-01-{(i % 28) + 1:02d}T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}.{i:06d}Z",
            )
            for i in range(total)
        ]
        conn.executemany(
            """
            insert into guard_evidence
              (evidence_id, action_id, request_id, harness, workspace, signal_id, category,
               severity, confidence, summary, details_json, action_identity, created_at)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()

        page = list_evidence(conn, limit=50)

        assert count_evidence(conn) == total
        assert len(page) == 50
        assert page[0].created_at >= page[-1].created_at

    def test_cursor_pagination_covers_all_records(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        total = 250
        for i in range(total):
            ts = f"2024-01-{(i // 28) + 1:02d}T{(i % 24):02d}:00:{(i % 60):02d}Z"
            store_evidence(conn, _rec(evidence_id=f"bulk-{i:04d}", created_at=ts))

        page_size = 50
        seen: list[str] = []
        cursor: str | None = None

        for _ in range(total // page_size + 2):
            page = list_evidence(conn, before_cursor=cursor, limit=page_size)
            if not page:
                break
            seen.extend(r.evidence_id for r in page)
            cursor = page[-1].created_at

        assert len(seen) == total

    def test_first_page_returns_most_recent(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for i in range(10):
            store_evidence(conn, _rec(evidence_id=f"p-{i}", created_at=f"2024-01-01T{i:02d}:00:00Z"))
        page = list_evidence(conn, limit=3)
        assert page[0].evidence_id == "p-9"
        assert page[1].evidence_id == "p-8"
        assert page[2].evidence_id == "p-7"


class TestExportRedaction:
    def test_export_omits_details_by_default(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="ex-1", details={"secret": "password123"}))
        exported = json.loads(export_evidence_json(conn))
        assert len(exported["items"]) == 1
        assert "details" not in exported["items"][0]
        assert "password123" not in json.dumps(exported)

    def test_export_includes_details_when_redact_empty(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="ex-2", details={"key": "val"}))
        exported = json.loads(export_evidence_json(conn, redact_fields=()))
        assert len(exported["items"]) == 1
        assert exported["items"][0]["details"] == {"key": "val"}

    def test_export_includes_action_identity(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="ex-3", action_identity="tool:bash"))
        exported = json.loads(export_evidence_json(conn))
        assert exported["items"][0]["action_identity"] == "tool:bash"

    def test_export_fields_include_required_keys(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="ex-4"))
        exported = json.loads(export_evidence_json(conn))
        row = exported["items"][0]
        for key in ("evidence_id", "action_id", "request_id", "harness", "category", "severity", "summary"):
            assert key in row, f"missing key: {key}"

    def test_export_redacts_paths_and_tokens_from_all_strings(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(
            conn,
            _rec(
                evidence_id="ex-5",
                workspace="/Users/alice/private/project",
                summary="Read /Users/alice/private/project/.env with token=secret-value",
                action_identity="/Users/alice/private/project/.env",
                details={"path": "/Users/alice/private/project/.env", "token": "sk-test-secret-value"},
            ),
        )
        exported = json.loads(export_evidence_json(conn, redact_fields=()))
        encoded = json.dumps(exported)
        assert "/Users/alice" not in encoded
        assert "secret-value" not in encoded
        assert "sk-test-secret-value" not in encoded

    def test_export_redacts_oauth_secret_fields_from_evidence_strings(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        oauth_blob = (
            'sync_state.credentials={"access_token":"eyJtest.payload.signature",'
            '"refresh_token":"refresh-secret-value",'
            '"authorization_code":"auth-code-secret",'
            '"user_code":"ABCD-EFGH",'
            '"dpop_private_key_pem":"dpop-private-key-secret"}'
        )
        store_evidence(
            conn,
            _rec(
                evidence_id="ex-oauth-redaction",
                summary=f"oauth debug dump {oauth_blob}",
                details={"oauth_blob": oauth_blob},
            ),
        )

        exported = json.loads(export_evidence_json(conn, redact_fields=()))
        encoded = json.dumps(exported)

        assert "sync_state.credentials" not in encoded
        assert "eyJtest.payload.signature" not in encoded
        assert "refresh-secret-value" not in encoded
        assert "auth-code-secret" not in encoded
        assert "ABCD-EFGH" not in encoded
        assert "dpop-private-key-secret" not in encoded

    def test_export_redacts_nested_oauth_secret_fields_from_evidence_strings(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        oauth_blob = (
            'sync_state.credentials={"access_token":"eyJtest.payload.signature",'
            '"metadata":{"refresh_token":"refresh-secret-value",'
            '"nested":{"authorization_code":"auth-code-secret",'
            '"dpop_private_key_pem":"dpop-private-key-secret"}},'
            '"user_code":"ABCD-EFGH"}'
        )
        store_evidence(
            conn,
            _rec(
                evidence_id="ex-oauth-redaction-nested",
                summary=f"nested oauth debug dump {oauth_blob}",
                details={"oauth_blob": oauth_blob},
            ),
        )

        exported = json.loads(export_evidence_json(conn, redact_fields=()))
        encoded = json.dumps(exported)

        assert "sync_state.credentials" not in encoded
        assert "eyJtest.payload.signature" not in encoded
        assert "refresh-secret-value" not in encoded
        assert "auth-code-secret" not in encoded
        assert "ABCD-EFGH" not in encoded
        assert "dpop-private-key-secret" not in encoded
