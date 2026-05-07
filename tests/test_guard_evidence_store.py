"""Phase 15: Evidence store scale — TDD tests."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from codex_plugin_scanner.guard.store_evidence import (
    EvidenceRecord,
    compact_evidence,
    count_evidence,
    evidence_index_statements,
    evidence_schema_statement,
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

    def test_indexes_idempotent(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for stmt in evidence_index_statements():
            conn.execute(stmt)
        names = [
            r[0]
            for r in conn.execute(
                "select name from sqlite_master where type='index' and name like 'idx_evidence%'"
            )
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


class TestExportEvidence:
    def test_export_returns_list(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for i in range(3):
            store_evidence(conn, _rec(evidence_id=f"e{i}", action_id=f"a{i}"))
        exported = export_evidence_json(conn)
        data = json.loads(exported)
        assert isinstance(data, list)
        assert len(data) == 3

    def test_export_fields_present(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        store_evidence(conn, _rec(evidence_id="ev-X", category="exfil", summary="found token"))
        data = json.loads(export_evidence_json(conn))
        record = data[0]
        assert record["evidence_id"] == "ev-X"
        assert record["category"] == "exfil"
        assert record["summary"] == "found token"

    def test_export_limit(self, tmp_path: Path) -> None:
        conn = _db(tmp_path)
        for i in range(20):
            store_evidence(conn, _rec(evidence_id=f"e{i}", action_id=f"a{i}"))
        data = json.loads(export_evidence_json(conn, limit=5))
        assert len(data) == 5


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
