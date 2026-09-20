"""Atomic package evidence persistence retains row and replay semantics."""

from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.store_evidence import (
    EvidenceRecord,
    ensure_evidence_schema,
    list_evidence,
    store_evidence,
    store_evidence_batch,
)


def record(identity: str, *, details=None) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=identity,
        action_id="package:test",
        request_id="request",
        harness="codex",
        workspace="project",
        signal_id="block",
        category="supply-chain",
        severity="critical",
        confidence=1.0,
        summary="Synthetic package evidence",
        details=details or {},
        action_identity="rule-1",
        created_at="2026-05-19T00:00:00Z",
    )


def connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    ensure_evidence_schema(conn)
    return conn


def test_batch_matches_single_record_storage_and_duplicate_replacement():
    records = [record("one", details={"path": "dependency"}), record("two"), record("one", details={"last": True})]
    with connection() as single, connection() as batch:
        for item in records:
            store_evidence(single, item)
        store_evidence_batch(batch, iter(records))
        expected = sorted(list_evidence(single), key=lambda item: item.evidence_id)
        assert sorted(list_evidence(batch), key=lambda item: item.evidence_id) == expected
        store_evidence_batch(batch, iter(records))
        assert sorted(list_evidence(batch), key=lambda item: item.evidence_id) == expected


def test_batch_serialization_failure_rolls_back_inserts_and_replacements():
    with connection() as conn:
        original = record("existing", details={"original": True})
        store_evidence(conn, original)
        records = [
            replace(original, details={"replacement": True}),
            record("new"),
            record("bad", details={"bad": object()}),
        ]
        with pytest.raises(TypeError):
            store_evidence_batch(conn, records)
        assert list_evidence(conn) == [original]
        assert not conn.in_transaction


def test_batch_sql_failure_rolls_back_and_keeps_connection_usable():
    with connection() as conn:
        conn.execute("""create trigger reject_evidence before insert on guard_evidence
                        when NEW.evidence_id = 'reject' begin select raise(ABORT, 'synthetic failure'); end""")
        with pytest.raises(sqlite3.IntegrityError, match="synthetic failure"):
            store_evidence_batch(conn, [record("first"), record("reject"), record("last")])
        assert list_evidence(conn) == []
        store_evidence_batch(conn, [record("recovery")])
        assert [item.evidence_id for item in list_evidence(conn)] == ["recovery"]
