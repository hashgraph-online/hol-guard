from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import (
    RuntimeHookEvidenceWriter,
    _NativeDecisionReceiptRecord,
)
from codex_plugin_scanner.guard.native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt
from codex_plugin_scanner.guard.native_response_decoder import response_from_payload
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_native_decision_receipts import native_decision_receipt_schema_statement


def _receipt(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "",
        "request_id": "request-1",
        "request_digest": "a" * 64,
        "harness": "claude-code",
        "event_name": "PostToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": "b" * 64,
        "rule_digest": "c" * 64,
        "runtime_identity": "d" * 64,
        "decision": "allow",
        "model_output_action": "allow_original",
        "policy_action": "allow",
        "observed_policy_action": None,
        "reason_code": "native_clean_output",
        "workspace_bound": True,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": 750,
    }
    value.update(overrides)
    identity = {
        "schema": "guard-native-hook-decision-identity.v1",
        "version": 1,
        **{key: value[key] for key in value if key not in {"schema", "version", "authority", "decision_id"}},
    }
    value["decision_id"] = hashlib.sha256(
        json.dumps(identity, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return value


def test_receipt_is_strictly_redacted_and_identity_bound() -> None:
    receipt = _receipt()
    assert validate_native_decision_receipt(receipt) == receipt
    with_raw = dict(receipt)
    with_raw["command"] = "private command"
    assert validate_native_decision_receipt(with_raw) is None
    with_bad_id = dict(receipt)
    with_bad_id["decision_id"] = "not-a-digest"
    assert validate_native_decision_receipt(with_bad_id) is None
    with_mutated_identity = dict(receipt)
    with_mutated_identity["reason_code"] = "native_other_reason"
    assert validate_native_decision_receipt(with_mutated_identity) is None


def test_prompt_receipt_requires_matching_native_prompt_result() -> None:
    receipt = _receipt(
        event_name="UserPromptSubmit",
        decision="deny",
        model_output_action="not_applicable",
        policy_action="block",
        reason_code="native_guard_bypass_prompt",
        prompt_risk_classes=["local_env_read", "exfil_intent", "guard_bypass_intent"],
    )
    result = {
        "schema": "guard-pre-tool-result.v1",
        "authority": "rust",
        "decision": "deny",
        "policy_action": "block",
        "minimum_action": "block",
        "reason_code": "native_guard_bypass_prompt",
        "prompt_risk_classes": ["local_env_read", "exfil_intent", "guard_bypass_intent"],
        "action": {"event": "UserPromptSubmit", "action_type": "prompt"},
    }
    edge = {
        "schema": "guard-hook-edge-result.v2",
        "authority": "rust",
        "harness": "claude-code",
        "event_name": "UserPromptSubmit",
        "payload_kind": "inline",
        "result": result,
    }
    assert validate_native_decision_receipt(receipt) == receipt
    assert receipt_matches_edge(edge, receipt)
    assert not receipt_matches_edge({**edge, "result": {**result, "decision": "allow"}}, receipt)
    other_action = {**result, "action": {"event": "PreToolUse", "action_type": "prompt"}}
    assert not receipt_matches_edge({**edge, "result": other_action}, receipt)
    changed_classes = {**result, "prompt_risk_classes": ["local_env_read"]}
    assert not receipt_matches_edge({**edge, "result": changed_classes}, receipt)
    assert validate_native_decision_receipt({**receipt, "prompt_risk_classes": ["guard_bypass_intent"]}) is None


@pytest.mark.parametrize(
    "classes",
    (
        [],
        ["local_env_read", "local_env_read"],
        ["guard_bypass_intent", "local_env_read"],
        ["unexpected_class"],
        ["local_env_read"] * 7,
    ),
)
def test_prompt_risk_classes_reject_unknown_duplicate_or_unbounded_values(classes: list[str]) -> None:
    receipt = _receipt(event_name="UserPromptSubmit", model_output_action="not_applicable", prompt_risk_classes=classes)
    assert validate_native_decision_receipt(receipt) is None
    tool = _receipt(event_name="PreToolUse", prompt_risk_classes=["local_env_read"])
    assert validate_native_decision_receipt(tool) is None


def test_receipt_handoff_never_waits_for_persistence(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()

    def persist(**_kwargs: object) -> bool:
        entered.set()
        assert release.wait(timeout=1)
        return True

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_native_decision_receipt",
        side_effect=persist,
    ):
        writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path / "guard-home"), batch_wait_seconds=0)
        try:
            started = time.monotonic()
            assert writer.submit_native_decision_receipt(receipt=_receipt())
            assert time.monotonic() - started < 0.1
            assert entered.wait(timeout=1)
            journal = (tmp_path / "guard-home" / "runtime-hook-evidence.jsonl").read_text(encoding="utf-8")
            assert "private command" not in journal
            release.set()
            assert writer.stop(timeout_seconds=1)
        finally:
            release.set()
            if writer.stats()["running"]:
                writer.stop(timeout_seconds=1)
    assert writer.stats()["receipt_processed"] == 1


def test_receipt_shutdown_journals_before_expiry(tmp_path: Path) -> None:
    writer = RuntimeHookEvidenceWriter(
        store=GuardStore(tmp_path / "guard-home"),
        batch_wait_seconds=0,
    )
    try:
        with patch.object(writer, "_drain_expired", return_value=True):
            assert writer.submit_native_decision_receipt(receipt=_receipt())
            assert writer.stop(timeout_seconds=1)
        journal = (tmp_path / "guard-home" / "runtime-hook-evidence.jsonl").read_text(encoding="utf-8")
    finally:
        if writer.stats()["running"]:
            assert writer.stop(timeout_seconds=1)

    assert "private command" not in journal
    assert writer.stats()["receipt_processed"] == 0
    assert writer.stats()["receipt_durable_pending"] == 1


def test_journal_rewrite_preserves_another_writer_receipt(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    first = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), batch_wait_seconds=0)
    second = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), batch_wait_seconds=0)
    first_record = _NativeDecisionReceiptRecord(receipt=_receipt(request_id="first"), payload_bytes=0)
    second_record = _NativeDecisionReceiptRecord(receipt=_receipt(request_id="second"), payload_bytes=0)
    try:
        first._append_journal(first_record)
        second._append_journal(second_record)
        first._rewrite_journal(remove_record_id=first_record.record_id)
    finally:
        assert first.stop(timeout_seconds=1)
        assert second.stop(timeout_seconds=1)

    lines = (guard_home / "runtime-hook-evidence.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["request_id"] == "second"


def test_receipt_queue_full_degrades_without_changing_decision(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()

    def persist(**_kwargs: object) -> bool:
        entered.set()
        assert release.wait(timeout=1)
        return True

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_native_decision_receipt",
        side_effect=persist,
    ):
        writer = RuntimeHookEvidenceWriter(
            store=GuardStore(tmp_path / "guard-home"),
            max_records=1,
            batch_wait_seconds=0,
        )
        try:
            assert writer.submit_native_decision_receipt(receipt=_receipt())
            assert entered.wait(timeout=1)
            assert writer.submit_native_decision_receipt(receipt=_receipt(request_id="request-2"))
            assert not writer.submit_native_decision_receipt(receipt=_receipt(request_id="request-3"))
            assert writer.stats()["receipt_dropped"] == 1
        finally:
            release.set()
            assert writer.stop(timeout_seconds=1)


def test_receipt_sqlite_failure_is_recoverable_and_bounded(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    failed = threading.Event()

    def fail(**_kwargs: object) -> bool:
        failed.set()
        raise sqlite3.OperationalError("database is locked")

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_native_decision_receipt",
        side_effect=fail,
    ):
        first = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), batch_wait_seconds=0)
        assert first.submit_native_decision_receipt(receipt=_receipt())
        assert failed.wait(timeout=1)
        assert first.stop(timeout_seconds=0.1)
        assert first.stats()["receipt_durable_pending"] == 1

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_native_decision_receipt",
        return_value=True,
    ):
        recovered = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), batch_wait_seconds=0)
        assert recovered.stop(timeout_seconds=1)
    assert recovered.stats()["recovered"] == 1
    assert recovered.stats()["receipt_processed"] == 1
    assert recovered.stats()["receipt_durable_pending"] == 0


def test_store_receipt_insert_is_idempotent(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipt = _receipt()
    assert store.record_native_decision_receipt(receipt)
    assert store.record_native_decision_receipt(receipt)
    assert store.native_decision_receipt_count() == 1


def test_prompt_receipt_persists_without_rewriting_tool_receipt_schema(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    tool = _receipt()
    prompt = _receipt(
        event_name="UserPromptSubmit",
        decision="deny",
        model_output_action="not_applicable",
        policy_action="block",
        reason_code="native_guard_bypass_prompt",
        prompt_risk_classes=["local_env_read", "exfil_intent", "guard_bypass_intent"],
    )
    assert store.record_native_decision_receipt(tool)
    assert store.record_native_decision_receipt(prompt)
    assert store.native_decision_receipt_count() == 2
    assert store.get_native_decision_receipt(tool["decision_id"]) == tool
    assert store.get_native_decision_receipt(prompt["decision_id"]) == prompt
    with store._connect() as connection:
        legacy = connection.execute(
            "select sql from sqlite_schema where type = 'table' and name = 'native_hook_decision_receipts'"
        ).fetchone()[0]
        assert "event_name in ('PreToolUse', 'PostToolUse')" in legacy
        assert connection.execute("select count(*) from schema_migrations where version = 29").fetchone()[0] == 1
        connection.execute(
            "update native_prompt_decision_receipts set prompt_risk_classes_json = ? where decision_id = ?",
            ('["guard_bypass_intent"]', prompt["decision_id"]),
        )
    assert store.get_native_decision_receipt(prompt["decision_id"]) is None
    assert store.get_native_decision_receipt(tool["decision_id"]) == tool


def test_existing_tool_receipt_schema_gains_prompt_storage_additively(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    with sqlite3.connect(guard_home / "guard.db") as connection:
        connection.execute(native_decision_receipt_schema_statement())
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        connection.execute("insert into schema_migrations values (26, '2026-01-01T00:00:00Z')")
    store = GuardStore(guard_home, prime_policy_integrity=False)
    existing = _receipt()
    prompt = _receipt(
        event_name="UserPromptSubmit",
        decision="deny",
        model_output_action="not_applicable",
        policy_action="block",
        reason_code="native_guard_bypass_prompt",
    )
    assert store.record_native_decision_receipt(existing)
    assert store.record_native_decision_receipt(prompt)
    assert store.get_native_decision_receipt(existing["decision_id"]) == existing
    assert store.get_native_decision_receipt(prompt["decision_id"]) == prompt
    with store._connect() as connection:
        legacy = connection.execute(
            "select sql from sqlite_schema where type = 'table' and name = 'native_hook_decision_receipts'"
        ).fetchone()[0]
        assert "event_name in ('PreToolUse', 'PostToolUse')" in legacy
        assert connection.execute("select count(*) from schema_migrations where version = 29").fetchone()[0] == 1


def test_store_initializes_receipt_schema_marker_and_recorded_at_index(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    with store._connect() as connection:
        table_row = connection.execute(
            "select 1 from sqlite_schema where type = 'table' and name = 'native_hook_decision_receipts'"
        ).fetchone()
        assert table_row is not None and table_row[0] == 1
        migration_row = connection.execute("select 1 from schema_migrations where version = 26").fetchone()
        assert migration_row is not None and migration_row[0] == 1
        indexes = {str(row[1]) for row in connection.execute("pragma index_list(native_hook_decision_receipts)")}
    assert "idx_native_hook_decision_receipts_recorded_at" in indexes


def test_post_tool_edge_decoder_requires_receipt_bound_to_result() -> None:
    result = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "notice": "none",
        "reason_code": "native_clean_output",
        "policy_action": "allow",
        "observed_policy_action": None,
        "reviewed_output_sha256": None,
        "observe_mode": False,
    }
    edge = {
        "schema": "guard-hook-edge-result.v2",
        "authority": "rust",
        "harness": "claude-code",
        "event_name": "PostToolUse",
        "payload_kind": "inline",
        "result": result,
        "receipt": _receipt(),
    }
    assert response_from_payload(edge) is not None

    missing_receipt = dict(edge)
    del missing_receipt["receipt"]
    assert response_from_payload(missing_receipt) is None

    mutated_result = dict(edge)
    mutated_result["result"] = {**result, "decision": "deny"}
    assert response_from_payload(mutated_result) is None
