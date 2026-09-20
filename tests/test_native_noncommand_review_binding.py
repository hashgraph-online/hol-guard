"""Current noncommand review authority; synthetic malformed-wire controls."""

from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_review_approval import pause_native_pre_tool_for_approval
from codex_plugin_scanner.guard.daemon.hook_native_review_binding import (
    NATIVE_REVIEW_BINDING_FIELD,
    native_review_policy_binding,
)
from codex_plugin_scanner.guard.native_decision_receipt import (
    canonical_receipt_bytes,
    validate_native_decision_receipt,
)
from codex_plugin_scanner.guard.native_hook_edge import _decode_edge
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_mixed_witness import ReceiptWitness

from .test_native_command_observations import _observations, _receipt


def _rehash(receipt):
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()


def _case(*, harness="cursor"):
    receipt = _receipt(None)
    receipt.update(harness=harness, review_scope="noncommand", reason_code="native_network_review")
    _rehash(receipt)
    return {
        "payload": {"tool_name": "WebFetch", "tool_input": {"url": "https://example.test/docs"}},
        "snapshot": {
            "mode": "enforce",
            "generation": receipt["policy_generation"],
            **{key: receipt[key] for key in ("policy_digest", "rule_digest", "runtime_identity")},
        },
        "edge": {
            "schema": "guard-hook-edge-result.v2",
            "authority": "rust",
            "harness": harness,
            "event_name": "PreToolUse",
            "payload_kind": "inline",
            "receipt": receipt,
            "result": {
                "schema": "guard-pre-tool-result.v1",
                "version": 1,
                "authority": "rust",
                "decision": "deny",
                "minimum_action": "review",
                "policy_action": "review",
                "reason_code": receipt["reason_code"],
                "reason": "Review this network request.",
                "explicitly_benign": False,
                "action": {
                    "schema": "guard-pre-tool-action.v1",
                    "version": 1,
                    "harness": harness,
                    "event": "PreToolUse",
                    "action_type": "network",
                    "operation": "request",
                    "bounded": True,
                    "sensitive_target": False,
                },
            },
        },
    }


def _binding(case, *, workspace_bound=True):
    edge = case["edge"]
    return native_review_policy_binding(
        harness=edge["harness"],
        native_result=edge["result"],
        verified_receipt=edge["receipt"],
        policy_snapshot=case["snapshot"],
        workspace_bound=workspace_bound,
    )


def _pause(store, case):
    edge = case["edge"]
    source = case.get("source", {})
    return pause_native_pre_tool_for_approval(
        store,
        harness=edge["harness"],
        payload=case["payload"],
        native_result=edge["result"],
        native_receipt=edge["receipt"],
        verified_receipt=edge["receipt"],
        policy_snapshot=case["snapshot"],
        workspace=Path(source.get("cwd", str(store.guard_home.parent / "workspace"))),
        guard_home=store.guard_home,
        home_dir=Path(source.get("home_dir", str(store.guard_home.parent))),
    )


def _resolve(store, response, harness):
    request_id = response["approval_request_id"]
    assert store.resolve_harness_native_approval_request(
        request_id,
        reason="Explicit test approval",
        resolved_at=datetime.now(timezone.utc).isoformat(),
        expected_harness=harness,
    )
    return request_id


def assert_current_review_roundtrip(store, case):
    """Exercise original Python consumer and SQLite using supplied receipt bytes."""
    edge, receipt = case["edge"], case["edge"]["receipt"]
    assert _decode_edge(edge) == edge
    assert validate_native_decision_receipt(receipt) == receipt
    first = _pause(store, case)
    assert first["policy_action"] == "review", first
    request_id = _resolve(store, first, edge["harness"])
    binding = store.get_approval_request(request_id)["action_envelope_json"][NATIVE_REVIEW_BINDING_FIELD]
    assert binding == _binding(case)
    assert binding["schema"] == "guard.native-review-policy-binding.v2"
    assert binding["request_digest"] == receipt["request_digest"]
    assert _pause(store, case)["approval_reuse_status"] == "accepted"
    assert "approval_reuse_status" not in _pause(store, case)
    from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter

    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    try:
        assert writer.submit_native_decision_receipt(receipt=receipt)
        assert writer.stop(timeout_seconds=2)
    finally:
        if writer.stats()["running"]:
            assert writer.stop(timeout_seconds=2)
    assert writer.stats()["receipt_processed"] == 1
    assert store.get_native_decision_receipt(receipt["decision_id"]) == receipt
    witness = ReceiptWitness(SimpleNamespace(store=store), maximum=1)
    witness.observe("mixed-load-0", edge)
    witness.admitted(receipt, True)
    witness.reconcile()
    assert witness.report()["committed"] == 1
    assert witness.report()["binding_mismatches"] == 0
    # A dropped marker preserves outer IDs and row count, but loses the exact
    # native identity. Neither the public getter nor the witness may accept it.
    with store._connect() as connection:
        connection.execute(
            "delete from native_hook_review_scopes where decision_id = ?",
            (receipt["decision_id"],),
        )
    assert store.get_native_decision_receipt(receipt["decision_id"]) is None
    witness.reconcile(verify_all=True)
    assert witness.report()["binding_mismatches"] == 1


def test_current_noncommand_review_roundtrip_and_once(tmp_path):
    assert_current_review_roundtrip(GuardStore(tmp_path / "guard-home"), _case())


@pytest.mark.parametrize(
    "field,value",
    [
        ("generation", 2),
        ("generation", True),
        ("policy_digest", "f" * 64),
        ("rule_digest", "f" * 64),
        ("runtime_identity", "f" * 64),
        ("mode", "observe"),
    ],
)
def test_noncommand_scope_needs_the_selected_current_snapshot(field, value):
    case = _case()
    case["snapshot"][field] = value
    with pytest.raises(ValueError, match="native_review_policy_binding_invalid"):
        _binding(case)


@pytest.mark.parametrize("snapshot,workspace", [(None, True), ({}, True), ("valid", False), ("valid", None)])
def test_noncommand_scope_needs_current_ack_and_workspace(snapshot, workspace):
    case = _case()
    if snapshot != "valid":
        case["snapshot"] = snapshot
    with pytest.raises(ValueError, match="native_review_policy_binding_invalid"):
        _binding(case, workspace_bound=workspace)


@pytest.mark.parametrize("mutation", ["missing", "unknown", "coexist", "event", "allow", "observe", "no_policy"])
def test_marker_cannot_make_legacy_or_malformed_receipts_authoritative(mutation):
    case = _case()
    receipt = case["edge"]["receipt"]
    if mutation == "missing":
        del receipt["review_scope"]
    elif mutation == "unknown":
        receipt["review_scope"] = "command"
    elif mutation == "coexist":
        receipt["command_extensions"] = _observations()["binding"]
    elif mutation == "event":
        receipt["event_name"] = "PostToolUse"
    elif mutation == "allow":
        receipt.update(decision="allow", policy_action="allow")
    elif mutation == "observe":
        receipt["observe_mode"] = True
    else:
        receipt["policy_digest"] = None
    _rehash(receipt)
    with pytest.raises(ValueError, match="native_review_policy_binding_invalid"):
        _binding(case)


def test_marker_is_committed_to_receipt_identity():
    case = _case()
    del case["edge"]["receipt"]["review_scope"]
    assert validate_native_decision_receipt(case["edge"]["receipt"]) is None


@pytest.mark.parametrize("mutation", ["extension", "event", "harness", "operation"])
def test_noncommand_marker_needs_matching_typed_result(mutation):
    case = _case()
    result = case["edge"]["result"]
    if mutation == "extension":
        result["command_extensions"] = _observations()
    else:
        result["action"][mutation] = "invalid"
    with pytest.raises(ValueError, match="native_review_policy_binding_invalid"):
        _binding(case)


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_digest", "f" * 64),
        ("policy_generation", 2),
        ("source_ref_external_allowed", True),
        ("harness", "claude-code"),
        ("policy_digest", "f" * 64),
        ("runtime_identity", "f" * 64),
    ],
)
def test_changed_verified_noncommand_identity_cannot_reuse_old_approval(tmp_path, field, value):
    case = _case()
    store = GuardStore(tmp_path / "guard-home")
    old_id = _resolve(store, _pause(store, case), "cursor")
    receipt = case["edge"]["receipt"]
    receipt[field] = value
    if field == "harness":
        case["edge"]["harness"] = case["edge"]["result"]["action"]["harness"] = value
    if field in {"policy_digest", "runtime_identity", "policy_generation"}:
        case["snapshot"]["generation" if field == "policy_generation" else field] = value
    _rehash(receipt)
    changed = _pause(store, case)
    assert changed["policy_action"] == "review"
    assert changed["approval_request_id"] != old_id
    assert "approval_reuse_status" not in changed


def test_receipt_migration_retains_legacy_rows_without_inventing_scope(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    legacy = _receipt(None)
    store.record_native_decision_receipt(legacy)
    with store._connect() as connection:
        connection.execute("drop trigger native_hook_review_scope_cleanup")
        connection.execute("drop table native_hook_review_scopes")
        connection.execute("delete from schema_migrations where version = 29")
    store = GuardStore(tmp_path / "guard-home", daemon_managed_schema=True)
    with store._connect() as connection:
        assert connection.execute("select count(*) from native_hook_review_scopes").fetchone()[0] == 0
        assert connection.execute("select 1 from schema_migrations where version = 29").fetchone()[0] == 1
    assert store.get_native_decision_receipt(legacy["decision_id"]) == legacy
    current = _case()["edge"]["receipt"]
    store.record_native_decision_receipt(current)
    assert store.get_native_decision_receipt(current["decision_id"]) == current


def _prior_reader_projection(store, identity):
    # Reproduce the immutable prior reader's SELECT * projection and strict
    # field shape. It knows only recorded_at and command_extensions_json.
    with store._connect() as connection:
        row = connection.execute(
            "select * from native_hook_decision_receipts where decision_id = ?", (identity,)
        ).fetchone()
    result = dict(row)
    result.pop("recorded_at")
    binding = result.pop("command_extensions_json")
    if binding is not None:
        result["command_extensions"] = json.loads(binding)
    for field in ("workspace_bound", "source_ref_external_allowed", "observe_mode"):
        result[field] = bool(result[field])
    if "review_scope" in result:
        return None
    return validate_native_decision_receipt(result)


def test_sidecar_keeps_prior_command_and_posttool_reader_projection(tmp_path):
    from .test_native_decision_receipt import _receipt as posttool_receipt

    store = GuardStore(tmp_path / "guard-home")
    legacy = (_receipt(None), _receipt(_observations()), posttool_receipt())
    current = _case()["edge"]["receipt"]
    store.record_native_decision_receipts((*legacy, current))
    for receipt in legacy:
        assert _prior_reader_projection(store, receipt["decision_id"]) == receipt
        assert store.get_native_decision_receipt(receipt["decision_id"]) == receipt
    assert _prior_reader_projection(store, current["decision_id"]) is None
    assert store.get_native_decision_receipt(current["decision_id"]) == current
    # Retain a real SQLite negative control for the rejected column migration:
    # even a NULL extra field breaks old ordinary PostToolUse receipt readback.
    with store._connect() as connection:
        connection.execute("alter table native_hook_decision_receipts add column review_scope text")
    try:
        assert _prior_reader_projection(store, legacy[-1]["decision_id"]) is None
    finally:
        with store._connect() as connection:
            connection.execute("alter table native_hook_decision_receipts drop column review_scope")


def test_scope_and_receipt_commit_atomically(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    with store._connect() as connection:
        connection.execute(
            "create trigger reject_scope before insert on native_hook_review_scopes "
            "begin select raise(abort, 'test scope insert failure'); end"
        )
    with pytest.raises(sqlite3.IntegrityError, match="test scope insert failure"):
        store.record_native_decision_receipts((_receipt(None), _case()["edge"]["receipt"]))
    assert store.native_decision_receipt_count() == 0
    with store._connect() as connection:
        assert connection.execute("select count(*) from native_hook_review_scopes").fetchone()[0] == 0


def test_prior_retention_also_removes_scope_without_foreign_key_enforcement(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    receipt = _case()["edge"]["receipt"]
    store.record_native_decision_receipt(receipt)
    with store._connect() as connection:
        connection.execute("pragma foreign_keys = off")
        assert connection.execute("select count(*) from native_hook_review_scopes").fetchone()[0] == 1
        connection.execute("delete from native_hook_decision_receipts where decision_id = ?", (receipt["decision_id"],))
        assert connection.execute("select count(*) from native_hook_review_scopes").fetchone()[0] == 0


def test_worker_forwards_selected_ack_to_noncommand_queue(tmp_path, monkeypatch):
    from .native_review_approval_support import _worker
    from .test_native_review_policy_binding import _review

    case = _case()
    worker, _store = _worker(tmp_path, monkeypatch, case["edge"], publish_native_policy=False)
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda *_args, **_kwargs: case["snapshot"])
    try:
        response = _review(worker, tmp_path, payload=case["payload"])
        assert response["policy_action"] == "review", response
        assert "approval_request_id" in response
    finally:
        worker.close()


@pytest.mark.parametrize("changed_snapshot", [False, True])
def test_codex_live_noncommand_completion_uses_the_selected_ack(tmp_path, monkeypatch, changed_snapshot):
    from codex_plugin_scanner.guard.daemon.hook_native_review_approval import queue_native_pre_tool_review
    from codex_plugin_scanner.guard.live_process_identity import (
        CODEX_BROWSER_WAIT_PROCESS_KEY,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
        current_process_identity,
    )

    from .test_native_codex_live_continuation import _complete, _Worker
    from .test_native_codex_live_continuation import _resolve as resolve_live

    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    case = _case(harness="codex")
    edge, hook = case["edge"], copy.deepcopy(case["payload"])
    hook["hook_event_name"] = "PreToolUse"
    hook[CODEX_BROWSER_WAIT_PROCESS_KEY] = current_process_identity()
    hook[CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY] = 120
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    row = queue_native_pre_tool_review(
        store,
        harness="codex",
        payload=hook,
        native_result=edge["result"],
        verified_receipt=edge["receipt"],
        policy_snapshot=case["snapshot"],
        workspace=workspace,
        guard_home=store.guard_home,
        home_dir=tmp_path,
    )
    assert row is not None
    resolve_live(store, row)
    worker = _Worker(store, edge)
    if changed_snapshot:
        worker.snapshot["generation"] += 1
    result = _complete(store, workspace, edge, hook, row, worker=worker)
    assert result["completed"] is not changed_snapshot, result
    if not changed_snapshot:
        assert result["action"] == "allow"
        assert store.get_request_resume(row["request_id"])["status"] == "sent"
