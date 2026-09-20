"""Finite controls: real receipt validation/SQLite with synthetic native/HTTP calls."""

from __future__ import annotations

import copy
import hashlib
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace

from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes, validate_native_decision_receipt
from codex_plugin_scanner.guard.store_native_decision_receipts import (
    StoreNativeDecisionReceiptsMixin,
    ensure_native_command_receipt_binding_schema,
    native_decision_receipt_schema_statements,
)
from scripts import native_slo_workspace_request_observer as request_observer
from scripts.native_slo_mixed_request import request_attempt
from scripts.native_slo_workspace_decision import authority_projection
from scripts.native_slo_workspace_observer import public_binding


def snapshot():
    now = int(time.time() * 1000)
    return {
        "generation": 7,
        "policy_digest": "a" * 64,
        "runtime_identity": "b" * 64,
        "rule_digest": "c" * 64,
        "mode": "enforce",
        "issued_at_ms": now - 1000,
        "expires_at_ms": now + 60_000,
        "command_extensions": {
            "schema": "guard.native-command-control-binding.v1",
            "program_digest": "d" * 64,
            "catalog_digest": "e" * 64,
            "trust_digest": "f" * 64,
            "revision": 4,
            "managed_revision": 2,
            "effective_digest": "1" * 64,
            "health": "healthy",
            "layers": [],
        },
    }


def receipt(authority, index=0, action="block"):
    command = authority["command_extensions"]
    value = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "0" * 64,
        "request_id": f"controlled-request-{index}",
        "request_digest": "2" * 64,
        "harness": "claude-code",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": authority["generation"],
        "policy_digest": authority["policy_digest"],
        "rule_digest": authority["rule_digest"],
        "runtime_identity": authority["runtime_identity"],
        "decision": "deny" if action == "block" else "allow",
        "model_output_action": "not_applicable",
        "policy_action": action,
        "observed_policy_action": action,
        "reason_code": "policy_default",
        "workspace_bound": True,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": 1000,
        "command_extensions": {
            "schema": "guard.native-command-receipt-binding.v1",
            "program_digest": command["program_digest"],
            "catalog_digest": command["catalog_digest"],
            "trust_digest": command["trust_digest"],
            "control_revision": command["revision"],
            "managed_control_revision": command["managed_revision"],
            "control_effective_digest": command["effective_digest"],
            "observations_digest": "3" * 64,
            "observation_count": 0,
            "uncertainty_count": 0,
        },
    }
    value["decision_id"] = hashlib.sha256(canonical_receipt_bytes(value)).hexdigest()
    assert validate_native_decision_receipt(value) == value
    return value


def row(authority, index=0, *, offered=20.0, finished=22.0, action="block"):
    native = receipt(authority, index, action)
    wall = authority["issued_at_ms"] + 100
    return {
        "attempt": f"mixed-policy-{index}",
        "workspace_index": index % 2,
        "review_calls": 1,
        "review_returned": True,
        "request_returned": True,
        "capture_faults": 0,
        "offered_ms": offered,
        "review_entered_ms": offered + 0.5,
        "native_finished_ms": finished,
        "review_returned_ms": finished + 0.5,
        "delivered_ms": finished + 1.0,
        "commit_observed_ms": finished + 2.0,
        "review_entered_wall_ms": wall,
        "review_returned_wall_ms": wall + 1,
        "request_scope_matches": True,
        "request_binding_matches": True,
        "authority_readback_before": True,
        "authority_readback_after": True,
        "native_receipt_validated": True,
        "native_receipt": native,
        "delivered_decision": native["decision"],
        "witness_decision_id": native["decision_id"],
        "writer_admitted": True,
        "witness_committed": True,
        "witness_commit_binding_valid": True,
        "committed_row_count": 1,
        "committed_receipt_validated": True,
        "committed_receipt": copy.deepcopy(native),
    }


class ReceiptStore(StoreNativeDecisionReceiptsMixin):
    def __init__(self, path):
        self.path = path
        with self._connect() as connection:
            statements = native_decision_receipt_schema_statements(
                """
                create table if not exists schema_migrations (
                  version integer primary key,
                  applied_at text not null
                )
                """
            )
            for statement in statements:
                connection.execute(statement)
            ensure_native_command_receipt_binding_schema(connection, applied_at=datetime.now(timezone.utc).isoformat())

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()


def control(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    guard_home = root / ".hol-guard"
    guard_home.mkdir(mode=0o700)
    workspaces = (root / "primary", root / "secondary")
    for path in workspaces:
        path.mkdir(mode=0o700)
    state = SimpleNamespace(
        snapshot=snapshot(),
        calls=[],
        http_calls=[],
        native_error=None,
        http_error=None,
        before_return=None,
        action="block",
        edge=None,
        response={
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
            "policy_action": "block",
            "decision": "deny",
        },
    )
    store = ReceiptStore(root / "receipts.sqlite3")

    def review(*args, **kwargs):
        state.calls.append((args, kwargs))
        if state.native_error is not None:
            raise state.native_error
        attempt = request_attempt(kwargs["payload"])
        index = int(attempt.rsplit("-", 1)[1]) if attempt is not None and attempt.startswith("mixed-policy-") else 31
        state.edge = {"receipt": receipt(state.snapshot, index, state.action)}
        if state.before_return is not None:
            state.before_return()
        return state.edge

    worker = SimpleNamespace(_review_raw_hook_native=review)
    writer = SimpleNamespace(submit_native_decision_receipt=store.record_native_decision_receipt)
    daemon = SimpleNamespace(_server=SimpleNamespace(hook_worker=worker, runtime_hook_evidence_writer=writer))
    session = SimpleNamespace(root=root, guard_home=guard_home, store=store, daemon=daemon)
    state.session, state.worker, state.writer, state.original = session, worker, writer, review
    state.workspaces = workspaces
    state.request_kwargs = None

    def request(daemon_arg, **kwargs):
        state.http_calls.append((daemon_arg, kwargs))
        if state.http_error is not None:
            raise state.http_error
        state.request_kwargs = {
            "payload": kwargs["request_payload"],
            "harness": kwargs["harness"],
            "event": "PreToolUse",
            "guard_home": kwargs["guard_home"],
            "home_dir": root,
            "cwd": kwargs["workspace"],
            "source_ref_external_allowed": False,
            "observe_mode": False,
            "deadline": time.monotonic() + 1,
            "policy_snapshot": {
                **public_binding(state.snapshot),
                "mode": "enforce",
                "command_extensions_bound": True,
            },
        }
        edge = worker._review_raw_hook_native(**state.request_kwargs)
        state.last_http_edge = edge
        writer.submit_native_decision_receipt(edge["receipt"])
        return state.response

    from scripts import native_slo_session

    monkeypatch.setattr(native_slo_session, "_request", request)
    monkeypatch.setattr(
        request_observer,
        "_authenticated_readback",
        lambda _store: (
            {**public_binding(state.snapshot), "mode": "enforce", "command_extensions_bound": True},
            copy.deepcopy(state.snapshot),
        ),
    )
    assert authority_projection(state.snapshot)["command_controls"]["control_revision"] == 4
    return state


def finish(state, witness, observer, accepted, *, expected=None, indexes=(0,)):
    observer.close()
    witness.reconcile(verify_all=True)
    return observer.join(
        accepted=accepted,
        snapshot=state.snapshot if expected is None else expected,
        action="block",
        declared_indexes=indexes,
    )
