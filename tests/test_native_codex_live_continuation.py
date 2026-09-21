"""Native review uses real queued continuation and atomic exact local authority."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateError, ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.codex_live_decision import resolve_codex_live_allow_authority
from codex_plugin_scanner.guard.daemon import codex_native_live_decision as completion
from codex_plugin_scanner.guard.daemon.hook_native_review_approval import (
    pause_native_pre_tool_for_approval,
    queue_native_pre_tool_review,
)
from codex_plugin_scanner.guard.live_process_identity import (
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
    current_process_identity,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    NativeCommandControlMutationRequiredError,
    hold_command_control_authority_lock,
)
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from codex_plugin_scanner.guard.runtime.actions import (
    GuardActionEnvelope,
    normalize_harness_payload,
    stable_action_hash,
)
from codex_plugin_scanner.guard.store import GuardStore

from .test_native_review_policy_binding import _bind_receipt, _bound_edge


@pytest.fixture(autouse=True)
def _native_mode(monkeypatch):
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _fixture(tmp_path, *, proof=True, payload=None):
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    edge = _bound_edge()
    edge["harness"] = edge["receipt"]["harness"] = "codex"
    _bind_receipt(edge)
    hook = (
        payload
        if payload is not None
        else {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ollama push test"},
        }
    )
    if proof:
        hook[CODEX_BROWSER_WAIT_PROCESS_KEY] = current_process_identity()
        hook[CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY] = 120
    row = queue_native_pre_tool_review(
        store,
        harness="codex",
        payload=hook,
        native_result=edge["result"],
        workspace=workspace,
        guard_home=store.guard_home,
        home_dir=tmp_path,
        verified_receipt=edge["receipt"],
    )
    assert row is not None
    return store, workspace, edge, hook, row


def _resolve(store, row, *, action="allow", gate=None):
    return apply_approval_resolution(
        store=store,
        request_id=row["request_id"],
        action=action,
        scope="artifact",
        workspace=None,
        reason="Explicit synthetic fixture decision",
        persist_policy=False,
        resolve_scope_matches=False,
        approval_gate_input=gate,
    )


class _Worker:
    def __init__(self, store, edge):
        self.store, self.edge = store, edge
        self.config_reader = None
        self.routes = []
        self.metrics = SimpleNamespace(record_route=self.routes.append)
        self.recorded = []
        self.calls = 0
        self.snapshot = {
            "mode": "enforce",
            "policy_digest": edge["receipt"]["policy_digest"],
            "command_extensions_bound": True,
            "generation": edge["receipt"]["policy_generation"],
            "runtime_identity": edge["receipt"]["runtime_identity"],
        }

    def prepare_workspace_policy(self, workspace, *, deadline):
        # Publication must precede SH acquisition.
        with hold_command_control_authority_lock(self.store.guard_home, shared=False, timeout_seconds=0):
            return self.snapshot

    def _review_raw_hook_native(self, **kwargs):
        self.calls += 1
        assert kwargs["observe_mode"] is False
        with (
            pytest.raises(NativeCommandControlMutationRequiredError),
            hold_command_control_authority_lock(self.store.guard_home, shared=False, timeout_seconds=0),
        ):
            pass
        return self.edge

    def _record_native_decision_receipt(self, receipt):
        self.recorded.append(receipt)
        return None  # No asynchronous logging acceptance is needed for authority.


def _complete(store, workspace, edge, hook, row, *, worker=None):
    return completion.complete_native_codex_live_decision(
        store,
        worker=worker or _Worker(store, edge),
        request_id=row["request_id"],
        payload={"hook_input": json.dumps(hook)},
        deadline=time.monotonic() + 3,
    )


def test_real_native_queue_records_proven_wait_and_canonical_action(tmp_path):
    store, workspace, edge, hook, row = _fixture(tmp_path)
    snapshot = row["continuation_snapshot"]
    assert snapshot["capability"] == "suspended-response" and snapshot["hookAttached"] is True
    operation = store.get_guard_operation_for_approval_request(row["request_id"])
    assert operation["status"] == "waiting_on_approval"
    assert operation["metadata"]["codex_browser_wait_process"] == hook[CODEX_BROWSER_WAIT_PROCESS_KEY]
    assert store.get_request_resume(row["request_id"]) is not None
    expected = normalize_harness_payload("codex", "PreToolUse", hook, workspace=workspace, home_dir=tmp_path)
    assert stable_action_hash(GuardActionEnvelope.from_dict(row["action_envelope_json"])) == stable_action_hash(
        expected
    )
    assert (
        row["action_envelope_json"]["native_review_policy_binding"]["policy_digest"] == edge["receipt"]["policy_digest"]
    )


@pytest.mark.parametrize(
    "proof", [None, {}, {"pid": True, "startToken": "invalid"}, {"pid": 999999999, "startToken": "stale"}]
)
def test_missing_or_dead_bridge_proof_never_invents_waiter(tmp_path, proof):
    hook = {
        "hook_event_name": "PreToolUse",
        CODEX_BROWSER_WAIT_PROCESS_KEY: proof,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 120,
    }
    store, _, _, _, row = _fixture(tmp_path, proof=False, payload=hook)
    assert row["continuation_snapshot"]["capability"] == "retry-only"
    assert store.get_guard_operation_for_approval_request(row["request_id"]) is None
    _resolve(store, row)
    assert (
        resolve_codex_live_allow_authority(
            store, request=store.get_approval_request(row["request_id"]), request_id=row["request_id"], now=_now()
        )
        is None
    )


@pytest.mark.parametrize("timeout", [None, False, 0, -1, 999999999, "120"])
def test_unbounded_bridge_wait_never_creates_continuation(tmp_path, timeout):
    hook = {
        "hook_event_name": "PreToolUse",
        CODEX_BROWSER_WAIT_PROCESS_KEY: current_process_identity(),
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: timeout,
    }
    store, _, _, _, row = _fixture(tmp_path, proof=False, payload=hook)
    assert row["continuation_snapshot"]["capability"] == "retry-only"
    assert store.get_guard_operation_for_approval_request(row["request_id"]) is None


def test_live_waiters_never_deduplicate_or_reuse_resolved_browser_rows(tmp_path):
    store, workspace, edge, hook, first = _fixture(tmp_path)
    _resolve(store, first)
    second = pause_native_pre_tool_for_approval(
        store,
        harness="codex",
        payload=hook,
        native_result=edge["result"],
        workspace=workspace,
        guard_home=store.guard_home,
        home_dir=tmp_path,
        verified_receipt=edge["receipt"],
    )
    assert second["approval_request_id"] != first["request_id"]
    assert "approval_reuse_status" not in second
    assert store.get_guard_operation_for_approval_request(second["approval_request_id"]) is not None


def test_explicit_no_saved_policy_still_requires_password_then_grants_exact_once(tmp_path):
    store, workspace, edge, hook, row = _fixture(tmp_path)
    password = "Synthetic native continuation fixture password 527!"
    update_settings(
        store.guard_home,
        {"enabled": True, "new_password": password, "confirm_password": password, "cooldown_seconds": 0},
    )
    with pytest.raises(ApprovalGateError):
        _resolve(store, row)
    assert store.get_approval_request(row["request_id"])["status"] == "pending"
    _resolve(store, row, gate=ApprovalGateInput(password=password))
    request = store.get_approval_request(row["request_id"])
    authority = resolve_codex_live_allow_authority(store, request=request, request_id=row["request_id"], now=_now())
    assert authority["source"] == "approval-gate-once"
    assert isinstance(authority["workspace"], str) and authority["workspace"].startswith("workspace:")
    assert (
        resolve_codex_live_allow_authority(
            store, request={**request, "workspace": str(tmp_path / "other")}, request_id=row["request_id"], now=_now()
        )
        is None
    )
    assert authority["artifact_hash"] == row["artifact_hash"]
    with store._connect() as connection:
        assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
    assert _complete(store, workspace, edge, hook, row)["completed"] is True


def test_fresh_native_review_and_real_once_consume_share_one_fence(tmp_path, monkeypatch):
    store, workspace, edge, hook, row = _fixture(tmp_path)
    _resolve(store, row)
    real = store.finalize_continuation_attempt
    calls = []

    def finalize(**kwargs):
        with (
            pytest.raises(NativeCommandControlMutationRequiredError),
            hold_command_control_authority_lock(store.guard_home, shared=False, timeout_seconds=0),
        ):
            pass
        calls.append("consumed")
        return real(**kwargs)

    monkeypatch.setattr(store, "finalize_continuation_attempt", finalize)
    worker = _Worker(store, edge)
    result = _complete(store, workspace, edge, hook, row, worker=worker)
    assert result["completed"] is True and result["action"] == "allow", result
    assert calls == ["consumed"] and worker.routes == ["native_resident"]
    assert store.get_request_resume(row["request_id"])["status"] == "sent"
    assert (
        resolve_codex_live_allow_authority(
            store, request=store.get_approval_request(row["request_id"]), request_id=row["request_id"], now=_now()
        )
        is None
    )
    assert _complete(store, workspace, edge, hook, row)["replayed"] is True


@pytest.mark.parametrize(
    "mutation",
    [
        "command",
        "policy",
        "controls",
        "permission_block",
        "missing_receipt",
        "missing_binding",
        "no_snapshot",
        "observe",
        "empty_response",
        "deadline",
        "missing_authority",
        "dead_waiter",
    ],
)
def test_fresh_completion_never_lifts_changed_or_unavailable_authority(tmp_path, mutation):
    store, workspace, edge, hook, row = _fixture(tmp_path)
    if mutation == "missing_authority":
        store.resolve_one_request_only(
            row["request_id"],
            resolution_action="allow",
            resolution_scope="artifact",
            reason="no authority fixture",
            resolved_at=_now(),
        )
    else:
        _resolve(store, row)
    worker = _Worker(store, edge)
    if mutation == "command":
        hook["tool_input"] = {"command": "ollama rm other"}
        edge["receipt"]["request_digest"] = "e" * 64
        _bind_receipt(edge)
    elif mutation == "policy":
        edge["receipt"]["policy_digest"] = worker.snapshot["policy_digest"] = "e" * 64
        _bind_receipt(edge)
    elif mutation == "controls":
        edge["result"]["command_extensions"]["binding"]["control_revision"] += 1
        _bind_receipt(edge)
    elif mutation == "permission_block":
        edge["result"]["minimum_action"] = edge["result"]["policy_action"] = edge["receipt"]["policy_action"] = "block"
        _bind_receipt(edge)
    elif mutation == "missing_receipt":
        edge.pop("receipt")
    elif mutation == "missing_binding":
        edge["result"].pop("command_extensions")
        edge["receipt"].pop("command_extensions")
        edge["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(edge["receipt"])).hexdigest()
    elif mutation == "no_snapshot":
        worker.snapshot = None
    elif mutation == "observe":
        worker.snapshot["mode"] = "observe"
    elif mutation == "empty_response":
        worker.edge = {}
    elif mutation == "deadline":

        def slow(**kwargs):
            time.sleep(0.02)
            return edge

        worker._review_raw_hook_native = slow
        result = completion.complete_native_codex_live_decision(
            store,
            worker=worker,
            request_id=row["request_id"],
            payload={"hook_input": json.dumps(hook)},
            deadline=time.monotonic() + 0.01,
        )
        assert result["completed"] is False
        return
    elif mutation == "dead_waiter":
        operation = store.get_guard_operation_for_approval_request(row["request_id"])
        metadata = operation["metadata"]
        metadata["codex_browser_wait_process"] = {"pid": 999999999, "startToken": "dead"}
        store.upsert_guard_operation(
            operation_id=operation["operation_id"],
            session_id=operation["session_id"],
            harness="codex",
            operation_type="tool_call",
            status="waiting_on_approval",
            approval_request_ids=[row["request_id"]],
            resume_token=None,
            metadata=metadata,
            now=_now(),
        )
    result = _complete(store, workspace, edge, hook, row, worker=worker)
    assert result["completed"] is False
    assert store.get_request_resume(row["request_id"])["status"] not in {"resumed", "sent"}


def test_browser_block_records_real_terminal_without_allow_authority(tmp_path):
    store, workspace, edge, hook, row = _fixture(tmp_path)
    _resolve(store, row, action="block")
    worker = _Worker(store, edge)
    result = _complete(store, workspace, edge, hook, row, worker=worker)
    assert result["completed"] is True and result["action"] == "block"
    assert worker.calls == 0
    assert store.get_request_resume(row["request_id"])["status"] == "skipped"


def test_exact_live_endpoint_uses_native_completion_without_python_reviewer(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler

    store, _workspace, edge, hook, row = _fixture(tmp_path)
    _resolve(store, row)
    worker = _Worker(store, edge)
    handler = object.__new__(_GuardDaemonHandler)
    handler.server = SimpleNamespace(store=store, hook_worker=worker, home_dir=tmp_path)
    observed = []
    handler._write_json = lambda result, *, status: observed.append((result, status))

    def forbidden(*args, **kwargs):
        pytest.fail("native browser continuation must not call a Python semantic reviewer")

    handler._revalidate_codex_live_allow = forbidden
    handler._handle_codex_live_decision(row["request_id"], {"hook_input": json.dumps(hook)})
    assert observed[0][1] == 200 and observed[0][0]["completed"] is True
    assert worker.routes == ["native_resident"]


def test_signing_failure_never_creates_continuation_authority(tmp_path, monkeypatch):
    store, workspace, edge, hook, row = _fixture(tmp_path)
    monkeypatch.setattr(store, "record_local_once_approval", lambda **kwargs: None)
    _resolve(store, row)
    result = _complete(store, workspace, edge, hook, row)
    assert result == {"completed": False, "error": "exact_approval_authority_missing"}


@pytest.mark.parametrize(
    "mutation", ["missing_process", "different_process", "expired", "cancelled", "changed_binding"]
)
def test_replay_requires_original_live_hook_and_current_native_policy(tmp_path, mutation):
    store, workspace, edge, hook, row = _fixture(tmp_path)
    _resolve(store, row)
    assert _complete(store, workspace, edge, hook, row)["completed"] is True
    if mutation == "missing_process":
        hook.pop(CODEX_BROWSER_WAIT_PROCESS_KEY)
    elif mutation == "different_process":
        hook[CODEX_BROWSER_WAIT_PROCESS_KEY] = {"pid": 999999999, "startToken": "different"}
    elif mutation == "changed_binding":
        edge["result"]["command_extensions"]["binding"]["control_revision"] += 1
        _bind_receipt(edge)
    else:
        operation = store.get_guard_operation_for_approval_request(row["request_id"])
        metadata = operation["metadata"]
        if mutation == "expired":
            metadata["codex_browser_wait_deadline_at"] = "2000-01-01T00:00:00+00:00"
        store.upsert_guard_operation(
            operation_id=operation["operation_id"],
            session_id=operation["session_id"],
            harness="codex",
            operation_type="tool_call",
            status="cancelled" if mutation == "cancelled" else "resumed",
            approval_request_ids=[row["request_id"]],
            resume_token=None,
            metadata=metadata,
            now=_now(),
        )
    assert _complete(store, workspace, edge, hook, row)["completed"] is False


def test_pending_live_hooks_keep_distinct_frozen_targets(tmp_path):
    store, workspace, edge, hook, first = _fixture(tmp_path)
    second = queue_native_pre_tool_review(
        store,
        harness="codex",
        payload=hook,
        native_result=edge["result"],
        workspace=workspace,
        guard_home=store.guard_home,
        home_dir=tmp_path,
        verified_receipt=edge["receipt"],
    )
    assert second["request_id"] != first["request_id"]
    assert store.get_approval_request(first["request_id"])["continuation_snapshot"] == first["continuation_snapshot"]
    assert len(store.list_approval_requests(status="pending")) == 2


def test_other_process_cannot_take_mutation_lock_during_atomic_consume(tmp_path, monkeypatch):
    import subprocess
    import sys

    from codex_plugin_scanner.guard.native_command_control_authority import AUTHORITY_LOCK_NAME

    store, workspace, edge, hook, row = _fixture(tmp_path)
    _resolve(store, row)
    code = """import os, sys
f=open(sys.argv[1], 'r+b', buffering=0)
try:
 if os.name == 'nt':
  import msvcrt
  msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
 else:
  import fcntl
  fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
 print('blocked')
else:
 print('acquired')
finally:
 f.close()
"""

    def probe():
        child = subprocess.run(
            [sys.executable, "-I", "-c", code, str(store.guard_home / AUTHORITY_LOCK_NAME)],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        return child.stdout.strip()

    real = store.finalize_continuation_attempt

    def finalize(**kwargs):
        assert probe() == "blocked"
        return real(**kwargs)

    monkeypatch.setattr(store, "finalize_continuation_attempt", finalize)
    assert _complete(store, workspace, edge, hook, row)["completed"] is True
    assert probe() == "acquired"
