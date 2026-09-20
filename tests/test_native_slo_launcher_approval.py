"""Exact, bounded fixture resolution of real local approval records."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.daemon.hook_native_review_approval import queue_native_pre_tool_review
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_launcher_approval import LauncherApprovalControl, resolve_launcher_review

from .native_review_approval_support import _bound_review_evidence
from .native_slo_approval_support import _assert_recorded_policy_binding


def _session(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    routes = {"native_resident": 0}
    metrics = SimpleNamespace(snapshot=lambda: {"routes": dict(routes)})
    daemon = SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=metrics)))
    return SimpleNamespace(store=store, workspace=workspace, daemon=daemon), routes


def _payload(command="curl https://example.invalid/synthetic-token"):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}


def _queue(session, *, harness="claude-code", payload=None, workspace=None):
    harness = "claude-code" if harness == "claude" else harness
    payload = payload or _payload()
    workspace = workspace or session.workspace
    native_result, receipt = _bound_review_evidence(
        harness=harness,
        payload=payload,
        workspace=workspace,
        native_result={"minimum_action": "review", "reason": "Synthetic launcher qualification"},
    )
    row = queue_native_pre_tool_review(
        session.store,
        harness=harness,
        payload=payload,
        native_result=native_result,
        native_receipt=receipt,
        workspace=workspace,
        guard_home=session.store.guard_home,
        verified_receipt=receipt,
    )
    assert row is not None
    _assert_recorded_policy_binding(row, receipt)
    return row["request_id"]


def _result(control, operation_id):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        result = control.result(operation_id)
        if result["state"] != "waiting":
            return result
        time.sleep(0.01)
    pytest.fail("fixture controller did not terminate")


@pytest.mark.parametrize("harness", ["claude", "claude-code", "codex"])
@pytest.mark.parametrize("resolution", ["allow", "block"])
def test_real_pending_resolution_is_exact_and_privacy_safe(tmp_path, harness, resolution):
    session, routes = _session(tmp_path)
    control = LauncherApprovalControl(session)
    try:
        begun = control.begin(harness, _payload(), resolution=resolution, timeout_seconds=2)
        routes["native_resident"] += 1
        request_id = _queue(session, harness=harness)
        result = _result(control, begun["operation_id"])
        assert result["state"] == "resolved"
        assert result["request_id"] == request_id
        assert result["resolution"] == resolution
        assert result["scope"] == "artifact"
        assert result["authority"] == "ordinary_local_review"
        assert result["routes"] == {"native_resident": 1}
        assert result["binding_present"] is True
        assert result["input_digest"] == begun["input_digest"]
        assert session.store.get_approval_request(request_id)["resolution_action"] == resolution
        serialized = json.dumps(assert_privacy_safe(result))
        assert "example.invalid" not in serialized
        assert "synthetic-token" not in serialized
        assert str(tmp_path) not in serialized
    finally:
        control.close()


def test_preexisting_deduplicated_request_is_never_selected(tmp_path):
    session, _ = _session(tmp_path)
    old = _queue(session)
    control = LauncherApprovalControl(session)
    try:
        begun = control.begin("claude", _payload(), timeout_seconds=0.15)
        assert _queue(session) == old
        result = _result(control, begun["operation_id"])
        assert result["state"] == "failed"
        assert result["failure"]["reason"] == "qualification_launcher_approval_deadline", result
        assert session.store.get_approval_request(old)["status"] == "pending"
    finally:
        control.close()


@pytest.mark.parametrize("field,value", [("workspace", "~/another-workspace"), ("workspace_hash", "f" * 64)])
def test_canonical_codex_workspace_label_and_hash_cannot_retarget_approval(tmp_path, monkeypatch, field, value):
    session, _ = _session(tmp_path)
    control = LauncherApprovalControl(session)
    release = threading.Event()
    original = control._new_pending

    def delayed(operation):
        assert release.wait(2)
        return original(operation)

    monkeypatch.setattr(control, "_new_pending", delayed)
    try:
        begun = control.begin("codex", _payload(), timeout_seconds=2)
        request_id = _queue(session, harness="codex")
        row = session.store.get_approval_request(request_id)
        assert row["workspace"] == str(session.workspace)
        assert row["action_envelope_json"]["workspace"] == "~/workspace"
        envelope = {**row["action_envelope_json"], field: value}
        with session.store._connect() as connection:
            connection.execute(
                "update approval_requests set action_envelope_json=? where request_id=?",
                (json.dumps(envelope), request_id),
            )
        release.set()
        result = _result(control, begun["operation_id"])
        assert result["state"] == "failed"
        assert result["failure"]["reason"] == "qualification_launcher_approval_identity_changed"
        assert session.store.get_approval_request(request_id)["status"] == "pending"
    finally:
        release.set()
        control.close()


def test_other_harness_tool_command_and_workspace_are_not_resolved(tmp_path):
    session, _ = _session(tmp_path)
    control = LauncherApprovalControl(session)
    try:
        begun = control.begin("claude", _payload(), timeout_seconds=2)
        others = [
            _queue(session, harness="codex"),
            _queue(session, payload=_payload("curl https://different.invalid")),
            _queue(session, payload={**_payload(), "tool_name": "Shell"}),
            _queue(session, workspace=tmp_path / "another-workspace"),
        ]
        exact = _queue(session)
        result = _result(control, begun["operation_id"])
        assert result["state"] == "resolved", result
        assert result["request_id"] == exact
        assert all(session.store.get_approval_request(request_id)["status"] == "pending" for request_id in others)
    finally:
        control.close()


def test_ambiguous_new_rows_fail_without_resolving_either(tmp_path, monkeypatch):
    session, _ = _session(tmp_path)
    control = LauncherApprovalControl(session)
    release = threading.Event()
    original = control._new_pending

    def delayed(operation):
        assert release.wait(2)
        return original(operation)

    monkeypatch.setattr(control, "_new_pending", delayed)
    try:
        begun = control.begin("claude", _payload(), timeout_seconds=2)
        ids = []
        for _ in range(2):
            request_id = uuid.uuid4().hex
            request = GuardApprovalRequest(
                request_id=request_id,
                harness="claude-code",
                artifact_id="claude-code:native-pretool:Bash",
                artifact_name="Bash",
                artifact_hash=request_id,
                policy_action="review",
                recommended_scope="artifact",
                changed_fields=("native_pre_tool",),
                source_scope="project",
                config_path=str(session.workspace),
                review_command="synthetic",
                approval_url="http://localhost",
                workspace=str(session.workspace),
                artifact_type="tool_call",
                launch_target=_payload()["tool_input"]["command"],
                action_identity=request_id,
            )
            ids.append(session.store.add_approval_request(request, "2026-09-17T00:00:00Z"))
        assert len(set(ids)) == 2
        release.set()
        result = _result(control, begun["operation_id"])
        assert result["state"] == "failed"
        assert result["failure"]["reason"] == "qualification_launcher_approval_ambiguous"
        assert all(session.store.get_approval_request(request_id)["status"] == "pending" for request_id in ids)
    finally:
        release.set()
        control.close()


def test_enabled_approval_gate_is_honored_by_production_service(tmp_path):
    session, _ = _session(tmp_path)
    password = "synthetic-fixture-password"
    update_settings(session.store.guard_home, {"enabled": True, "new_password": password, "confirm_password": password})
    request_id = _queue(session)
    with pytest.raises(PermissionError):
        resolve_launcher_review(session.store, request_id, "allow")
    assert session.store.get_approval_request(request_id)["status"] == "pending"
    result = resolve_launcher_review(
        session.store, request_id, "allow", approval_gate_input=ApprovalGateInput(password=password)
    )
    assert result["approval_durable"] is True
    assert password not in json.dumps(result)


def test_close_cancels_wait_without_resolving_later_request(tmp_path):
    session, _ = _session(tmp_path)
    control = LauncherApprovalControl(session)
    begun = control.begin("claude", _payload(), timeout_seconds=2)
    with pytest.raises(RuntimeError, match="already_active"):
        control.begin("codex", _payload())
    control.close()
    request_id = _queue(session)
    assert control.result(begun["operation_id"])["state"] == "failed"
    assert session.store.get_approval_request(request_id)["status"] == "pending"
    with pytest.raises(RuntimeError, match="capacity"):
        control.begin("claude", _payload())
    with pytest.raises(ValueError, match="unknown_operation"):
        control.result(uuid.uuid4().hex)


def test_late_service_completion_reports_failure_and_actual_durable_outcome(tmp_path, monkeypatch):
    session, _ = _session(tmp_path)
    control = LauncherApprovalControl(session)
    entered, release = threading.Event(), threading.Event()

    def delayed(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        return resolve_launcher_review(*args, **kwargs)

    monkeypatch.setattr("scripts.native_slo_launcher_approval.resolve_launcher_review", delayed)
    try:
        begun = control.begin("claude", _payload(), timeout_seconds=0.2)
        request_id = _queue(session)
        assert entered.wait(1)
        time.sleep(0.25)
        release.set()
        result = _result(control, begun["operation_id"])
        assert result["state"] == "failed"
        assert result["failure"]["reason"] == "qualification_launcher_approval_resolution_late"
        assert result["approval_durable"] is True
        assert result["request_id"] == request_id
        assert session.store.get_approval_request(request_id)["status"] == "resolved"
    finally:
        release.set()
        control.close()


@pytest.mark.parametrize("timeout", [0, -1, 8.01, float("nan"), float("inf"), True])
def test_deadline_is_explicitly_bounded(tmp_path, timeout):
    session, _ = _session(tmp_path)
    control = LauncherApprovalControl(session)
    with pytest.raises(ValueError, match="invalid_deadline"):
        control.begin("claude", _payload(), timeout_seconds=timeout)
    control.close()


def test_input_and_operation_count_are_bounded(tmp_path, monkeypatch):
    session, _ = _session(tmp_path)
    control = LauncherApprovalControl(session)
    for harness, payload in (("cursor", _payload()), ("claude", _payload("x" * 2049))):
        with pytest.raises(ValueError):
            control.begin(harness, payload)
    monkeypatch.setattr("scripts.native_slo_launcher_approval._MAX_OPERATIONS", 1)
    begun = control.begin("claude", _payload(), timeout_seconds=0.01)
    assert _result(control, begun["operation_id"])["state"] == "failed"
    with pytest.raises(RuntimeError, match="capacity"):
        control.begin("claude", _payload())
    control.close()


@pytest.mark.parametrize("outcome", ["resolve", "deadline", "cancel", "deduplicated"])
def test_real_pending_read_contention_keeps_original_deadline_and_cancellation(tmp_path, monkeypatch, outcome):
    session, _ = _session(tmp_path)
    old = _queue(session) if outcome == "deduplicated" else None
    control = LauncherApprovalControl(session)
    entered, release, contended = threading.Event(), threading.Event(), threading.Event()
    failures = []
    original = control._new_pending

    def pending(operation):
        entered.set()
        assert release.wait(2)
        try:
            return original(operation)
        except sqlite3.OperationalError as error:
            failures.append(getattr(error, "sqlite_errorcode", None))
            contended.set()
            raise

    monkeypatch.setattr(control, "_new_pending", pending)
    connection = None
    try:
        timeout = 0.15 if outcome in {"deadline", "deduplicated"} else 2
        begun = control.begin("claude", _payload(), timeout_seconds=timeout)
        assert entered.wait(1)
        request_id = _queue(session)
        if old is not None:
            assert request_id == old
        connection = sqlite3.connect(session.store.path, isolation_level=None, timeout=0.2)
        assert connection.execute("pragma locking_mode=exclusive").fetchone()[0] == "exclusive"
        connection.execute("begin exclusive")
        connection.execute("select count(*) from approval_requests").fetchone()
        release.set()
        assert contended.wait(1)
        if outcome == "cancel":
            control.close()
        result = _result(control, begun["operation_id"]) if outcome == "deadline" else None
        connection.execute("rollback")
        connection.close()
        connection = None
        if result is None:
            result = _result(control, begun["operation_id"])
        if not hasattr(sqlite3, "SQLITE_BUSY"):
            # Python 3.10 has no engine result code: an unclassified error
            # remains terminal rather than falling back to message matching.
            assert failures == [None]
            assert result["state"] == "failed", result
            assert result["failure"]["reason"] == "unclassified_failure"
            assert "read_contention" not in result
            assert session.store.get_approval_request(request_id)["status"] == "pending"
            return
        if outcome == "resolve":
            assert result["state"] == "resolved", result
            assert result["request_id"] == request_id
            assert session.store.get_approval_request(request_id)["status"] == "resolved"
        else:
            assert result["state"] == "failed", result
            reason = "cancelled" if outcome == "cancel" else "deadline"
            assert result["failure"]["reason"] == f"qualification_launcher_approval_{reason}", result
            assert session.store.get_approval_request(request_id)["status"] == "pending"
        assert failures and all(code & 0xFF in {5, 6} for code in failures)
        assert result["read_contention"]["count"] == len(failures)
        assert result["read_contention"]["sqlite_errorcode"] == failures[-1]
        assert result["read_contention"]["last_failure"]["category"] == "OperationalError"
        assert result["read_contention"]["last_failure"]["reason"] == "unclassified_failure"
        assert_privacy_safe(result)
    finally:
        release.set()
        if connection is not None:
            connection.close()
        control.close()


@pytest.mark.parametrize("code", [None, 8, 11], ids=["missing", "SQLITE_READONLY", "SQLITE_CORRUPT"])
def test_unknown_or_noncontention_pending_read_failure_is_never_retried(tmp_path, monkeypatch, code):
    session, _ = _session(tmp_path)
    control = LauncherApprovalControl(session)
    calls = []
    original = session.store._connect_once

    @contextmanager
    def connection():
        if threading.current_thread().name == "launcher-approval-control":
            calls.append(True)
            error = sqlite3.OperationalError("database is locked")
            if code is not None:
                error.sqlite_errorcode = code
            raise error
        with original() as current:
            yield current

    monkeypatch.setattr(session.store, "_connect_once", connection)
    try:
        begun = control.begin("claude", _payload(), timeout_seconds=2)
        result = _result(control, begun["operation_id"])
        assert calls == [True]
        assert result["state"] == "failed"
        assert result["failure"]["reason"] == "unclassified_failure"
        assert "read_contention" not in result
    finally:
        control.close()


def test_resolution_contention_is_never_retried(tmp_path, monkeypatch):
    session, _ = _session(tmp_path)
    control = LauncherApprovalControl(session)
    calls = []

    def resolve(*_args, **_kwargs):
        calls.append(True)
        error = sqlite3.OperationalError("database is locked")
        error.sqlite_errorcode = 5  # SQLITE_BUSY
        raise error

    monkeypatch.setattr("scripts.native_slo_launcher_approval.resolve_launcher_review", resolve)
    try:
        begun = control.begin("claude", _payload(), timeout_seconds=2)
        request_id = _queue(session)
        result = _result(control, begun["operation_id"])
        assert calls == [True]
        assert result["state"] == "failed"
        assert result["request_id"] == request_id
        assert result["approval_durable"] is False
        assert result["failure"]["reason"] == "unclassified_failure"
        assert "read_contention" not in result
        assert session.store.get_approval_request(request_id)["status"] == "pending"
    finally:
        control.close()


def test_contention_after_pending_select_does_not_retry_context_exit(tmp_path, monkeypatch):
    session, _ = _session(tmp_path)
    control = LauncherApprovalControl(session)
    exits = []
    original = session.store._connect_once

    @contextmanager
    def connection():
        with original() as current:
            yield current
            if threading.current_thread().name == "launcher-approval-control":
                exits.append(True)
                error = sqlite3.OperationalError("database is locked")
                error.sqlite_errorcode = 5  # SQLITE_BUSY
                raise error

    monkeypatch.setattr(session.store, "_connect_once", connection)
    try:
        begun = control.begin("claude", _payload(), timeout_seconds=2)
        result = _result(control, begun["operation_id"])
        assert exits == [True]
        assert result["state"] == "failed"
        assert result["failure"]["reason"] == "unclassified_failure"
        assert "read_contention" not in result
    finally:
        control.close()


def test_pending_probe_never_enters_store_recovery(tmp_path, monkeypatch):
    session, _ = _session(tmp_path)
    control = LauncherApprovalControl(session)
    calls, recoveries = [], []
    original = session.store._connect_once

    @contextmanager
    def connection():
        if threading.current_thread().name == "launcher-approval-control":
            calls.append(True)
            raise sqlite3.DatabaseError("database disk image is malformed")
        with original() as current:
            yield current

    def recover(*_args, **_kwargs):
        recoveries.append(True)
        return False

    monkeypatch.setattr(session.store, "_connect_once", connection)
    monkeypatch.setattr(session.store, "_recover_fatal_sqlite_store", recover)
    try:
        begun = control.begin("claude", _payload(), timeout_seconds=2)
        result = _result(control, begun["operation_id"])
        assert calls == [True]
        assert recoveries == []
        assert result["state"] == "failed"
        assert result["failure"]["category"] == "DatabaseError"
        assert result["failure"]["reason"] == "unclassified_failure"
        assert "read_contention" not in result
    finally:
        control.close()
