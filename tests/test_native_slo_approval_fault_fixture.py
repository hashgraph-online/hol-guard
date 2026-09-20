"""Source-only synthetic edges verify private observation and control wiring."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import codex_native_live_decision, server
from scripts.native_slo_approval_fault_fixture import LauncherApprovalFaultFixture
from scripts.native_slo_launcher_approval import LauncherApprovalControl

from .test_native_codex_live_continuation import _fixture
from .test_native_review_policy_binding import _bound_edge
from .test_native_slo_launcher_approval import _payload, _queue, _result, _session


def _observed_session(tmp_path):
    session, _ = _session(tmp_path)
    session.root, session.guard_home = tmp_path, session.store.guard_home
    session.daemon._server.hook_process_runner = SimpleNamespace(stats=lambda: {"routes": {}})
    edge = _bound_edge()
    worker = session.daemon._server.hook_worker
    worker._review_raw_hook_native = lambda **_kwargs: edge
    worker.test_oracle = None
    return session, edge


def test_real_public_settings_api_accepts_two_second_wait_without_a_mocked_clamp(tmp_path):
    from codex_plugin_scanner.guard.config import load_guard_config, update_guard_settings

    session, _ = _session(tmp_path)
    updated = update_guard_settings(session.store.guard_home, {"approval_wait_timeout_seconds": 2})
    loaded = load_guard_config(session.store.guard_home)
    assert type(updated.approval_wait_timeout_seconds) is int
    assert updated.approval_wait_timeout_seconds == loaded.approval_wait_timeout_seconds == 2


def test_pending_callback_observes_exact_new_row_before_real_gated_resolution(tmp_path):
    session, _ = _session(tmp_path)
    observed = []

    def before_resolve(request_id):
        row = session.store.get_approval_request(request_id)
        observed.append((request_id, row["status"], row["launch_target"]))

    control = LauncherApprovalControl(session, before_resolve=before_resolve)
    try:
        begun = control.begin("claude-code", _payload(), timeout_seconds=2)
        request_id = _queue(session)
        result = _result(control, begun["operation_id"])
        assert result["state"] == "resolved"
        assert result["approval_durable"] is True
        assert observed == [(request_id, "pending", _payload()["tool_input"]["command"])]
    finally:
        control.close()


@pytest.mark.parametrize("change", ["failure", "retargeted"])
def test_failed_or_retargeted_control_cannot_resolve_the_original_row(tmp_path, change):
    session, _ = _session(tmp_path)

    def before_resolve(request_id):
        if change == "failure":
            raise RuntimeError("qualification_mutation_failed")
        with session.store._connect() as connection:
            connection.execute(
                "update approval_requests set launch_target = 'changed' where request_id = ?", (request_id,)
            )

    control = LauncherApprovalControl(session, before_resolve=before_resolve)
    try:
        begun = control.begin("claude-code", _payload(), timeout_seconds=2)
        request_id = _queue(session)
        result = _result(control, begun["operation_id"])
        assert result["state"] == "failed"
        assert result["request_id"] == request_id
        assert result["approval_durable"] is False
        assert session.store.get_approval_request(request_id)["status"] == "pending"
    finally:
        control.close()


def test_observers_delegate_native_and_completion_results_then_restore_all_patches(tmp_path, monkeypatch):
    session, edge = _observed_session(tmp_path)
    completed = {"completed": False, "error": "synthetic_completion_failure"}
    calls = []

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        return completed

    monkeypatch.setattr(codex_native_live_decision, "complete_native_codex_live_decision", original)
    native = session.daemon._server.hook_worker._review_raw_hook_native
    handler = server._GuardDaemonHandler._handle_codex_live_decision
    write = server._GuardDaemonHandler._write_json
    fixture = LauncherApprovalFaultFixture(session)
    fixture._request_id = "a" * 32
    try:
        fixture._install_observers()
        assert session.daemon._server.hook_worker._review_raw_hook_native() is edge
        kwargs = {"request_id": "a" * 32, "deadline": 123.5, "payload": {"hook_input": "synthetic"}}
        assert codex_native_live_decision.complete_native_codex_live_decision(session.store, **kwargs) is completed
        assert calls == [((session.store,), kwargs)]
        assert fixture._native[0]["receipt_valid"] is True
        assert fixture._receipts[0] == edge["receipt"]
        assert fixture._in_flight == 0
    finally:
        fixture.close()
    assert session.daemon._server.hook_worker._review_raw_hook_native is native
    assert codex_native_live_decision.complete_native_codex_live_decision is original
    assert server._GuardDaemonHandler._handle_codex_live_decision is handler
    assert server._GuardDaemonHandler._write_json is write


def test_expiry_delay_crosses_real_original_wait_without_replacing_passed_deadline(tmp_path, monkeypatch):
    session, _ = _observed_session(tmp_path)
    calls = []

    def original(_store, **kwargs):
        calls.append((kwargs, datetime.now(timezone.utc)))
        return {"completed": False, "error": "fresh_policy_revalidation_failed"}

    monkeypatch.setattr(codex_native_live_decision, "complete_native_codex_live_decision", original)
    fixture = LauncherApprovalFaultFixture(session)
    fixture._scenario, fixture._request_id = "approval_wait_expiry", "a" * 32
    try:
        fixture._install_observers()
        fixture._expiry = datetime.now(timezone.utc) + timedelta(seconds=0.025)
        deadline = time.monotonic() + 0.001
        codex_native_live_decision.complete_native_codex_live_decision(
            session.store,
            request_id="a" * 32,
            worker=session.daemon._server.hook_worker,
            payload={"hook_input": "synthetic"},
            deadline=deadline,
        )
        assert calls[0][0]["deadline"] == deadline
        assert calls[0][1] >= fixture._expiry
        assert time.monotonic() >= deadline
        assert fixture._fault == {"applied": True, "delay_entered": True, "original_wait_expired": True}
        assert fixture._in_flight == 0
    finally:
        fixture.close()


def test_existing_fixture_dispatch_lazily_owns_and_closes_fault_sibling(tmp_path, monkeypatch):
    from scripts import native_slo_approval_fault_fixture as fault_module
    from scripts.native_slo_launcher_review import LauncherReviewFixture

    session, _ = _observed_session(tmp_path)
    calls = []

    class Sibling:
        def __init__(self, owner):
            assert owner is session
            calls.append("constructed")

        def dispatch(self, operation, request):
            calls.append((operation, request))
            return {"state": "waiting"}

        def close(self):
            calls.append("closed")

    monkeypatch.setattr(fault_module, "LauncherApprovalFaultFixture", Sibling)
    fixture = LauncherReviewFixture(session)
    try:
        for operation in ("launcher_approval_fault_begin", "launcher_approval_fault_result"):
            assert fixture.dispatch(operation, {"scenario": "approval_wait_expiry"}) == {"state": "waiting"}
        assert calls.count("constructed") == 1
    finally:
        fixture.close()
    assert calls[-1] == "closed"


def test_fault_witness_capacity_never_silently_overwrites_an_earlier_attempt(tmp_path):
    session, _ = _observed_session(tmp_path)
    fixture = LauncherApprovalFaultFixture(session)
    try:
        for index in range(9):
            fixture._append(fixture._posts, {"index": index})
        assert fixture._posts == [{"index": index} for index in range(8)]
        assert fixture._overflow is True
    finally:
        fixture.close()


@pytest.mark.parametrize("remaining", [-1, 3])
def test_expiry_injection_is_bounded_and_cannot_repair_an_already_expired_wait(tmp_path, remaining):
    session, _ = _observed_session(tmp_path)
    fixture = LauncherApprovalFaultFixture(session)
    fixture._expiry = datetime.now(timezone.utc) + timedelta(seconds=remaining)
    try:
        with pytest.raises(RuntimeError, match="outside_bound"):
            fixture._hold_expiry()
        assert fixture._fault == {"applied": False}
    finally:
        fixture.close()


def test_ambiguous_fault_drops_only_first_actual_completed_response_for_exact_request(tmp_path, monkeypatch):
    session, _ = _observed_session(tmp_path)
    writes, closures, handled = [], [], []
    monkeypatch.setattr(
        server._GuardDaemonHandler,
        "_write_json",
        lambda handler, data, **kwargs: writes.append((handler.path, data, kwargs)),
    )
    monkeypatch.setattr(
        server._GuardDaemonHandler,
        "_handle_codex_live_decision",
        lambda handler, request_id, data: handled.append((request_id, data)),
    )
    fixture = LauncherApprovalFaultFixture(session)
    fixture._scenario, fixture._request_id = "ambiguous_completion_retry", "a" * 32
    connection = SimpleNamespace(shutdown=lambda kind: closures.append(kind), close=lambda: closures.append("closed"))
    handler = SimpleNamespace(path="/v1/requests/" + "a" * 32 + "/live-decision", connection=connection)
    try:
        fixture._install_observers()
        body = {"hook_input": json.dumps({"tool_name": "Bash", "tool_input": {"command": "synthetic"}})}
        for _ in range(2):
            server._GuardDaemonHandler._handle_codex_live_decision(handler, "a" * 32, body)
        assert handled == [("a" * 32, body)] * 2
        assert fixture._posts[0] == fixture._posts[1]
        failed = {"completed": False, "error": "fresh_policy_revalidation_failed"}
        server._GuardDaemonHandler._write_json(handler, failed, status=409)
        assert not closures and writes[-1][1] is failed
        completed = {"completed": True, "action": "allow", "replayed": False}
        server._GuardDaemonHandler._write_json(handler, completed, status=200)
        assert closures[-1] == "closed" and handler.close_connection is True
        assert len(writes) == 1
        replayed = {**completed, "replayed": True}
        server._GuardDaemonHandler._write_json(handler, replayed, status=200)
        assert writes[-1][1] is replayed and len(writes) == 2
        assert fixture._drops == 1
        assert [row["delivered"] for row in fixture._responses] == [True, False, True]
        handler.path = "/v1/requests/" + "b" * 32 + "/live-decision"
        server._GuardDaemonHandler._write_json(handler, completed, status=200)
        assert len(writes) == 3 and len(fixture._responses) == 3
    finally:
        fixture.close()


@pytest.mark.parametrize("scenario", ["resident_restart_pending", "stricter_policy_pending"])
def test_control_is_applied_while_real_live_operation_and_approval_are_pending(tmp_path, monkeypatch, scenario):
    from codex_plugin_scanner.guard import config
    from scripts.native_slo_mixed_server import MixedScenarioFixture

    store, workspace, edge, _hook, row = _fixture(tmp_path)
    before = {
        "generation": edge["receipt"]["policy_generation"],
        "policy_digest": edge["receipt"]["policy_digest"],
        "runtime_identity": edge["receipt"]["runtime_identity"],
    }
    after = {**before, "generation": before["generation"] + 1, "policy_digest": "f" * 64}
    calls = []
    worker = SimpleNamespace(policy_snapshot_publisher=SimpleNamespace(current_snapshot_binding=lambda: before))
    session = SimpleNamespace(
        store=store,
        guard_home=store.guard_home,
        workspace=workspace,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)),
    )

    def stopped():
        calls.append("contained")
        assert store.get_approval_request(row["request_id"])["status"] == "pending"
        return True

    def ack(_fixture, action, *, previous_generation):
        calls.append(("acked", action, previous_generation))
        if action == "block":
            actual = config.load_guard_config(store.guard_home)
            assert actual.default_action == actual.subprocess_action == "block"
        return after

    original_update = config.update_guard_settings

    def update(*args, **kwargs):
        calls.append(("settings", args[1], dict(kwargs)))
        assert kwargs == {}  # No gate bypass or synthetic grant.
        return original_update(*args, **kwargs)

    session.stop_resident = stopped
    monkeypatch.setattr(MixedScenarioFixture, "_ack", ack)
    monkeypatch.setattr(config, "update_guard_settings", update)
    fixture = LauncherApprovalFaultFixture(session)
    fixture._scenario = scenario
    try:
        fixture._pending(row["request_id"])
        assert fixture._fault["pending_observed"] is True
        assert fixture._fault["original_wait_live"] is True
        assert fixture._fault["binding_before"] == before
        assert fixture._fault["binding_after"] == after
        assert fixture._fault["applied"] is True
        assert store.get_approval_request(row["request_id"])["status"] == "pending"
        if scenario == "resident_restart_pending":
            assert calls == ["contained", ("acked", "allow", 0)]
        else:
            assert calls[0] == ("settings", {"default_action": "block", "subprocess_action": "block"}, {})
            assert calls[1] == ("acked", "block", before["generation"])
    finally:
        fixture.close()
