from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from contextvars import Context
from pathlib import Path
from types import MethodType, SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler
from scripts.native_slo_faults import FaultFixture

from .native_review_approval_support import _bound_review_evidence


def _session(tmp_path: Path) -> SimpleNamespace:
    home, workspace = tmp_path / "guard", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    snapshot = {
        "mode": "enforce",
        "effective_policy": {
            "default_action": "allow",
            "subprocess_action": "allow",
            "risk_actions": {"execution": "allow"},
        },
    }
    worker = SimpleNamespace(
        policy_snapshot_publisher=SimpleNamespace(current_snapshot=lambda: snapshot, is_ready=lambda: True),
        test_oracle=None,
        _review_raw_hook_native=lambda **_kwargs: {"result": {"decision": "allow"}},
    )
    return SimpleNamespace(
        command_authority_fixture={"verified_health": "protected"},
        root=tmp_path,
        guard_home=home,
        workspace=workspace,
        store=SimpleNamespace(add_approval_request=lambda **_kwargs: None),
        daemon=SimpleNamespace(
            _server=SimpleNamespace(
                hook_worker=worker, runtime_hook_scheduler=RuntimeHookScheduler(retained_bytes_limit=1024)
            )
        ),
    )


def test_unavailability_witness_is_not_asserted_until_injected_fault_runs(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard import native_hook_edge

    original = native_hook_edge.native_resident_client_request
    session = _session(tmp_path)
    with FaultFixture(session, "unavailable") as fault:
        assert "native_request_unavailable" not in fault.result()["setup"]
        assert native_hook_edge.native_resident_client_request() is None
        assert fault.result()["setup"]["native_request_unavailable"] is True
        fault.before_case()
        assert "native_request_unavailable" not in fault.result()["setup"]
    assert native_hook_edge.native_resident_client_request is original


def test_byte_fault_exercises_real_scheduler_and_restores_limit(tmp_path: Path) -> None:
    session = _session(tmp_path)
    scheduler = session.daemon._server.runtime_hook_scheduler
    with FaultFixture(session, "queue_bytes") as fault:
        assert "byte_reservation_rejected" not in fault.result()["setup"]
        assert scheduler.reserve_bytes(payload_bytes=100, deadline=time.monotonic() + 1) == (
            None,
            "daemon_hook_queue_bytes",
        )
        assert fault.result()["setup"]["byte_reservation_rejected"] is True
    assert scheduler.stats()["retained_bytes_limit"] == 1024


def test_unknown_fault_has_no_fake_success(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="no witnessed implementation"), FaultFixture(_session(tmp_path), "unknown"):
        pass


def test_enter_failure_restores_publisher_and_native_observers(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
    from codex_plugin_scanner.guard.store import GuardStore

    session = _session(tmp_path)
    publisher = NativePolicySnapshotPublisher(store=GuardStore(session.guard_home))
    worker = session.daemon._server.hook_worker
    worker.policy_snapshot_publisher = publisher
    original_record = publisher._record_error
    original_native = worker._review_raw_hook_native
    try:
        with pytest.raises(RuntimeError, match="no witnessed implementation"), FaultFixture(session, "unknown"):
            pytest.fail("unknown setup cannot enter")
        assert publisher._record_error == original_record
        assert "_record_error" not in publisher.__dict__
        assert worker._review_raw_hook_native is original_native
    finally:
        publisher.close()


def test_integrity_fault_observes_the_handler_local_import_without_faking_rejection(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime import hook_payload_reference

    original = hook_payload_reference.hook_payload_reference_size
    with FaultFixture(_session(tmp_path), "integrity") as fault:
        # The real HTTP handler resolves this import when it handles a request.
        from codex_plugin_scanner.guard.runtime.hook_payload_reference import hook_payload_reference_size

        assert "payload_reference_rejected" not in fault.result()["setup"]
        assert hook_payload_reference_size({"tool_output": "benign"}) is None
        assert "payload_reference_rejected" not in fault.result()["setup"]
        with pytest.raises(hook_payload_reference.HookPayloadReferenceError):
            hook_payload_reference_size({"guard_payload_ref": {"version": 1}})
        assert fault.result()["setup"]["payload_reference_rejected"] is True
    assert hook_payload_reference.hook_payload_reference_size is original


def test_approval_persistence_fault_is_witnessed_through_real_positional_caller(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon.hook_native_review_approval import pause_native_pre_tool_for_approval
    from codex_plugin_scanner.guard.store import GuardStore

    session = _session(tmp_path)
    session.store = GuardStore(session.guard_home)
    original = session.store.add_approval_request
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git diff"}}
    native_result, receipt = _bound_review_evidence(
        harness="claude-code",
        payload=payload,
        workspace=session.workspace,
        native_result={"decision": "deny", "minimum_action": "review", "policy_action": "review"},
    )
    with FaultFixture(session, "review_queue_failed") as fault:
        assert "approval_persistence_failed" not in fault.result()["setup"]
        response = pause_native_pre_tool_for_approval(
            session.store,
            harness="claude-code",
            payload=payload,
            native_result=native_result,
            native_receipt=None,
            workspace=session.workspace,
            guard_home=session.guard_home,
        )
        assert response["reason_code"] == "native_review_policy_binding_invalid"
        assert response["policy_action"] == "block"
        assert "approval_persistence_failed" not in fault.result()["setup"]
        assert session.store.list_approval_requests(status="pending") == []
        response = pause_native_pre_tool_for_approval(
            session.store,
            harness="claude-code",
            payload=payload,
            native_result=native_result,
            native_receipt=None,
            workspace=session.workspace,
            guard_home=session.guard_home,
            verified_receipt=receipt,
        )
        assert fault.result()["setup"]["approval_persistence_failed"] is True
        assert response["reason_code"] == "native_review_queue_failed"
        assert response["policy_action"] == "block"
        assert session.store.list_approval_requests(status="pending") == []
        fault.before_case()
        assert "approval_persistence_failed" not in fault.result()["setup"]
    assert session.store.add_approval_request == original


def test_serial_case_captures_native_failure_in_worker_context_and_resets_between_cases(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.native_resident_client import (
        native_resident_client_failure_code,
        record_native_resident_client_failure_code,
    )

    def run() -> None:
        record_native_resident_client_failure_code("native_client_endpoint_invalid")
        session = _session(tmp_path)
        worker = session.daemon._server.hook_worker
        arguments = {"deadline": time.monotonic() + 1, "policy_snapshot": {"generation": 1, "mode": "enforce"}}
        received = []

        def native(**kwargs: object) -> None:
            received.append(kwargs)
            record_native_resident_client_failure_code("native_client_timed_out")
            return None

        worker._review_raw_hook_native = native
        with FaultFixture(session, "normal") as fault, ThreadPoolExecutor(max_workers=1) as pool:
            fault.before_case()
            assert pool.submit(worker._review_raw_hook_native, **arguments).result(timeout=1) is None
            result = fault.result()
            assert result["native_result"] is None and result["native_call_count"] == 1
            assert result["native_completed_call_count"] == 1
            diagnostic = result["native_call_diagnostic"]
            assert diagnostic["client_before_state"] == "absent"
            assert diagnostic["client_after_value"] == "native_client_timed_out"
            assert diagnostic["client_code_attribution"] == "context_transition"
            assert diagnostic["caller_deadline_valid"] is diagnostic["policy_generation_valid"] is True
            assert native_resident_client_failure_code() == "native_client_endpoint_invalid"
            assert received == [arguments] and received[0]["policy_snapshot"] is arguments["policy_snapshot"]
            fault.before_case()
            assert fault.result()["native_result"] is fault.result()["native_call_diagnostic"] is None
            assert fault.result()["native_call_count"] == 0
        assert worker._review_raw_hook_native is native

    Context().run(run)


def test_native_capture_preserves_exact_success_and_exception(tmp_path: Path) -> None:
    session = _session(tmp_path)
    worker = session.daemon._server.hook_worker
    edge = {"result": {"decision": "deny"}}
    error = RuntimeError("original unchanged error")

    def native(*, fail: bool = False) -> object:
        if fail:
            raise error
        return edge

    worker._review_raw_hook_native = native
    with FaultFixture(session, "normal") as fault:
        assert worker._review_raw_hook_native() is edge
        assert fault.result()["native_result"] == edge["result"]
        fault.before_case()
        with pytest.raises(RuntimeError) as caught:
            worker._review_raw_hook_native(fail=True)
        assert caught.value is error
        assert fault.result()["native_call_count"] == 1
        assert fault.result()["native_completed_call_count"] == 0
        assert fault.result()["native_call_diagnostic"] is None


def test_policy_refusal_captures_original_reason_once_for_only_the_owned_daemon(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_worker_responses as responses

    session = _session(tmp_path)
    server = session.daemon._server
    first = "native_policy_windows_acl_verify_failed"
    later = "native_policy_snapshot_generation_lock_timeout"
    publisher = server.hook_worker.policy_snapshot_publisher
    publisher.last_error = first
    original = responses._native_policy_not_ready_reason
    returned = []
    received = []

    def original_with_later_state(daemon_server):
        received.append(daemon_server)
        reason = original(daemon_server)
        returned.append(reason)
        publisher.last_error = later
        return reason

    monkeypatch.setattr(responses, "_native_policy_not_ready_reason", original_with_later_state)
    fault = FaultFixture(session, "normal")
    assert fault.result()["policy_refusal_count"] is None
    with fault, ThreadPoolExecutor(max_workers=1) as pool:
        fault.before_case()
        assert fault.result()["policy_refusal_count"] == 0
        result = pool.submit(responses._native_policy_not_ready_reason, server).result(timeout=1)
        assert result is returned[0] and received == [server]
        evidence = fault.result()
        assert evidence["policy_refusal_count"] == 1
        assert evidence["policy_refusal_diagnostic"]["publisher_error_value"] == first
        assert publisher.last_error == later
        assert evidence["native_call_count"] == evidence["native_completed_call_count"] == 0
        assert evidence["native_call_diagnostic"] is None
        other = SimpleNamespace(hook_worker=server.hook_worker)
        assert responses._native_policy_not_ready_reason(other) is returned[1]
        assert received == [server, other]
        assert fault.result()["policy_refusal_count"] == 1
        assert fault.result()["policy_refusal_diagnostic"] == evidence["policy_refusal_diagnostic"]
        fault.before_case()
        assert fault.result()["policy_refusal_count"] == 0
        assert fault.result()["policy_refusal_diagnostic"] is None
    assert responses._native_policy_not_ready_reason is original_with_later_state


def test_policy_refusal_preserves_original_exception_identity_and_restores_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_worker_responses as responses

    session = _session(tmp_path)
    failure = RuntimeError("original private failure")
    calls = []

    def original(daemon_server):
        calls.append(daemon_server)
        raise failure

    monkeypatch.setattr(responses, "_native_policy_not_ready_reason", original)
    with FaultFixture(session, "normal") as fault:
        with pytest.raises(RuntimeError) as caught:
            responses._native_policy_not_ready_reason(session.daemon._server)
        assert caught.value is failure and calls == [session.daemon._server]
        assert fault.result()["policy_refusal_count"] == 0
        assert fault.result()["policy_refusal_diagnostic"] is None
    assert responses._native_policy_not_ready_reason is original


def test_missing_reason_observer_stays_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.daemon import hook_worker_responses as responses

    monkeypatch.delattr(responses, "_native_policy_not_ready_reason")
    with FaultFixture(_session(tmp_path), "normal") as fault:
        fault.before_case()
        assert fault.result()["policy_refusal_count"] is None
        assert fault.result()["policy_refusal_diagnostic"] is None


def test_policy_refusal_retains_the_owned_original_publisher_cause_across_cases(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.config_source_io import GuardConfigSourceError
    from codex_plugin_scanner.guard.daemon import hook_worker_responses as responses
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
    from codex_plugin_scanner.guard.store import GuardStore

    session = _session(tmp_path)
    publisher = NativePolicySnapshotPublisher(store=GuardStore(session.guard_home))
    session.daemon._server.hook_worker.policy_snapshot_publisher = publisher
    original = publisher._record_error
    try:
        with FaultFixture(session, "normal") as fault:
            try:
                try:
                    raise OSError(32, "private configuration error")
                except OSError as error:
                    raise GuardConfigSourceError("guard_config_source_unavailable") from error
            except GuardConfigSourceError as error:
                publisher._record_error(type(error).__name__)
            # The current error can predate a case; it remains tied to the same
            # publisher record rather than being relabelled as a new failure.
            for _ in range(2):
                fault.before_case()
                reason = responses._native_policy_not_ready_reason(session.daemon._server)
                assert "guardconfigsourceerror" in reason
                diagnostic = fault.result()["policy_refusal_diagnostic"]
                assert isinstance(diagnostic, dict)
                assert diagnostic["publisher_error_value"] == "guardconfigsourceerror"
                cause = diagnostic["publisher_config_failure"]
                assert isinstance(cause, dict)
                assert cause["config_cause_1_errno"] == 32
                assert cause["observer_generation"] == 2
                assert fault.result()["native_call_count"] == 0
            publisher._record_error("native_policy_snapshot_expired")
            fault.before_case()
            responses._native_policy_not_ready_reason(session.daemon._server)
            diagnostic = fault.result()["policy_refusal_diagnostic"]
            assert isinstance(diagnostic, dict) and "publisher_config_failure" not in diagnostic
        assert publisher._record_error == original
        assert "_record_error" not in publisher.__dict__
    finally:
        publisher.close()


def test_optional_refusal_serializer_failure_does_not_replace_the_original_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_worker_responses as responses
    from scripts import native_slo_faults

    session = _session(tmp_path)
    returned = object()
    monkeypatch.setattr(responses, "_native_policy_not_ready_reason", lambda _server: returned)

    def unavailable(_reason):
        raise RuntimeError("private diagnostic failure")

    monkeypatch.setattr(native_slo_faults, "policy_refusal_diagnostic", unavailable)
    with FaultFixture(session, "normal") as fault:
        assert responses._native_policy_not_ready_reason(session.daemon._server) is returned
        assert fault.result()["policy_refusal_count"] == 1
        assert fault.result()["policy_refusal_diagnostic"] == {"publisher_error_state": "collection_failed"}


def test_optional_refusal_recording_failure_marks_count_unavailable_until_next_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_worker_responses as responses

    session = _session(tmp_path)
    returned = "HOL Guard could not prepare the native policy safely. native_policy_windows_acl_verify_failed."
    monkeypatch.setattr(responses, "_native_policy_not_ready_reason", lambda _server: returned)

    class UnavailableLock:
        def __enter__(self):
            raise RuntimeError("private capture failure")

        def __exit__(self, *_args):
            raise AssertionError("unavailable lock was never acquired")

    with FaultFixture(session, "normal") as fault:
        original_lock = fault.capture_lock
        fault.capture_lock = UnavailableLock()
        try:
            assert responses._native_policy_not_ready_reason(session.daemon._server) is returned
        finally:
            fault.capture_lock = original_lock
        assert fault.result()["policy_refusal_count"] is None
        assert fault.result()["policy_refusal_diagnostic"] is None
        assert responses._native_policy_not_ready_reason(session.daemon._server) is returned
        assert fault.result()["policy_refusal_count"] is None
        fault.before_case()
        assert fault.result()["policy_refusal_count"] == 0


def test_production_posttool_refusal_response_and_route_are_unchanged_with_private_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_worker as worker_module
    from codex_plugin_scanner.guard.daemon import hook_worker_responses as responses
    from codex_plugin_scanner.guard.daemon.hook_availability_policy import availability_harness_response
    from scripts.native_slo_workloads import build_cases, validate_case

    session = _session(tmp_path)
    worker = session.daemon._server.hook_worker
    calls = []
    routes = []
    code = "native_policy_windows_acl_verify_failed"

    class Publisher:
        @property
        def last_error(self):
            calls.append("last_error")
            return code

        def start(self):
            calls.append("start")

        def register_workspace(self, workspace):
            assert workspace == session.workspace
            calls.append("register_workspace")

        def wait_until_ready(self, _deadline):
            raise AssertionError("the existing nonempty-error branch must not wait")

        def current_snapshot_binding(self):
            calls.append("current_snapshot_binding")
            return None

        def current_snapshot(self):
            calls.append("current_snapshot")
            return None

    worker.policy_snapshot_publisher = Publisher()
    worker._publish_native_policy = True
    worker.prepare_workspace_policy = MethodType(worker_module.HookWorker.prepare_workspace_policy, worker)
    worker.metrics = SimpleNamespace(record_route=routes.append)
    monkeypatch.setattr(worker_module, "native_mode", lambda: "auto")

    class Handler:
        result = None

        def _runtime_hook_fail_safe_response(
            self, payload, _params, *, default_harness, reason, reason_code, native_authoritative
        ):
            assert native_authoritative is True
            return availability_harness_response(
                payload, harness=default_harness, event_name="PostToolUse", reason=reason, reason_code=reason_code
            )

        def _write_json(self, value):
            self.result = value

    handler = Handler()
    case = next(case for case in build_cases(session.workspace) if case.case_id == "pi/PostToolUse/empty-output/empty")
    with FaultFixture(session, "normal") as fault:
        calls.clear()
        assert (
            responses.prepare_native_hook_policy(
                handler, session.daemon._server, case.payload, {}, "pi", session.workspace, 100.4
            )
            is False
        )
        assert calls == [
            "register_workspace",
            "start",
            "last_error",
            "current_snapshot_binding",
            "current_snapshot",
            "last_error",
        ]
        assert handler.result == {
            "decision": "allow",
            "policy_action": "allow",
            "reason_code": "native_policy_not_ready",
        }
        assert routes == ["native_fail_safe"]
        with pytest.raises(AssertionError, match=r"native_qualification_mismatch:.*:route"):
            validate_case(case, handler.result, routes[0])
        evidence = fault.result()
        assert evidence["policy_refusal_count"] == 1
        assert evidence["policy_refusal_diagnostic"]["publisher_error_value"] == code
        assert evidence["native_call_count"] == evidence["native_completed_call_count"] == 0
        assert evidence["native_call_diagnostic"] is None
