"""Finite synthetic controls for failure evidence; no Windows runtime claim."""

from __future__ import annotations

import json
import threading
from contextvars import copy_context
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from ci.native_runtime import default_auto_failure as evidence
from ci.native_runtime import default_auto_routes as routes
from ci.native_runtime import probe_native_default_auto as probe
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeCapabilities, NativeRuntimeIdentity


def _publisher() -> NativePolicySnapshotPublisher:
    publisher = NativePolicySnapshotPublisher.__new__(NativePolicySnapshotPublisher)
    publisher._condition = threading.Condition()
    publisher._epoch = 3
    publisher._snapshot = {"generation": 7, "private_payload": "PRIVATE_SNAPSHOT"}
    publisher._acked = True
    publisher._closed = False
    publisher._last_error = "native_policy_snapshot_resident_changed"
    return publisher


def _daemon(publisher: object) -> SimpleNamespace:
    return SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher)))


def _identity(capture: evidence.DefaultAutoFailureCapture, tmp_path: Path) -> None:
    capture.bind_identity(
        NativeRuntimeIdentity(tmp_path / "PRIVATE_RUNTIME_PATH", 123, 456, "a" * 64),
        NativeRuntimeCapabilities(3, "PRIVATE_VERSION", "b" * 64, "c" * 40, "x86_64-windows", ()),
    )


def _read(tmp_path: Path) -> dict[str, Any]:
    return json.loads((tmp_path / "probe-failure.json").read_text(encoding="utf-8"))


def test_failure_keeps_original_and_build_identity_with_fixed_private_free_schema(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SOURCE_SHA", "d" * 40)
    success = tmp_path / "probe.json"
    success.write_text("existing success is separate", encoding="utf-8")
    error = RuntimeError("PRIVATE_EXCEPTION_TEXT")
    daemon = _daemon(_publisher())
    with pytest.raises(RuntimeError) as raised, evidence.DefaultAutoFailureCapture(success) as capture:
        _identity(capture, tmp_path)
        evidence.bind_corpus(daemon)
        evidence.observe_delivery(
            daemon,
            "claude-code",
            "PostToolUse",
            {
                "reason_code": "native_hook_unavailable",
                "decision": "allow",
                "payload": "PRIVATE_REQUEST_BODY",
            },
        )
        evidence.observe_corpus(daemon, {"routes": {"native_resident": 3, "native_fail_safe": 18}})
        evidence.end_corpus(daemon, {}, {"receipt_accepted": 21, "PRIVATE_RECEIPT": 44})
        raise error
    assert raised.value is error
    report = _read(tmp_path)
    assert report["passed"] is False and report["qualification"] is False
    assert (
        report["required_native_decisions"],
        report["allowed_fail_safe_decisions"],
        report["readiness_budget_ms"],
    ) == (21, 0, 400)
    assert report["expected_build_sha"] == "d" * 40
    assert report["installed_identity"] == {
        "build_sha": "c" * 40,
        "runtime_sha256": "a" * 64,
        "rule_digest": "b" * 64,
        "runtime_size": 123,
        "protocol_version": 3,
        "target": "x86_64-windows",
    }
    assert report["deliveries"][0]["reason_code"] == "native_hook_unavailable"
    assert "route" not in report["deliveries"][0]
    assert report["corpus"]["routes"] == {"native_resident": 3, "native_fail_safe": 18}
    assert "PRIVATE" not in json.dumps(report)
    assert success.read_text(encoding="utf-8") == "existing success is separate"


def test_success_and_retired_capture_emit_no_failure_or_late_delivery(tmp_path) -> None:
    daemon = _daemon(_publisher())
    with evidence.DefaultAutoFailureCapture(tmp_path / "probe.json") as capture:
        evidence.bind_corpus(daemon)
        evidence.end_corpus(daemon, {}, {})
        evidence.observe_delivery(daemon, "pi", "PostToolUse", {})
    evidence.observe_delivery(daemon, "pi", "PostToolUse", {})
    assert capture._deliveries == []
    assert evidence._ACTIVE.get() is None
    assert not (tmp_path / "probe-failure.json").exists()


@pytest.mark.parametrize("private_value", ["PRIVATE_REASON", {"PRIVATE": "VALUE"}, ["PRIVATE"], True, 7])
def test_unknown_or_malformed_response_values_never_export_arbitrary_content(tmp_path, private_value) -> None:
    daemon = _daemon(_publisher())
    with pytest.raises(ValueError), evidence.DefaultAutoFailureCapture(tmp_path / "probe.json"):
        evidence.bind_corpus(daemon)
        evidence.observe_delivery(
            daemon,
            "PRIVATE_HARNESS",
            "PRIVATE_EVENT",
            {
                "reason_code": private_value,
                "decision": private_value,
            },
        )
        raise ValueError("PRIVATE_FAILURE")
    row = _read(tmp_path)["deliveries"][0]
    assert [row[name] for name in ("harness", "event", "reason_code", "decision")] == ["other"] * 4
    assert "PRIVATE" not in json.dumps(_read(tmp_path))


def test_delivery_inventory_is_bounded_and_not_a_route_attribution(tmp_path) -> None:
    daemon = _daemon(_publisher())
    with pytest.raises(RuntimeError), evidence.DefaultAutoFailureCapture(tmp_path / "probe.json"):
        evidence.bind_corpus(daemon)
        for _ in range(30):
            evidence.observe_delivery(daemon, "pi", "PostToolUse", {"decision": "allow"})
        raise RuntimeError()
    report = _read(tmp_path)
    assert len(report["deliveries"]) == 21
    assert report["detail_incomplete"] is True
    assert all(
        row["publisher_attribution"] == "state_observed_after_delivery_not_request_cause"
        for row in report["deliveries"]
    )
    assert (tmp_path / "probe-failure.json").stat().st_size <= 32 * 1024


def test_publisher_is_exact_owned_object_and_snapshots_do_not_follow_later_generation(tmp_path) -> None:
    publisher = _publisher()
    daemon = _daemon(publisher)
    with pytest.raises(RuntimeError), evidence.DefaultAutoFailureCapture(tmp_path / "probe.json"):
        evidence.bind_corpus(daemon)
        evidence.observe_delivery(daemon, "pi", "PostToolUse", {})
        evidence.observe_corpus(daemon, {"routes": {"native_resident": 3, "PRIVATE": 9, "native_fail_safe": True}})
        publisher._snapshot = {"generation": 999}
        publisher._last_error = "PRIVATE_LATE_FAILURE"
        daemon._server.hook_worker.policy_snapshot_publisher = _publisher()
        evidence.observe_delivery(daemon, "pi", "PostToolUse", {})
        evidence.end_corpus(daemon, {}, {})
        evidence.observe_delivery(daemon, "pi", "PostToolUse", {})
        raise RuntimeError()
    report = _read(tmp_path)
    assert len(report["deliveries"]) == 2
    assert report["deliveries"][0]["publisher_after_delivery"]["snapshot_generation"] == 7
    assert report["deliveries"][1]["publisher_after_delivery"] == {
        "available": False,
        "owned_publisher_changed_or_retired": True,
    }
    assert report["corpus"]["publisher"]["snapshot_generation"] == 7
    assert report["corpus"]["routes"] == {"native_resident": 3}
    assert "PRIVATE" not in json.dumps(report)


def test_busy_publisher_never_waits_for_lock(tmp_path) -> None:
    publisher = _publisher()
    entered, release = threading.Event(), threading.Event()

    def hold() -> None:
        with publisher._condition:
            entered.set()
            assert release.wait(5)

    thread = threading.Thread(target=hold)
    thread.start()
    try:
        assert entered.wait(5)
        with pytest.raises(RuntimeError), evidence.DefaultAutoFailureCapture(tmp_path / "probe.json"):
            daemon = _daemon(publisher)
            evidence.bind_corpus(daemon)
            evidence.observe_delivery(daemon, "pi", "PostToolUse", {})
            assert not release.is_set()
            raise RuntimeError()
        assert _read(tmp_path)["deliveries"][0]["publisher_after_delivery"] == {"available": False, "busy": True}
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive()


def test_context_owner_and_nested_lifetimes_prevent_cross_probe_capture(tmp_path) -> None:
    daemon = _daemon(_publisher())
    with evidence.DefaultAutoFailureCapture(None) as outer:
        evidence.bind_corpus(daemon)
        copied = copy_context()
        thread = threading.Thread(target=lambda: copied.run(evidence.observe_delivery, daemon, "pi", "PostToolUse", {}))
        thread.start()
        thread.join(5)
        assert not thread.is_alive()
        with evidence.DefaultAutoFailureCapture(tmp_path / "probe.json") as inner:
            evidence.bind_corpus(daemon)
            evidence.observe_delivery(daemon, "pi", "PostToolUse", {})
        evidence.observe_delivery(daemon, "pi", "PostToolUse", {})
        assert len(outer._deliveries) == len(inner._deliveries) == 1
    assert evidence._ACTIVE.get() is None


def test_caller_client_context_is_explicitly_not_worker_attribution(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(evidence, "native_resident_client_failure_code", lambda: "native_client_timed_out")
    with pytest.raises(RuntimeError), evidence.DefaultAutoFailureCapture(tmp_path / "probe.json"):
        daemon = _daemon(_publisher())
        evidence.bind_corpus(daemon)
        evidence.end_corpus(daemon, {}, {})
        raise RuntimeError()
    assert _read(tmp_path)["corpus"]["client_context"] == {
        "scope": "probe_context_only",
        "daemon_worker_attribution": False,
        "code": "native_client_timed_out",
    }


@pytest.mark.parametrize("failure", ["collector", "serialization", "oversize", "existing_file"])
def test_optional_detail_or_write_failure_cannot_mask_original_or_lose_bound_identity(
    tmp_path, monkeypatch, failure
) -> None:
    error = RuntimeError("original private error")
    if failure == "existing_file":
        (tmp_path / "probe-failure.json").write_text("prior evidence", encoding="utf-8")
    with pytest.raises(RuntimeError) as raised, evidence.DefaultAutoFailureCapture(tmp_path / "probe.json") as capture:
        _identity(capture, tmp_path)
        daemon = _daemon(_publisher())
        evidence.bind_corpus(daemon)
        if failure == "collector":

            def fail(_publisher: object) -> dict[str, object]:
                raise OSError("private lock failure")

            monkeypatch.setattr(evidence, "_publisher_state", fail)
            evidence.observe_delivery(daemon, "pi", "PostToolUse", {})
        elif failure in {"serialization", "oversize"}:
            capture._corpus["bad_detail"] = object() if failure == "serialization" else "x" * 33000
        raise error
    assert raised.value is error
    if failure == "existing_file":
        assert (tmp_path / "probe-failure.json").read_text(encoding="utf-8") == "prior evidence"
    else:
        report = _read(tmp_path)
        assert report["detail_incomplete"] is True
        assert report["installed_identity"]["build_sha"] == "c" * 40
        assert "bad_detail" not in json.dumps(report)


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_actual_corpus_wrong_route_gate_keeps_pre_cleanup_state(tmp_path, monkeypatch, cleanup_fails) -> None:
    publisher = _publisher()
    publisher._workspace_paths = {(tmp_path / "hook-workspace").resolve()}
    stopped: list[bool] = []
    worker = SimpleNamespace(
        policy_snapshot_publisher=publisher,
        prepare_workspace_policy=lambda *args, **kwargs: object(),
        metrics=SimpleNamespace(snapshot=lambda: {"routes": {"native_resident": 3, "native_fail_safe": 18}}),
    )

    class Daemon:
        def __init__(self, *args, **kwargs):
            self._server = SimpleNamespace(hook_worker=worker, runtime_hook_evidence_writer=object())

        def start(self):
            pass

        def stop(self):
            stopped.append(True)
            publisher._snapshot = {"generation": 888}
            if cleanup_fails:
                raise OSError("PRIVATE_STOP_FAILURE")

    def deliveries(daemon, _home, _workspace, _routes, receipts, _reasons):
        for _ in range(21):
            receipts.append({"route": "native_resident"})
            evidence.observe_delivery(daemon, "pi", "PostToolUse", {"reason_code": "native_hook_unavailable"})

    def modes(*_args):
        publisher._snapshot = {"generation": 777}
        return {}

    monkeypatch.setattr(probe, "GuardStore", lambda *args: object())
    monkeypatch.setattr(probe, "_prepare_empty_command_authority", lambda store: {})
    monkeypatch.setattr(probe, "GuardDaemonServer", Daemon)
    monkeypatch.setattr(probe, "_ownership_routes", lambda: {})
    monkeypatch.setattr(probe, "_exercise_installed_routes", deliveries)
    monkeypatch.setattr(probe, "_exercise_mode_invariants", modes)
    monkeypatch.setattr(probe, "wait_for_receipt_corpus", lambda *args, **kwargs: {"receipt_accepted": 21})
    with (
        pytest.raises(OSError if cleanup_fails else RuntimeError),
        evidence.DefaultAutoFailureCapture(tmp_path / "probe.json"),
    ):
        probe._installed_hook_corpus(tmp_path)
    report = _read(tmp_path)
    assert stopped == [True]
    assert report["corpus"]["publisher"]["snapshot_generation"] == 7
    assert report["corpus"]["routes"] == {"native_resident": 3, "native_fail_safe": 18}
    assert len(report["deliveries"]) == 21
    assert report["passed"] is False


def test_route_observer_preserves_exact_request_once_and_original_denial(tmp_path, monkeypatch) -> None:
    calls: list[tuple[object, ...]] = []
    denial = {"decision": "deny", "reason_code": "native_policy_block", "PRIVATE": "BODY"}

    def request(*args):
        calls.append(args)
        return denial

    monkeypatch.setattr(routes, "_installed_hook_request", request)
    daemon = _daemon(_publisher())
    with pytest.raises(RuntimeError), evidence.DefaultAutoFailureCapture(tmp_path / "probe.json"):
        evidence.bind_corpus(daemon)
        routes._exercise_installed_routes(
            cast(GuardDaemonServer, cast(object, daemon)),
            tmp_path,
            tmp_path,
            {"pi": {"pre_tool_use": "installed_pre", "post_tool_use": "none"}},
            [],
            {},
        )
    assert len(calls) == 1
    assert calls[0][:5] == (daemon, tmp_path, tmp_path, "pi", "PreToolUse")
    assert calls[0][5] == {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "printf guard"},
    }
    assert _read(tmp_path)["deliveries"][0]["reason_code"] == "native_policy_block"
    assert "PRIVATE" not in json.dumps(_read(tmp_path))


def test_primary_failure_is_retained_separately_when_cleanup_replaces_it(tmp_path) -> None:
    with pytest.raises(OSError), evidence.DefaultAutoFailureCapture(tmp_path / "probe.json"):
        evidence.bind_corpus(_daemon(_publisher()))
        try:
            raise ValueError("PRIVATE_PRIMARY")
        except ValueError as error:
            evidence.observe_corpus_failure(error)
            raise OSError("PRIVATE_CLEANUP") from error
    report = _read(tmp_path)
    assert report["primary_failure_before_cleanup"] == "ValueError"
    assert report["original_failure_category"] == "OSError"
    assert "PRIVATE" not in json.dumps(report)


def test_main_binds_verified_installed_identity_before_original_probe_failure(tmp_path, monkeypatch) -> None:
    identity = NativeRuntimeIdentity(tmp_path / "PRIVATE_RUNTIME", 123, 456, "a" * 64)
    capabilities = NativeRuntimeCapabilities(3, "PRIVATE_VERSION", "b" * 64, "c" * 40, "x86_64-windows", ())
    error = RuntimeError("PRIVATE_ORIGINAL")

    def fail(_identity):
        assert _identity is identity
        raise error

    monkeypatch.setattr(probe.codex_plugin_scanner, "__file__", str(tmp_path / "installed" / "__init__.py"))
    monkeypatch.setattr(probe, "_require_clean_probe_environment", lambda: None)
    monkeypatch.setattr(probe, "_probe_native_identity", lambda: (object(), identity, capabilities))
    monkeypatch.setattr(probe, "_assert_binary_override_ignored", lambda _identity: None)
    monkeypatch.setattr(probe, "_run_temporary_probe", fail)
    with pytest.raises(RuntimeError) as raised:
        probe.main(json_path=tmp_path / "probe.json")
    assert raised.value is error
    report = _read(tmp_path)
    assert report["installed_identity"]["runtime_sha256"] == identity.sha256
    assert report["installed_identity"]["build_sha"] == capabilities.build_sha
    assert not (tmp_path / "probe.json").exists()


def test_failure_before_verified_identity_never_invents_runtime_binding(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SOURCE_SHA", "PRIVATE_INVALID_BUILD")

    def fail():
        raise ValueError("PRIVATE_ENVIRONMENT_FAILURE")

    monkeypatch.setattr(probe, "_require_clean_probe_environment", fail)
    with pytest.raises(ValueError):
        probe.main(json_path=tmp_path / "probe.json")
    report = _read(tmp_path)
    assert report["expected_build_sha"] is None
    assert report["installed_identity"] == {}
    assert "PRIVATE" not in json.dumps(report)


def test_receipt_failure_maps_keep_failed_attempts_and_snapshot_existing_stats(tmp_path) -> None:
    original = RuntimeError("PRIVATE_ORIGINAL")
    all_failures = {"receipt_persistence/sqlite_busy": 1, "journal_checkpoint/os_permission": 2}
    receipt_failures = {"receipt_persistence/sqlite_busy": 1}
    stats = {
        "receipt_accepted": 19,
        "receipt_processed": 19,
        "receipt_failures": 1,
        "failure_diagnostics": all_failures,
        "receipt_failure_diagnostics": receipt_failures,
    }
    with pytest.raises(RuntimeError) as caught, evidence.DefaultAutoFailureCapture(tmp_path / "probe.json"):
        daemon = _daemon(_publisher())
        evidence.bind_corpus(daemon)
        evidence.end_corpus(daemon, {"routes": {"native_resident": 19}}, stats)
        all_failures.clear()
        receipt_failures.clear()
        raise original
    assert caught.value is original
    report = _read(tmp_path)
    assert report["corpus"]["evidence_failure_diagnostics"] == {
        "all_evidence": {"receipt_persistence/sqlite_busy": 1, "journal_checkpoint/os_permission": 2},
        "native_receipts": {"receipt_persistence/sqlite_busy": 1},
    }
    assert report["corpus"]["receipt_counts"] == {
        "receipt_accepted": 19,
        "receipt_processed": 19,
        "receipt_failures": 1,
    }
    assert report["passed"] is report["qualification"] is False
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ({}, {}),
        ({"PRIVATE_PATH/PRIVATE_MESSAGE": 1}, None),
        ({"receipt_persistence/os_timeout": True}, None),
        ({"receipt_persistence/os_timeout": -1}, None),
    ],
    ids=["unavailable", "known-empty", "unknown-key", "boolean-count", "negative-count"],
)
def test_missing_and_malformed_failure_maps_remain_unavailable_without_private_values(
    tmp_path, value, expected
) -> None:
    with pytest.raises(RuntimeError), evidence.DefaultAutoFailureCapture(tmp_path / "probe.json"):
        daemon = _daemon(_publisher())
        evidence.bind_corpus(daemon)
        evidence.end_corpus(daemon, {}, {"failure_diagnostics": value, "receipt_failure_diagnostics": value})
        raise RuntimeError("PRIVATE_ORIGINAL")
    report = _read(tmp_path)
    assert report["corpus"]["evidence_failure_diagnostics"] == {
        "all_evidence": expected,
        "native_receipts": expected,
    }
    assert "PRIVATE" not in json.dumps(report)


def test_current_counter_contract_failure_keeps_original_probe_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_diagnostics as writer_diagnostics

    original = RuntimeError("PRIVATE_ORIGINAL")
    failure_map = {"receipt_persistence/sqlite_busy": 1}
    observed: list[object] = []

    def fail_snapshot(value: object) -> dict[str, int] | None:
        observed.append(value)
        raise RuntimeError("PRIVATE_COUNTER_FAILURE")

    monkeypatch.setattr(writer_diagnostics, "evidence_failure_snapshot", fail_snapshot)
    with pytest.raises(RuntimeError) as caught, evidence.DefaultAutoFailureCapture(tmp_path / "probe.json") as capture:
        daemon = _daemon(_publisher())
        evidence.bind_corpus(daemon)
        evidence.end_corpus(
            daemon,
            {"routes": {"native_resident": 19}},
            {"receipt_accepted": 19, "receipt_failures": 1, "failure_diagnostics": failure_map},
        )
        raise original
    assert caught.value is original
    assert len(observed) == 1 and observed[0] is failure_map
    report = _read(tmp_path)
    assert report["detail_incomplete"] is True
    assert report["passed"] is report["qualification"] is False
    assert report["corpus"]["receipt_counts"] == {"receipt_accepted": 19, "receipt_failures": 1}
    assert "evidence_failure_diagnostics" not in report["corpus"]
    assert "PRIVATE" not in json.dumps(report)
    assert evidence._ACTIVE.get() is None
    assert capture._publisher is None and capture._corpus_active is False
