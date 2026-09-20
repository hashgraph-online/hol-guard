"""Constructor-order controls with the real worker, publisher and thread."""

from __future__ import annotations

from contextlib import ExitStack
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.daemon import hook_worker
from scripts import native_slo_session
from scripts.native_slo_failure import FixtureFailureError
from scripts.native_slo_workspace_lifecycle_clocks import LifecycleClocks, valid_lifecycle_clocks
from scripts.native_slo_workspace_lifecycle_faults import FirstAdmissionReplyFault
from scripts.native_slo_workspace_lifecycle_service import register_scopes, replace_service
from scripts.native_slo_workspace_observer import PublicationObserver
from scripts.native_slo_workspace_server import WorkspaceScenarioFixture
from scripts.native_slo_workspace_startup import construct_workspace_session, prepare_owned_publisher
from tests.native_policy_snapshot_test_fixtures import _ack, _status


def _auto_constructor(monkeypatch):
    """Use production constructor/start; only native status and IPC are modeled."""
    factory = hook_worker.get_native_policy_snapshot_publisher
    calls = []

    def create(store, **kwargs):
        publisher = factory(store, **kwargs)
        publisher._status_provider = _status
        publisher._client_request = lambda **request: calls.append(request) or _ack(request["payload"])
        return publisher

    monkeypatch.setattr(hook_worker, "get_native_policy_snapshot_publisher", create)
    monkeypatch.setattr(hook_worker, "native_mode", lambda: "auto")
    monkeypatch.setattr(hook_worker, "python_oracle_enabled", lambda: False)
    monkeypatch.setattr(
        native_runtime, "native_runtime_status", lambda: SimpleNamespace(**vars(_status()), reason="native_ready")
    )
    return calls


def test_late_attachment_reproduces_installed_rejection_without_disabling_constructor_start(monkeypatch):
    calls = _auto_constructor(monkeypatch)
    adapter = native_slo_session.AdapterSession(_status().identity.path)
    try:
        assert adapter.daemon._server.hook_worker.policy_snapshot_publisher._thread is not None
        assert calls
        with pytest.raises(RuntimeError, match="observer must precede publisher startup"):
            WorkspaceScenarioFixture(adapter, 1)
    finally:
        adapter.close()


@pytest.mark.parametrize("count", [1, 10, 100])
def test_observation_precedes_real_constructor_start_and_captures_all_first_compile_scopes(monkeypatch, count):
    calls = _auto_constructor(monkeypatch)
    runtime = _status().identity.path
    original = native_slo_session.GuardDaemonServer
    with ExitStack() as lifetime:
        adapter, fixture = construct_workspace_session(
            runtime, count=count, configuration=None, progress=lambda _: None, lifetime=lifetime
        )
        lifetime.callback(adapter.close)
        publisher = fixture.publisher
        assert publisher._thread is not None and publisher._thread.is_alive()
        assert adapter.daemon._server.hook_worker.policy_snapshot_publisher is publisher
        assert publisher._workspace_paths == set(fixture.workspaces)
        assert calls, "the real constructor must execute publication without AdapterSession.enter"
        compiles = [row for row in fixture.observer.rows() if row["kind"] == "compile"]
        assert compiles and all(row["registered_workspaces"] == count for row in compiles)
        assert compiles[0]["succeeded"] and compiles[0]["cache_entries"] == count + 1
        assert native_slo_session.GuardDaemonServer is original
    assert publisher.closed and not publisher._thread.is_alive()
    assert fixture.observer._closed


def test_first_admission_fault_is_attached_before_real_replacement_constructor_publishes(monkeypatch):
    calls = _auto_constructor(monkeypatch)
    adapter = native_slo_session.AdapterSession(_status().identity.path)
    original = adapter.daemon
    original.start()
    try:
        with ExitStack() as lifetime:
            retained = {}

            def prepare(publisher):
                assert publisher._thread is None and publisher.current_snapshot_binding() is None
                retained["observer"] = lifetime.enter_context(PublicationObserver(publisher, (adapter.workspace,)))
                retained["fault"] = lifetime.enter_context(FirstAdmissionReplyFault(publisher))
                register_scopes(publisher, (adapter.workspace,))
                retained["accepted_before_start"] = publisher._thread is None

            monkeypatch.setattr(adapter, "stop_resident", lambda: True)
            before_calls = len(calls)
            clocks = LifecycleClocks()
            proof = replace_service(adapter, (adapter.workspace,), prepare=prepare, clocks=clocks)
            assert valid_lifecycle_clocks(clocks.report())
            assert list(clocks.boundaries) == [
                "store_constructor_enter",
                "store_constructor_return",
                "server_constructor_enter",
                "server_constructor_return",
            ]
            assert clocks.boundaries["store_constructor_return"] <= clocks.boundaries["server_constructor_enter"]
            publisher = adapter.daemon._server.hook_worker.policy_snapshot_publisher
            lifetime.callback(publisher.close)
            assert retained["accepted_before_start"]
            assert proof["cold_publisher_without_ack"] and proof["old_service_contained"]
            assert proof["cold_observation_boundary"] == "before_real_constructor_start"
            assert publisher._thread is not None
            assert len(calls) > before_calls
            fault = retained["fault"].report()
            assert fault["real_accepted_reply_discarded"] and fault["production_ack_error_observed"]
            assert fault["first_error_withheld_ack"]
            rows = retained["observer"].rows()
            assert any(row["kind"] == "barrier" and row["ready"] is False for row in rows)
    finally:
        adapter.close()
        original.stop()


def test_owned_factory_preserves_foreign_calls_arguments_and_original_results(monkeypatch):
    owned, foreign = object(), object()
    publisher = SimpleNamespace(_thread=None, _started=False, current_snapshot_binding=lambda: None)
    other = object()
    calls, prepared = [], []

    def factory(store, *args, **kwargs):
        calls.append((store, args, kwargs))
        return publisher if store is owned else other

    monkeypatch.setattr(hook_worker, "get_native_policy_snapshot_publisher", factory)
    with prepare_owned_publisher(owned, prepared.append) as captured:
        assert hook_worker.get_native_policy_snapshot_publisher(foreign, "foreign", config_capture=other) is other
        assert hook_worker.get_native_policy_snapshot_publisher(owned, config_capture=other) is publisher
        assert captured == prepared == [publisher]
    assert hook_worker.get_native_policy_snapshot_publisher is factory
    assert calls == [(foreign, ("foreign",), {"config_capture": other}), (owned, (), {"config_capture": other})]


@pytest.mark.parametrize("stage", ["factory", "preparation", "constructor"])
def test_original_constructor_boundary_failures_propagate_and_factory_is_restored(monkeypatch, stage):
    owned = object()
    failure = RuntimeError("original constructor failure")
    publisher = SimpleNamespace(_thread=None, _started=False, current_snapshot_binding=lambda: None, closed=False)
    publisher.close = lambda: setattr(publisher, "closed", True)

    def factory(*args, **kwargs):
        if stage == "factory":
            raise failure
        return publisher

    def prepare(value):
        assert value is publisher
        if stage == "preparation":
            raise failure

    monkeypatch.setattr(hook_worker, "get_native_policy_snapshot_publisher", factory)
    with pytest.raises(RuntimeError) as caught, prepare_owned_publisher(owned, prepare):
        hook_worker.get_native_policy_snapshot_publisher(owned)
        raise failure
    assert caught.value is failure
    assert hook_worker.get_native_policy_snapshot_publisher is factory


def test_constructor_exception_after_real_publisher_start_contains_thread_and_preserves_failure(tmp_path, monkeypatch):
    _auto_constructor(monkeypatch)
    from codex_plugin_scanner.guard.store import GuardStore
    from scripts.native_slo_command_fixture import prepare_empty_command_authority

    store = GuardStore(tmp_path / ".hol-guard")
    prepare_empty_command_authority(store)
    failure = RuntimeError("failure after real worker construction")
    publisher = None
    with pytest.raises(RuntimeError) as caught, prepare_owned_publisher(store, lambda _: None):
        worker = hook_worker.HookWorker(store=store)
        publisher = worker.policy_snapshot_publisher
        assert publisher._thread is not None and publisher._thread.is_alive()
        raise failure
    assert caught.value is failure
    assert publisher is not None and publisher.closed
    assert not publisher._thread.is_alive()


def test_constructor_cleanup_error_retains_original_failure_and_failed_containment(monkeypatch):
    owned = object()
    original = RuntimeError("original failed constructor")

    def close():
        raise OSError("owned publisher cleanup failed")

    publisher = SimpleNamespace(_thread=None, _started=False, current_snapshot_binding=lambda: None, close=close)
    monkeypatch.setattr(hook_worker, "get_native_policy_snapshot_publisher", lambda *_: publisher)
    with pytest.raises(FixtureFailureError) as caught, prepare_owned_publisher(owned, lambda _: None):
        hook_worker.get_native_policy_snapshot_publisher(owned)
        raise original
    assert caught.value.__cause__ is original and str(caught.value) == str(original)
    assert caught.value.detail["category"] == "RuntimeError"
    assert caught.value.detail["captured_publisher_contained"] is False
    assert caught.value.detail["publisher_cleanup_failure"]["category"] == "OSError"


@pytest.mark.parametrize("started", [False, True])
def test_unobserved_or_already_started_publisher_cannot_be_accepted(monkeypatch, started):
    owned = object()
    publisher = SimpleNamespace(_thread=object() if started else None, _started=started)
    monkeypatch.setattr(hook_worker, "get_native_policy_snapshot_publisher", lambda *_: publisher)
    with (
        pytest.raises(RuntimeError, match=r"already started|not observed"),
        prepare_owned_publisher(owned, lambda _: pytest.fail("invalid publisher prepared")),
    ):
        if started:
            hook_worker.get_native_policy_snapshot_publisher(owned)
