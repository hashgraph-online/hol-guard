from __future__ import annotations

import threading
import time
from contextlib import closing, contextmanager
from types import SimpleNamespace

import pytest

from scripts import native_slo_session
from scripts.native_slo_mixed_witness import ReceiptWitness
from scripts.native_slo_workspace_observer import public_binding
from scripts.native_slo_workspace_request_observer import WorkspaceRequestObserver
from tests.native_workspace_request_fixtures import control, finish


def test_http_timeout_does_not_hide_native_call_still_in_flight(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    failure = TimeoutError("original HTTP deadline")
    errors = []
    thread = None

    def blocked():
        entered.set()
        if not release.wait(2):
            raise AssertionError("controlled native release deadline")

    state.before_return = blocked

    def request(_daemon, **kwargs):
        nonlocal thread
        arguments = {
            "payload": kwargs["request_payload"],
            "harness": kwargs["harness"],
            "event": "PreToolUse",
            "guard_home": kwargs["guard_home"],
            "home_dir": state.session.root,
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

        def run():
            try:
                state.worker._review_raw_hook_native(**arguments)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        assert entered.wait(1)
        raise failure

    monkeypatch.setattr(native_slo_session, "_request", request)
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        paired = state.worker._review_raw_hook_native
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            accepted = time.monotonic()
            try:
                with pytest.raises(TimeoutError) as captured:
                    observer.probe(0, 1)
                assert captured.value is failure
                observer.close()
                assert state.worker._review_raw_hook_native is paired
                assert observer._active_at_freeze == 0
                assert observer._native_at_freeze == 1
            finally:
                release.set()
                if thread is not None:
                    thread.join(2)
                    assert not thread.is_alive()
        result = finish(state, witness, observer, accepted)
    assert errors == [] and len(state.calls) == 1
    assert result["passed"] is False
    assert result["observation_lifecycle"]["native_calls_in_flight_at_freeze"] == 1
    assert result["observation_lifecycle"]["native_calls_currently_in_flight"] == 0


def test_freeze_during_valid_request_preserves_incomplete_http_and_native_counts(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            state.before_return = observer.freeze
            accepted = time.monotonic()
            assert observer.probe(0, 1) is state.response
        result = finish(state, witness, observer, accepted)
    assert result["rows"][0]["passed"] is True
    assert result["passed"] is False
    assert result["observation_lifecycle"]["http_requests_in_flight_at_freeze"] == 1
    assert result["observation_lifecycle"]["native_calls_in_flight_at_freeze"] == 1


def test_duplicate_owned_review_still_forwards_and_cannot_pass(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            accepted = time.monotonic()
            observer.probe(0, 1)
            assert state.worker._review_raw_hook_native(**state.request_kwargs) is state.edge
        result = finish(state, witness, observer, accepted)
    assert len(state.calls) == 2
    assert result["passed"] is False
    assert result["actual_request_rows"][0]["review_calls"] == 2
    assert result["rows"][0]["checks"]["one_completed_review"] is False


def test_late_retained_wrapper_call_is_forwarded_and_explicitly_incomplete(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            held = state.worker._review_raw_hook_native
            accepted = time.monotonic()
            observer.probe(0, 1)
        assert held(**state.request_kwargs) is state.edge
        result = finish(state, witness, observer, accepted)
    assert len(state.calls) == 2
    assert result["passed"] is False
    assert result["actual_request_rows"][0]["review_calls"] == 1
    assert result["observation_lifecycle"]["late_native_calls"] == 1


def test_late_native_call_during_sqlite_readback_invalidates_the_final_join(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    returned, errors = [], []
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            held = state.worker._review_raw_hook_native
            accepted = time.monotonic()
            observer.probe(0, 1)
        witness.reconcile(verify_all=True)

        def block_native_return():
            entered.set()
            assert release.wait(2)

        state.before_return = block_native_return

        def late_call():
            try:
                returned.append(held(**state.request_kwargs))
            except BaseException as error:
                errors.append(error)

        late = threading.Thread(target=late_call)
        read = witness.reader.read

        def read_with_late_native_call(identity):
            stored = read(identity)
            late.start()
            assert entered.wait(1)
            return stored

        monkeypatch.setattr(witness.reader, "read", read_with_late_native_call)
        try:
            result = observer.join(accepted=accepted, snapshot=state.snapshot, action="block", declared_indexes=(0,))
            assert late.is_alive()
            assert result["passed"] is False
            assert result["observation_complete"] is False
            assert result["observation_lifecycle"]["late_native_calls"] == 1
            # The original call has not returned to the older receipt witness.
            assert result["receipt_witness"]["observations"] == {}
        finally:
            release.set()
            late.join(timeout=2)
            assert not late.is_alive()
        assert errors == []
        assert returned == [state.edge]
    assert len(state.calls) == 2


def test_close_preserves_later_wrapper_owner_and_refuses_complete_result(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)

    def later(**_kwargs):
        return None

    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        paired = state.worker._review_raw_hook_native
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            accepted = time.monotonic()
            observer.probe(0, 1)
            state.worker._review_raw_hook_native = later
            observer.close()
            assert state.worker._review_raw_hook_native is later
            result = finish(state, witness, observer, accepted)
            # Cleanup the deliberately installed later owner before the older
            # ReceiptWitness exits; this restoration is not done by our observer.
            state.worker._review_raw_hook_native = paired
    assert result["passed"] is False
    assert result["observation_lifecycle"]["owned_wrapper_restored"] is False
    assert state.worker._review_raw_hook_native is state.original


def test_nested_scope_restores_each_exact_captured_callable(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        paired = state.worker._review_raw_hook_native
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as outer:
            outer_call = state.worker._review_raw_hook_native
            with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as inner:
                accepted = time.monotonic()
                inner.probe(0, 1)
            assert state.worker._review_raw_hook_native is outer_call
            result = finish(state, witness, inner, accepted)
            assert result["passed"] is True
            assert outer._unowned_calls == 1
        assert state.worker._review_raw_hook_native is paired
    assert state.worker._review_raw_hook_native is state.original
    assert len(state.calls) == 1


def test_receipt_witness_must_be_entered_first(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    witness = ReceiptWitness(state.session, maximum=1)
    observer = WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1)
    with pytest.raises(RuntimeError, match="paired receipt witness"):
        observer.__enter__()
    assert state.worker._review_raw_hook_native is state.original
    assert state.calls == []


def test_closed_receipt_witness_cannot_admit_new_request_observation(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    witness = ReceiptWitness(state.session, maximum=1).__enter__()
    witness.close()
    assert witness.report()["journal_instrumentation_installed"] is True
    observer = WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1)
    with pytest.raises(RuntimeError, match="paired receipt witness"):
        observer.__enter__()
    assert state.worker._review_raw_hook_native is state.original
    assert state.calls == []


def test_old_observer_refuses_request_after_actual_worker_replacement(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    replacement = SimpleNamespace(_review_raw_hook_native=state.original)
    with (
        closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness,
        WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer,
    ):
        state.session.daemon._server.hook_worker = replacement
        try:
            with pytest.raises(RuntimeError, match="offer lifecycle"):
                observer.probe(0, 1)
            assert state.http_calls == []
            assert observer._refused_offers == 1
        finally:
            state.session.daemon._server.hook_worker = state.worker
    assert replacement._review_raw_hook_native is state.original


def test_declared_workspace_must_stay_within_owned_canonical_root(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    witness = ReceiptWitness(state.session, maximum=1)
    with pytest.raises(ValueError, match="outside owned canonical root"):
        WorkspaceRequestObserver(state.session, witness, (tmp_path.parent.resolve(),), maximum=1)
    assert state.calls == []


def test_readback_scope_never_wraps_original_native_or_receipt_write(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    depth, scopes = [0], [0]

    @contextmanager
    def readback():
        scopes[0] += 1
        depth[0] += 1
        try:
            yield
        finally:
            depth[0] -= 1

    def before_return():
        assert depth[0] == 0

    def submit(value):
        assert depth[0] == 0
        return state.session.store.record_native_decision_receipt(value)

    state.before_return = before_return
    state.writer.submit_native_decision_receipt = submit
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        # Install this control only after ReceiptWitness entered, so no fake
        # SQLite observer registration or extension lifecycle is exercised.
        witness.sqlite_observer = SimpleNamespace(readback=readback, report=lambda: {"control_scope_only": True})
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            accepted = time.monotonic()
            observer.probe(0, 1)
        assert scopes[0] == 2 and depth[0] == 0
        witness.reconcile(verify_all=True)
        before_join = scopes[0]
        result = observer.join(accepted=accepted, snapshot=state.snapshot, action="block", declared_indexes=(0,))
        assert scopes[0] == before_join + 1 and depth[0] == 0
    assert result["passed"] is True
    assert state.session.store.native_decision_receipt_count() == 1
