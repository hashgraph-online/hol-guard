from __future__ import annotations

import copy
import json
import time
from contextlib import closing

import pytest

from scripts.native_slo_mixed_witness import ReceiptWitness
from scripts.native_slo_workspace_request_observer import WorkspaceRequestObserver
from tests.native_workspace_request_fixtures import control, finish


def test_secondary_request_preserves_original_calls_and_joins_real_sqlite_receipt(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        paired = state.worker._review_raw_hook_native
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            accepted = time.monotonic()
            response = observer.probe(0, 1)
            assert response is state.response
            assert state.last_http_edge is state.edge
        assert state.worker._review_raw_hook_native is paired
        result = finish(state, witness, observer, accepted)
    assert state.worker._review_raw_hook_native is state.original
    assert result["passed"] is True
    assert result["qualification_complete"] is False
    assert result["clock_sources"] == {"monotonic": "time.monotonic", "wall": "time.time"}
    assert len(state.calls) == len(state.http_calls) == 1
    assert state.calls[0] == ((), state.request_kwargs)
    assert state.calls[0][1]["payload"] is state.request_kwargs["payload"]
    assert state.http_calls[0][0] is state.session.daemon
    assert state.http_calls[0][1]["workspace"] is state.workspaces[1]
    assert state.http_calls[0][1]["guard_home"] is state.session.guard_home
    assert state.http_calls[0][1]["harness"] == "claude-code"
    assert set(state.http_calls[0][1]) == {"workspace", "guard_home", "harness", "request_payload"}
    assert state.session.store.native_decision_receipt_count() == 1
    captured = result["actual_request_rows"][0]
    assert captured["native_receipt"] == state.session.store.get_native_decision_receipt(
        state.edge["receipt"]["decision_id"]
    )
    assert captured["committed_row_count_before"] == captured["committed_row_count_after"] == 1
    assert captured["native_finished_ms"] <= captured["review_returned_ms"] <= captured["delivered_ms"]
    assert result["observation_lifecycle"]["owned_wrapper_restored"] is True


@pytest.mark.parametrize("kind", ["ordinary", "base"])
def test_original_native_exception_identity_survives_observation(tmp_path, monkeypatch, kind):
    state = control(tmp_path, monkeypatch)
    failure = ValueError("native control") if kind == "ordinary" else KeyboardInterrupt("native control")
    state.native_error = failure
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            accepted = time.monotonic()
            with pytest.raises(type(failure)) as captured:
                observer.probe(0, 1)
            assert captured.value is failure
        result = finish(state, witness, observer, accepted)
    assert len(state.calls) == len(state.http_calls) == 1
    assert result["passed"] is False
    assert result["actual_request_rows"][0]["review_returned"] is False
    assert result["observation_lifecycle"]["native_calls_currently_in_flight"] == 0


def test_original_http_exception_identity_survives_without_inventing_native_call(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    failure = TimeoutError("original HTTP timeout")
    state.http_error = failure
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            accepted = time.monotonic()
            with pytest.raises(TimeoutError) as captured:
                observer.probe(0, 1)
            assert captured.value is failure
        result = finish(state, witness, observer, accepted)
    assert len(state.http_calls) == 1 and state.calls == []
    assert result["passed"] is False
    assert result["actual_request_rows"][0]["review_calls"] == 0


@pytest.mark.parametrize("fault", ["raise", "nan", "bool"])
def test_diagnostic_clock_fault_cannot_replace_original_result(tmp_path, monkeypatch, fault):
    state = control(tmp_path, monkeypatch)

    def clock():
        if fault == "raise":
            raise KeyboardInterrupt("private clock error")
        return float("nan") if fault == "nan" else True

    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1, clock=clock) as observer:
            accepted = time.monotonic()
            assert observer.probe(0, 1) is state.response
        result = finish(state, witness, observer, accepted)
    assert len(state.calls) == len(state.http_calls) == 1
    assert state.session.store.native_decision_receipt_count() == 1
    assert result["passed"] is False
    assert result["actual_request_rows"][0]["capture_faults"] > 0
    assert result["clock_sources"]["monotonic"] == "injected_control_clock"
    assert "private clock error" not in json.dumps(result)


def test_unknown_native_call_forwards_once_without_entering_declared_set(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            result = state.worker._review_raw_hook_native(payload={"tool_use_id": "external-call"})
            assert result is state.edge
            accepted = time.monotonic()
            observer.probe(0, 1)
        joined = finish(state, witness, observer, accepted)
    assert len(state.calls) == 2
    assert joined["passed"] is True and joined["unowned_native_calls_excluded"] == 1
    assert joined["observed_requests"] == 1
    assert joined["first_scope"] == "only the complete declared request set, not all daemon traffic"


@pytest.mark.parametrize("change", ["delete", "alter"])
def test_real_sqlite_missing_or_changed_receipt_cannot_supply_commit(tmp_path, monkeypatch, change):
    state = control(tmp_path, monkeypatch)
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            accepted = time.monotonic()
            observer.probe(0, 1)
        identity = state.edge["receipt"]["decision_id"]
        with state.session.store._connect() as connection:
            if change == "delete":
                connection.execute("delete from native_hook_decision_receipts where decision_id = ?", (identity,))
            else:
                connection.execute(
                    "update native_hook_decision_receipts set policy_digest = ? where decision_id = ?",
                    ("4" * 64, identity),
                )
        result = finish(state, witness, observer, accepted)
    assert result["passed"] is False
    assert result["actual_request_rows"][0]["committed_receipt"] is None
    assert result["rows"][0]["checks"]["unique_committed_readback"] is False


def test_public_readback_change_cannot_match_previous_request_authority(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    target = copy.deepcopy(state.snapshot)

    def change():
        state.snapshot["generation"] += 1

    state.before_return = change
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            accepted = time.monotonic()
            observer.probe(0, 1)
        result = finish(state, witness, observer, accepted, expected=target)
    assert result["passed"] is False
    assert result["actual_request_rows"][0]["authority_readback_before"] is True
    assert result["actual_request_rows"][0]["authority_readback_after"] is False
    assert result["rows"][0]["checks"]["validated_native_receipt"] is True


def test_join_requires_closed_observer_before_sqlite_readback(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            accepted = time.monotonic()
            observer.probe(0, 1)
            observer.freeze()
            with pytest.raises(RuntimeError, match="close request observation"):
                observer.join(accepted=accepted, snapshot=state.snapshot, action="block", declared_indexes=(0,))
        assert finish(state, witness, observer, accepted)["passed"] is True


@pytest.mark.parametrize("index", [-1, 1, True])
def test_refused_offer_is_counted_and_never_sent_to_http(tmp_path, monkeypatch, index):
    state = control(tmp_path, monkeypatch)
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            accepted = time.monotonic()
            with pytest.raises(ValueError, match="index outside"):
                observer.probe(index, 1)
            assert state.http_calls == []
            observer.probe(0, 1)
        result = finish(state, witness, observer, accepted)
    assert result["passed"] is False
    assert result["observation_lifecycle"]["refused_offers"] == 1
    assert len(state.http_calls) == 1


def test_omitting_a_bad_owned_response_cannot_shrink_the_declared_join(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    denied = copy.deepcopy(state.response)
    with closing(ReceiptWitness(state.session, maximum=2).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=2) as observer:
            accepted = time.monotonic()
            state.response = {
                "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
                "policy_action": "allow",
                "decision": "allow",
                "continue": True,
            }
            observer.probe(0, 0)
            state.response = denied
            observer.probe(1, 1)
        result = finish(state, witness, observer, accepted, indexes=(1,))
    assert len(state.calls) == len(state.http_calls) == state.session.store.native_decision_receipt_count() == 2
    assert result["receipt_witness"]["native_receipts"] == result["receipt_witness"]["committed"] == 2
    assert result["passed"] is False and result["observation_complete"] is False
    assert result["exact_attempts"] is False
    assert result["declared_attempts"] == ["mixed-policy-1"]
    assert result["owned_offered_attempts"] == ["mixed-policy-0", "mixed-policy-1"]
    assert result["undeclared_owned_attempts"] == ["mixed-policy-0"]
    assert result["declared_requests"] == 1 and result["observed_requests"] == 2
    assert result["actual_request_rows"][0]["delivered_decision"] == "allow"
    assert result["rows"][0]["checks"]["delivery_matches"] is False
    assert result["rows"][1]["passed"] is True
