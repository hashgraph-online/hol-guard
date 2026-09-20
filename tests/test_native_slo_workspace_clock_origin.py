"""Real receipt/SQLite joins with controlled native/HTTP authority inputs."""

from __future__ import annotations

import copy
import hashlib
import json
import time
from contextlib import closing
from typing import Any, cast

import pytest

from scripts.native_slo_mixed_witness import ReceiptWitness
from scripts.native_slo_workspace_decision import join_decisions
from scripts.native_slo_workspace_observer import public_binding
from scripts.native_slo_workspace_request_observer import WorkspaceRequestObserver
from tests.native_workspace_request_fixtures import control, finish


def test_original_late_witness_origin_refuses_earlier_acceptance_even_after_receipt_commit(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    accepted = time.monotonic()
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        assert witness.started > accepted
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            observer.probe(0, 1)
        with pytest.raises(ValueError, match="workspace request join outside declared bounds") as failure:
            finish(state, witness, observer, accepted)
        assert hashlib.sha256(str(failure.value).encode()).hexdigest() == (
            "f0402d120d4f1f91da06aedd77eb597a94bdaaae5bfaecf5b2c66c07392e1806"
        )
        assert witness.report()["native_receipts"] == witness.report()["committed"] == 1
    assert (
        state.session.store.get_native_decision_receipt(state.edge["receipt"]["decision_id"]) == state.edge["receipt"]
    )
    assert state.worker._review_raw_hook_native is state.original


@pytest.mark.parametrize("origin_boundary", ["acceptance", "earlier_cell_entry"])
def test_shared_earlier_origin_preserves_real_receipt_join_durations_and_json_roundtrip(
    tmp_path, monkeypatch, origin_boundary
):
    state = control(tmp_path, monkeypatch)
    cell_entry = time.monotonic()
    accepted = time.monotonic()
    origin = accepted if origin_boundary == "acceptance" else cell_entry
    with closing(ReceiptWitness(state.session, maximum=1, monotonic_origin=origin).__enter__()) as witness:
        assert witness.started == origin <= accepted
        with WorkspaceRequestObserver(state.session, witness, state.workspaces, maximum=1) as observer:
            assert observer.started == origin
            response = observer.probe(0, 1)
        result = cast(dict[str, Any], finish(state, witness, observer, accepted))
        witness_row = witness.row("mixed-policy-0")
        assert witness_row is not None
        binding = public_binding(state.snapshot)
        assert binding is not None
        assert witness.first_decision(binding, "block", since=accepted) == witness_row
        assert witness.first_decision(binding, "block", since=time.monotonic() + 1) is None
        assert witness.report()["commit_age_upper_bound_ms"] == pytest.approx(
            witness_row["commit_observed_ms"] - witness_row["native_finished_ms"]
        )
    assert response is state.response
    assert state.worker._review_raw_hook_native is state.original
    assert result["passed"] is True
    assert result["accepted_ms"] == pytest.approx((accepted - origin) * 1000)
    roundtrip = json.loads(json.dumps(result, allow_nan=False))
    assert roundtrip == result
    row = roundtrip["actual_request_rows"][0]
    assert (
        row["native_receipt"]
        == row["committed_receipt"]
        == state.session.store.get_native_decision_receipt(state.edge["receipt"]["decision_id"])
    )
    assert row["workspace_index"] == 1
    # A change of coordinate origin adds one offset to all monotonic stamps.
    # It never changes the acceptance instant, receipt identity or durations.
    shifted = copy.deepcopy(roundtrip["actual_request_rows"])
    for key in (
        "offered_ms",
        "review_entered_ms",
        "native_finished_ms",
        "review_returned_ms",
        "delivered_ms",
        "commit_observed_ms",
    ):
        shifted[0][key] += 1000
    translated = cast(
        dict[str, Any],
        join_decisions(
            shifted,
            authority=roundtrip["authority"],
            action="block",
            accepted_ms=roundtrip["accepted_ms"] + 1000,
            declared_attempts=roundtrip["declared_attempts"],
            observation_complete=roundtrip["observation_complete"],
        ),
    )
    assert translated["passed"] is True
    for key in ("accepted_to_offer_ms", "accepted_to_native_finish_ms"):
        assert translated["rows"][0][key] == pytest.approx(roundtrip["rows"][0][key])
    assert translated["rows"][0]["checks"] == roundtrip["rows"][0]["checks"]
    assert len(state.calls) == len(state.http_calls) == 1


@pytest.mark.parametrize(
    "origin",
    [True, False, -1.0, float("nan"), float("inf"), float("-inf"), "1", 10**1000],
    ids=["true", "false", "negative", "nan", "positive_infinity", "negative_infinity", "string", "huge_integer"],
)
def test_witness_refuses_invalid_origin_before_any_observation(tmp_path, monkeypatch, origin):
    state = control(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="mixed receipt clock origin invalid"):
        ReceiptWitness(state.session, maximum=1, monotonic_origin=origin)
    assert state.worker._review_raw_hook_native is state.original
    assert state.calls == state.http_calls == []


def test_witness_refuses_future_origin_and_default_keeps_construction_boundary(tmp_path, monkeypatch):
    state = control(tmp_path, monkeypatch)
    before = time.monotonic()
    witness = ReceiptWitness(state.session, maximum=1)
    assert before <= witness.started <= time.monotonic()
    with pytest.raises(ValueError, match="mixed receipt clock origin invalid"):
        ReceiptWitness(state.session, maximum=1, monotonic_origin=time.monotonic() + 60)
