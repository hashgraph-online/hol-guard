"""Deterministic source models for concurrent attempt and route accounting."""

from __future__ import annotations

import threading
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts.native_slo_posture_server import PostureScenarioFixture
from scripts.native_slo_posture_witness import POSTURE_ROUTES, binding_key, posture_case
from tests.test_native_slo_posture import _context, _response


@pytest.mark.parametrize("route", range(len(POSTURE_ROUTES)))
def test_posture_http_request_keeps_case_payload_with_separate_attempt_label(tmp_path, monkeypatch, route):
    from scripts import native_slo_session
    from scripts.native_slo_mixed_request import request_attempt

    worker = SimpleNamespace(policy_snapshot_publisher=SimpleNamespace())
    session = SimpleNamespace(
        root=tmp_path,
        workspace=tmp_path,
        guard_home=tmp_path / "guard-home",
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)),
    )
    fixture = PostureScenarioFixture(session)
    calls = []

    def request(daemon, **kwargs):
        calls.append((daemon, kwargs))
        return {}

    monkeypatch.setattr(native_slo_session, "_request", request)
    fixture._request(route, phase="enforce_to_watch", part="before")
    assert len(calls) == 1 and calls[0][0] is session.daemon
    harness, event = POSTURE_ROUTES[route]
    body = calls[0][1]["request_payload"]
    native_field = "tool_use_id" if harness == "claude-code" else "tool_call_id"
    assert request_attempt(body) == fixture.rows[0]["attempt"] == "mixed-load-0"
    assert isinstance(body[native_field], str) and body[native_field].startswith("fixture-")
    assert {key: value for key, value in body.items() if key not in {native_field, "native_slo_attempt"}} == (
        posture_case(harness, event).payload
    )
    assert calls[0][1]["harness"] == harness
    assert fixture.rows[0]["state"] == "completed"


@pytest.mark.parametrize("fault", ("", "extra_route", "missing_native_observation", "transport_failure"))
def test_actual_threads_conserve_each_modeled_request_and_reject_extra_or_missing_routes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    counters = {"native_resident": 0}
    current = _context()["binding"]
    contexts = {}
    metrics = SimpleNamespace(snapshot=lambda: {"routes": dict(counters)})
    worker = SimpleNamespace(policy_snapshot_publisher=SimpleNamespace(), metrics=metrics)
    session = SimpleNamespace(root=tmp_path, daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)))
    fixture: Any = PostureScenarioFixture(session)
    known = {binding_key(current)}
    counts_lock = threading.Lock()
    first_wave = threading.Barrier(5)
    entered: set[int] = set()

    def apply(_operation, _before, _probe):
        # The overlap is real Python threads; all semantic responses here are
        # declared source models. No HTTP/native installed proof is claimed.
        first_wave.wait(timeout=1.0)
        current.update(generation=2, mode="observe")
        known.add(binding_key(current))
        if fault == "extra_route":
            counters["python_semantic"] = 1
        return dict(current)

    fixture.controls = SimpleNamespace(worker=worker, ack=lambda: dict(current), apply=apply, known=known, progress={})
    fixture.witness = SimpleNamespace(context=lambda attempt: contexts.get(attempt))

    def request(route, *, phase, part, scope="initial", required=None):
        harness, event = POSTURE_ROUTES[route]
        binding = deepcopy(current)
        with fixture.lock:
            attempt = f"mixed-load-{len(fixture.rows)}"
            row = {
                "attempt": attempt,
                "phase": phase,
                "part": part,
                "scope": scope,
                "harness": harness,
                "event": event,
                "state": "offered",
                "required": required,
                "started": time.monotonic(),
            }
            fixture.rows.append(row)
        with counts_lock:
            first = part == "during" and route not in entered
            if first:
                entered.add(route)
        if first:
            first_wave.wait(timeout=1.0)
        time.sleep(0.01 if part == "during" else 0.001)
        context = _context(str(binding["mode"]))
        context["binding"] = binding
        if not (fault == "missing_native_observation" and part == "during"):
            contexts[attempt] = context
        case = posture_case(harness, event, str(binding["mode"]))
        row.update(
            response=_response(case.expected.fields),
            state="failed" if fault == "transport_failure" and part == "during" else "completed",
            finished=time.monotonic(),
        )
        with counts_lock:
            counters["native_resident"] += 1

    monkeypatch.setattr(fixture, "_request", request)
    result = fixture.phase("enforce_to_watch")
    assert result["passed"] is (not fault)
    assert result["overlapping_http_calls"] >= 4
    assert result["unfinished_workers"] == 0
    assert result["attempted"] == len(fixture.rows) == counters["native_resident"]
    assert result["route_conservation"] is (not fault)
    if not fault:
        assert result["validated_request_bindings"] == len(fixture.rows)
        assert result["watch_deliveries"] >= 4 and result["enforce_deliveries"] >= 4
        assert result["native_receipts"] == result["intrinsic_block_receipts"]
    elif fault == "extra_route":
        assert result["other_routes_observed"] == 1
        assert result["semantic_mismatches"] == 0
    else:
        assert result["semantic_mismatches"] > 0


def test_explicit_probe_failure_cannot_set_a_delivered_fault_witness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = SimpleNamespace(policy_snapshot_publisher=SimpleNamespace())
    fixture: Any = PostureScenarioFixture(
        SimpleNamespace(root=tmp_path, daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)))
    )
    fixture.witness = SimpleNamespace(context=lambda _attempt: None)

    def request(route, *, phase, part, scope, required):
        harness, event = POSTURE_ROUTES[route]
        fixture.rows.append(
            {
                "attempt": f"mixed-load-{route}",
                "phase": phase,
                "part": part,
                "scope": scope,
                "harness": harness,
                "event": event,
                "required": required,
                "state": "completed",
                "response": {},
            }
        )

    monkeypatch.setattr(fixture, "_request", request)
    with pytest.raises(RuntimeError, match="probe contract failed"):
        fixture._probes("failed_publication", "held", "initial", "unavailable")
    assert len(fixture.rows) == 4 and all(row["valid"] is False for row in fixture.rows)
