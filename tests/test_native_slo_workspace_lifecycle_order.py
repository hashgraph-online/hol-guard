"""Caller ordering controls; native authority and HTTP are explicit test doubles."""

from __future__ import annotations

import copy
from types import SimpleNamespace
from typing import Any, cast

import pytest

from scripts import native_slo_workspace_lifecycle as lifecycle
from scripts.native_slo_workspace_lifecycle_clocks import LifecycleClocks


@pytest.fixture
def controlled_cell(tmp_path, monkeypatch):
    home, workspace = tmp_path / ".hol-guard", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    now = [10.0]
    calls = []
    state = SimpleNamespace(constructor_seconds=0.05, start_seconds=2.0, start_failure=None, invalidate=None)
    snapshot: dict[str, Any] = {
        "generation": 7,
        "policy_digest": "a" * 64,
        "runtime_identity": "b" * 64,
        "mode": "enforce",
        "effective_policy": {"default_action": "allow", "subprocess_action": "allow", "sandbox_analysis": "strict"},
    }

    class Publisher:
        closed = False
        _thread = None

        def __init__(self, value: dict[str, Any]):
            self.snapshot: dict[str, Any] | None = value

        def current_snapshot(self):
            return copy.deepcopy(self.snapshot)

        def request_publish(self):
            pass

        def close(self):
            self.closed = True

    def worker(publisher):
        def prepare(_workspace, *, deadline):
            calls.append(("prepare", now[0], deadline))
            return publisher.current_snapshot()

        return SimpleNamespace(policy_snapshot_publisher=publisher, prepare_workspace_policy=prepare)

    publisher = Publisher(snapshot)
    session = SimpleNamespace(
        root=tmp_path,
        guard_home=home,
        store=object(),
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker(publisher))),
    )

    def readback(_store):
        value = session.daemon._server.hook_worker.policy_snapshot_publisher.current_snapshot()
        return value, value

    def replace(_session, _workspaces, *, prepare, clocks):
        value = copy.deepcopy(snapshot)
        value["generation"] = 8
        cold = Publisher(value)
        prepare(cold)
        now[0] += state.constructor_seconds

        def start():
            calls.append(("start", now[0]))
            now[0] += state.start_seconds
            if state.start_failure is not None:
                raise state.start_failure
            if state.invalidate == "withdrawn":
                cold.snapshot = None
            elif state.invalidate == "changed":
                assert cold.snapshot is not None
                cold.snapshot["generation"] += 1
            calls.append(("started", now[0]))

        session.daemon = SimpleNamespace(_server=SimpleNamespace(hook_worker=worker(cold)), start=start)
        return {"service_instances": 2, "python_process_restarted": False}

    class Observer:
        started = now[0]

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def rows(self, *_args):
            return []

        def report(self):
            return {"complete": True}

        def close(self):
            pass

        def freeze(self):
            pass

    class Witness:
        def __enter__(self):
            return self

        def close(self):
            pass

        def reconcile(self, **_kwargs):
            pass

        def report(self):
            return {"native_receipts": 0, "committed": 0}

    def witness_factory(*_args, **kwargs):
        state.witness_origin = kwargs.get("monotonic_origin")
        state.witness_constructed = now[0]
        return Witness()

    class Requests(Observer):
        def probe(self, *_args):
            calls.append(("probe", now[0]))

        def join(self, *, accepted, **_kwargs):
            return {"passed": True, "accepted_to_offer_ms": (now[0] - accepted) * 1000}

    monkeypatch.setattr(lifecycle, "time", SimpleNamespace(monotonic=lambda: now[0], sleep=lambda _: None))
    monkeypatch.setattr(lifecycle, "LifecycleClocks", lambda: LifecycleClocks(lambda: now[0]))
    monkeypatch.setattr(lifecycle, "_overlay", lambda _: None)
    monkeypatch.setattr(lifecycle, "_authenticated_readback", readback)
    monkeypatch.setattr(
        lifecycle, "_readback_matches", lambda binding, accepted, expected: binding == accepted == expected
    )
    monkeypatch.setattr(lifecycle, "replace_service", replace)
    monkeypatch.setattr(lifecycle, "register_scopes", lambda *_: None)
    monkeypatch.setattr(lifecycle, "PublicationObserver", lambda *_: Observer())
    monkeypatch.setattr(lifecycle, "ReceiptWitness", witness_factory)
    monkeypatch.setattr(lifecycle, "WorkspaceRequestObserver", lambda *_args, **_kwargs: Requests())
    monkeypatch.setattr(lifecycle, "phase_chain", lambda *_args, **_kwargs: {"matched": True})
    monkeypatch.setattr(lifecycle, "_scope_checks", lambda *_: {"controlled_scope": True})
    monkeypatch.setattr(lifecycle, "_drain", lambda _: True)
    return session, workspace, state, calls


def test_cold_ack_is_observed_before_unrelated_full_start_without_resetting_deadline(controlled_cell):
    session, workspace, state, calls = controlled_cell
    result = cast(dict[str, Any], lifecycle.run_lifecycle_cell(session, (workspace,), "service_restart"))
    assert result["passed"] is True, result.get("failure")
    clocks = result["lifecycle_clocks"]["boundaries_ms"]
    assert result["readiness_deadline_ms"] == 400
    assert result["accepted_ms"] == 0
    assert result["accept_to_ack_ms"] == pytest.approx(50)
    assert clocks["recovered_ack_return"] <= 400
    assert clocks["daemon_start_return"] - clocks["daemon_start_enter"] == pytest.approx(2000)
    assert clocks["recovered_ack_return"] <= clocks["daemon_start_enter"]
    assert result["requests"]["accepted_to_offer_ms"] == pytest.approx(2050)
    assert [call[0] for call in calls] == ["prepare", "prepare", "start", "started", "probe"]
    assert calls[1][2] == pytest.approx(10.4)
    assert state.witness_origin == 10.0
    assert state.witness_constructed == pytest.approx(10.05)


@pytest.mark.parametrize("invalidated", ["withdrawn", "changed"])
def test_full_start_authority_change_prevents_owned_probe(controlled_cell, invalidated):
    session, workspace, state, calls = controlled_cell
    state.invalidate = invalidated
    result = cast(dict[str, Any], lifecycle.run_lifecycle_cell(session, (workspace,), "service_restart"))
    assert result["passed"] is False
    assert result["binding"]["generation"] == 8
    assert result["lifecycle_clocks"]["boundaries_ms"]["recovered_ack_return"] <= 400
    assert "daemon_start_return" in result["lifecycle_clocks"]["boundaries_ms"]
    assert not any(call[0] == "probe" for call in calls)


def test_full_start_failure_still_fails_after_a_timely_native_ack(controlled_cell):
    from scripts.native_slo_failure import failure_evidence

    session, workspace, state, calls = controlled_cell
    state.start_failure = ValueError("controlled full startup failure")
    result = cast(dict[str, Any], lifecycle.run_lifecycle_cell(session, (workspace,), "service_restart"))
    assert result["passed"] is False
    assert result["failure"] == failure_evidence(state.start_failure)
    assert result["binding"]["generation"] == 8
    assert "daemon_start_return" not in result["lifecycle_clocks"]["boundaries_ms"]
    assert not any(call[0] == "probe" for call in calls)


def test_constructor_that_exhausts_original_native_deadline_still_fails(controlled_cell):
    session, workspace, state, calls = controlled_cell
    state.constructor_seconds = 0.5
    result = cast(dict[str, Any], lifecycle.run_lifecycle_cell(session, (workspace,), "service_restart"))
    assert result["passed"] is False
    assert result["readiness_deadline_ms"] == 400
    assert result["accepted_ms"] == 0
    assert "recovered_ack_return" not in result["lifecycle_clocks"]["boundaries_ms"]
    assert not any(call[0] in {"start", "probe"} for call in calls)


@pytest.mark.parametrize("withdrawal", ["explicit_mutation", "metadata_reconciliation"])
def test_ack_withdrawn_during_readback_cannot_escape_real_publisher_barrier(tmp_path, monkeypatch, withdrawal):
    from codex_plugin_scanner.guard.native_policy_snapshot_codec import _digest_v3
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
    from codex_plugin_scanner.guard.store import GuardStore

    # Exercise the real barrier and metadata invalidation. The ACK and MAC
    # readback below are controlled inputs, not native publication evidence.
    store = GuardStore(tmp_path / "guard")
    publisher = NativePolicySnapshotPublisher(store=store, wall_clock=lambda: 100.0)
    policy = {"default_action": "allow", "subprocess_action": "allow", "sandbox_analysis": "strict"}
    config = dict(policy, mode="enforce")
    snapshot: dict[str, object] = {
        "generation": 7,
        "policy_digest": "a" * 64,
        "runtime_identity": "b" * 64,
        "mode": "enforce",
        "effective_policy": policy,
        "expires_at_ms": 160_000,
    }
    publisher._snapshot = snapshot
    publisher._acked = True
    publisher._epoch = 9
    publisher._published_policy_fingerprint = (_digest_v3(policy), "enforce", _digest_v3({}))
    monkeypatch.setattr(publisher, "_compiled_effective_policy", lambda: config)
    monkeypatch.setattr(publisher, "_compiled_command_extensions", lambda: {})
    worker = SimpleNamespace(
        policy_snapshot_publisher=publisher,
        prepare_workspace_policy=lambda *_args, **_kwargs: publisher.current_snapshot_binding(),
    )
    session = SimpleNamespace(store=store, daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)))
    now = [10.0]
    monkeypatch.setattr(
        lifecycle,
        "time",
        SimpleNamespace(monotonic=lambda: now[0], sleep=lambda _: now.__setitem__(0, 10.5)),
    )
    readbacks = []

    def readback(_store):
        accepted = publisher.current_snapshot()
        binding = publisher.current_snapshot_binding()
        assert accepted == snapshot and binding is not None
        if withdrawal == "explicit_mutation":
            publisher.request_publish()
        else:
            assert publisher._policy_input_changed({str(tmp_path / "workspace" / ".hol-guard.toml")}) is True
            assert publisher._observed_policy_fingerprint == publisher._published_policy_fingerprint
            assert publisher._epoch == 9 and publisher.last_error is None
        assert publisher.current_snapshot() is None
        readbacks.append(accepted)
        return binding, accepted

    monkeypatch.setattr(lifecycle, "_authenticated_readback", readback)
    monkeypatch.setattr(lifecycle, "_readback_matches", lambda _binding, accepted, expected: accepted == expected)
    try:
        with pytest.raises(RuntimeError, match="authenticated acknowledgment deadline"):
            lifecycle.await_ack(session, minimum=7, action="allow", strict=True, workspace=tmp_path, deadline=10.4)
        assert readbacks == [snapshot]
        assert publisher.current_snapshot() is None
    finally:
        publisher.close()
