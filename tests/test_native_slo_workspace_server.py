from __future__ import annotations

import copy
import threading
from types import SimpleNamespace

import pytest

from scripts import native_slo_workspace_server as server
from scripts.native_slo_workspace_observer import PublicationObserver

BINDING = {"generation": 7, "policy_digest": "a" * 64, "runtime_identity": "b" * 64}


def _authority_fixture(tmp_path, monkeypatch):
    value = server.WorkspaceScenarioFixture.__new__(server.WorkspaceScenarioFixture)
    snapshot = {
        **BINDING,
        "mode": "enforce",
        "effective_policy": {
            "default_action": "block",
            "subprocess_action": "block",
            "sandbox_analysis": "strict",
        },
    }
    calls = []

    def prepare(workspace, *, deadline):
        assert workspace == tmp_path
        calls.append(deadline)
        return BINDING

    value.session = SimpleNamespace(workspace=tmp_path, store=object())
    value.worker = SimpleNamespace(prepare_workspace_policy=prepare)
    value.publisher = SimpleNamespace(current_snapshot=lambda: snapshot)
    monkeypatch.setattr(server, "_authenticated_readback", lambda _store: (BINDING, snapshot))
    monkeypatch.setattr(server, "_readback_matches", lambda *_args: True)
    clock = [10.0]
    monkeypatch.setattr(server.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(server.time, "sleep", lambda _delay: clock.__setitem__(0, 10.5))
    return value, snapshot, calls


def test_ack_keeps_original_deadline_and_requires_complete_current_binding(tmp_path, monkeypatch):
    value, snapshot, calls = _authority_fixture(tmp_path, monkeypatch)
    assert value._ack(previous=7, action="block", strict=True, deadline=10.4) is snapshot
    assert calls == [10.4]


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("generation", 8),
        ("policy_digest", "c" * 64),
        ("runtime_identity", "d" * 64),
        ("mode", "observe"),
        ("effective_policy", {"default_action": "allow", "subprocess_action": "block"}),
    ],
)
def test_changed_or_weaker_authority_cannot_satisfy_ack(tmp_path, monkeypatch, field, replacement):
    value, snapshot, _ = _authority_fixture(tmp_path, monkeypatch)
    snapshot[field] = replacement
    with pytest.raises(RuntimeError, match="deadline"):
        value._ack(previous=7, action="block", strict=True, deadline=10.4)


def test_matching_public_dictionary_without_authenticated_readback_is_insufficient(tmp_path, monkeypatch):
    value, _, _ = _authority_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(server, "_readback_matches", lambda *_args: False)
    with pytest.raises(RuntimeError, match="deadline"):
        value._ack(previous=7, action="block", strict=True, deadline=10.4)


def _completed(tmp_path):
    value = server.WorkspaceScenarioFixture.__new__(server.WorkspaceScenarioFixture)
    observations = {"journal_write_calls": 6, "journal_fsync_calls": 3}
    report = {"native_receipts": 6, "committed": 6, "observations": observations}
    calls = []
    value.witness = SimpleNamespace(
        reconcile=lambda **kwargs: calls.append(kwargs),
        report=lambda: copy.deepcopy(report),
        close=lambda: calls.append("closed"),
    )
    value.observer = PublicationObserver(SimpleNamespace(), (tmp_path,))
    writer = SimpleNamespace(
        _condition=threading.Condition(),
        _in_flight=False,
        stats=lambda: {"queued": 0, "durable_pending": 0, "receipt_durable_pending": 0, "accepted": 6, "processed": 6},
    )
    value.session = SimpleNamespace(
        daemon=SimpleNamespace(_server=SimpleNamespace(runtime_hook_evidence_writer=writer))
    )
    value.failed, value.finished, value.next_phase = False, False, 6
    value.cache_feature_failed = False
    value.workspaces, value.phases = (tmp_path,), [{} for _ in range(6)]
    return value, report, calls


def test_finish_accepts_normal_journal_activity_only_after_exact_receipt_commit_count(tmp_path):
    value, _, calls = _completed(tmp_path)
    result = value.finish()
    assert result["passed"] and result["receipt_count"] == result["committed_receipts"] == 6
    assert calls == [{"verify_all": True}, "closed"]
    assert result["coverage_limits"]["pending"] == [
        "key_rotation",
        "expiry_fault",
        "first_admission_fault",
        "lost_metadata_hint",
    ]


@pytest.mark.parametrize(
    "field,count",
    [("native_receipts", 0), ("committed", 5), ("missing", 1), ("binding_mismatches", 1), ("writer_rejected", 1)],
)
def test_finish_rejects_missing_or_mismatched_real_receipts(tmp_path, field, count):
    value, report, _ = _completed(tmp_path)
    report[field] = count
    assert value.finish()["passed"] is False


@pytest.mark.parametrize(
    "field", ["duplicate_observations", "witness_overflow", "invalid_receipt_identity", "native_without_receipt"]
)
def test_finish_rejects_witness_observation_failures(tmp_path, field):
    value, report, _ = _completed(tmp_path)
    report["observations"][field] = 1
    assert value.finish()["passed"] is False


def test_unvisited_phase_cannot_be_offered_out_of_order(tmp_path):
    value, _, _ = _completed(tmp_path)
    value.next_phase = 0
    with pytest.raises(ValueError, match="order"):
        value.phase("public_policy")
    assert value.next_phase == 0


def test_private_workspace_control_rejects_legacy_profile_on_other_build(tmp_path):
    value, _, _ = _completed(tmp_path)
    value.witness, value.runtime_build_sha = None, "f" * 40
    result = value.dispatch("workspace_start", {"receipt_profile": "baseline_2e672d2"})
    assert result["status"] == "failed" and value.witness is None


@pytest.mark.parametrize("observed_at", [10.4, 10.5])
def test_chain_observed_at_or_after_deadline_is_failed_even_with_actual_matching_spans(
    tmp_path, monkeypatch, observed_at
):
    from scripts import native_slo_workspace_trace

    value, _, _ = _completed(tmp_path)
    monkeypatch.setattr(native_slo_workspace_trace, "phase_chain", lambda *_args, **_kwargs: {"matched": True})
    monkeypatch.setattr(server.time, "monotonic", lambda: observed_at)
    with pytest.raises(RuntimeError, match="deadline"):
        value._chain(0, BINDING, 10.0, 10.4)


def test_cache_feature_failure_does_not_relabel_valid_native_authority(tmp_path):
    value, _, _ = _completed(tmp_path)
    value.cache_feature_failed = True
    result = value.finish()
    assert result["passed"] and result["cache_feature_checks_passed"] is False
