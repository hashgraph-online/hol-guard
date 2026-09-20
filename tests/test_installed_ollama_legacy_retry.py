"""Exact retry wiring and the real coordinator's conservative Ollama boundary."""

from __future__ import annotations

import copy
from collections import Counter
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateError, update_settings
from codex_plugin_scanner.guard.daemon.hook_native_review_binding import NATIVE_REVIEW_BINDING_FIELD
from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt
from codex_plugin_scanner.guard.native_hook_edge import _decode_edge
from codex_plugin_scanner.guard.runtime.command_activity_contract import CorrelationKind
from codex_plugin_scanner.guard.runtime.command_activity_privacy import StrongHarnessIdentifier
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError
from codex_plugin_scanner.guard.store import GuardStore
from scripts.ci import installed_native_ollama_probe as probe
from scripts.ci.native_ollama_contract import (
    ACTIVE_CASES,
    LEGACY_RETRY_SCOPE,
    payload_digest,
    require_same_ack,
    review_payload,
    validate_legacy_retry,
)
from scripts.native_slo_contract import assert_privacy_safe

from .test_native_noncommand_review_binding import _binding, _pause
from .test_native_noncommand_review_rust import rust_cases as rust_cases


def _record():
    return {
        "hook_envelope_digest": "a" * 64,
        "request_digest": "b" * 64,
        "policy_generation": 1,
        "policy_digest": "c" * 64,
        "control_revision": 1,
        "observations_digest": "d" * 64,
        "legacy_approval_reused": False,
        "approval_durable": True,
        "action": "review",
    }


def _rows():
    return {
        "prior": {"status": "resolved", "resolution_action": "allow"},
        "next": {"status": "pending", "harness": "claude-code"},
    }


@pytest.mark.parametrize(
    "field", ["hook_envelope_digest", "request_digest", "policy_generation", "policy_digest", "control_revision"]
)
def test_retry_evidence_rejects_changed_request_or_authority(field):
    first, retry = _record(), _record()
    retry[field] = 2 if isinstance(retry[field], int) else "e" * 64
    with pytest.raises(AssertionError, match="legacy_retry_request_or_authority_changed"):
        validate_legacy_retry(SimpleNamespace(get_approval_request=_rows().get), "prior", "next", first, retry)


@pytest.mark.parametrize(
    "mutation", ["same_id", "missing_row", "resolved_row", "old_pending", "allow", "reuse", "null"]
)
def test_retry_cannot_claim_success_without_new_durable_review(mutation):
    rows, first, retry = _rows(), _record(), _record()
    next_id = "next"
    if mutation == "same_id":
        next_id = "prior"
    elif mutation == "missing_row":
        del rows["next"]
    elif mutation == "resolved_row":
        rows["next"]["status"] = "resolved"
    elif mutation == "old_pending":
        rows["prior"]["status"] = "pending"
    elif mutation == "allow":
        retry["action"] = "allow"
    elif mutation == "reuse":
        retry["legacy_approval_reused"] = True
    else:
        first["request_digest"] = retry["request_digest"] = None
    with pytest.raises(AssertionError, match="installed_ollama_"):
        validate_legacy_retry(SimpleNamespace(get_approval_request=rows.get), "prior", next_id, first, retry)


@pytest.mark.parametrize("field", ["generation", "policy_digest", "runtime_identity", "command_extensions"])
def test_retry_requires_the_same_complete_ack(field):
    before = {
        "generation": 1,
        "policy_digest": "a" * 64,
        "runtime_identity": "b" * 64,
        "command_extensions": {"revision": 1},
    }
    require_same_ack(before, copy.deepcopy(before))
    changed = copy.deepcopy(before)
    changed[field] = None
    with pytest.raises(AssertionError, match="legacy_retry_ack_changed"):
        require_same_ack(before, changed)
    del changed[field]
    with pytest.raises(AssertionError, match="legacy_retry_ack_changed"):
        require_same_ack(before, changed)


def test_report_retains_exact_retry_digests_and_scope():
    record = _record()
    record.update(
        validate_legacy_retry(SimpleNamespace(get_approval_request=_rows().get), "prior", "next", record, record)
    )
    assert assert_privacy_safe({"native": {"cases": [record]}})["native"]["cases"][0] == record


def test_all_installed_phases_keep_strong_ids_and_retry_identical_envelope(tmp_path, monkeypatch):
    """Modeled transport verifies fixture sequencing, not native qualification."""
    rows, calls = {}, []

    class Session:
        def __init__(self, *_args, **_kwargs):
            self.workspace = tmp_path / "workspace"
            self.store = SimpleNamespace(get_approval_request=rows.get)
            self.daemon = SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(test_oracle=None)))

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    current_revision = 0

    def commit(_store, _password, _layer, *, revision):
        nonlocal current_revision
        if revision != current_revision:
            raise ExtensionControlAuthorityError("stale revision")
        current_revision += 1
        return current_revision

    def snapshot(_session, revision, *, phase):
        return {
            "generation": revision + 1,
            "policy_digest": str(revision) * 64,
            "runtime_identity": "f" * 64,
            "command_extensions": {"revision": revision},
        }

    def review(session, phase, case, ack, *, request_payload):
        calls.append((phase, case.name, request_payload, copy.deepcopy(request_payload), copy.deepcopy(ack)))
        record = _record() | {
            "phase": phase,
            "case": case.name,
            "action": case.action,
            "hook_envelope_digest": payload_digest(request_payload),
            "policy_generation": ack["generation"],
            "policy_digest": ack["policy_digest"],
            "control_revision": ack["command_extensions"]["revision"],
        }
        approval_id = f"review-{len(calls)}" if case.action == "review" else None
        if approval_id is not None:
            rows[approval_id] = {"status": "pending", "harness": "claude-code"}
        return record, approval_id

    def approve(_store, _password, approval_id):
        rows[approval_id].update(status="resolved", resolution_action="allow")

    monkeypatch.setattr(probe, "AdapterSession", Session)
    monkeypatch.setattr(probe, "artifact_identity", lambda _expected: (tmp_path / "runtime", {"build_sha": "a" * 40}))
    monkeypatch.setattr(probe, "prepare_fixture_authority", lambda _store: "modeled-password")
    monkeypatch.setattr(probe, "commit_controls", commit)
    monkeypatch.setattr(probe, "ready_binding", snapshot)
    monkeypatch.setattr(probe, "review_case", review)
    monkeypatch.setattr(probe, "approve_review", approve)
    report = probe.run_probe({})
    assert report["passed"] is True, report
    assert Counter(call[0] for call in calls) == {
        "initial": 2,
        "enabled": 7,
        "approved_retry": 1,
        "disabled": 2,
        "updated": 2,
        "settings_rollback": 7,
        "stale_write_rejected": 1,
    }
    original, retry = calls[2], calls[3]
    assert original[0:2] == ("enabled", "push") and retry[0:2] == ("approved_retry", "push")
    assert original[2] is retry[2]
    assert original[3:] == retry[3:]
    identifiers = [call[2]["tool_use_id"] for call in calls]
    assert len(set(identifiers)) == len(calls) - 1
    for identifier in identifiers:
        StrongHarnessIdentifier(harness="claude-code", kind=CorrelationKind.REQUEST, value=identifier)
    assert report["native_approval_consume_qualified"] is False
    assert report["approval_retry_scope"] == LEGACY_RETRY_SCOPE
    assert report["cases"][3]["same_hook_envelope"] is True
    assert report["cases"][3]["same_native_request_and_policy"] is True
    assert report["cases"][3]["distinct_pending_review"] is True
    assert report["cases"][3]["hook_envelope_digest"] == report["cases"][2]["hook_envelope_digest"]


def test_actual_signed_ollama_review_cannot_reuse_resolved_legacy_approval(tmp_path, rust_cases):
    """Consume unmodified Rust producer evidence; this is not an installed run."""
    case = copy.deepcopy(rust_cases["ollama"])
    original = copy.deepcopy(case)
    edge, receipt = case["edge"], case["edge"]["receipt"]
    assert edge["harness"] == "cursor"
    assert _decode_edge(edge) == edge
    assert validate_native_decision_receipt(receipt) == receipt
    assert case["payload"]["tool_input"]["command"] == ACTIVE_CASES[0].command
    observations = edge["result"]["command_extensions"]
    assert observations["binding"]["uncertainty_count"] == 0
    assert [item["rule_id"] for item in observations["observations"]] == ["command.ollama.push"]
    assert "review_scope" not in receipt
    store = GuardStore(tmp_path / "guard-home")
    password = "synthetic-ollama-approval-password"
    update_settings(
        store.guard_home,
        {"enabled": True, "new_password": password, "confirm_password": password, "cooldown_seconds": 0},
    )
    first = _pause(store, case)
    assert first["policy_action"] == "review" and "approval_reuse_status" not in first
    prior_id = first["approval_request_id"]
    with pytest.raises(ApprovalGateError):
        probe.approve_review(store, "wrong-synthetic-password", prior_id)
    assert store.get_approval_request(prior_id)["status"] == "pending"
    probe.approve_review(store, password, prior_id)
    prior = copy.deepcopy(store.get_approval_request(prior_id))
    assert prior["status"] == "resolved" and prior["resolution_action"] == "allow"
    retry = _pause(store, case)
    assert retry["policy_action"] == "review", retry
    assert retry["reason_code"] == "native_command_review_required"
    assert "approval_reuse_status" not in retry
    assert retry["approval_request_id"] != prior_id
    pending = store.get_approval_request(retry["approval_request_id"])
    assert pending["status"] == "pending" and pending["harness"] == "cursor"
    assert prior["action_envelope_json"][NATIVE_REVIEW_BINDING_FIELD] == _binding(case)
    assert pending["action_envelope_json"][NATIVE_REVIEW_BINDING_FIELD] == _binding(case)
    assert store.get_approval_request(prior_id) == prior
    assert case == original, "the retry must retain the original native payload, receipt and current ACK"
    assert store.record_native_decision_receipt(receipt)
    assert store.get_native_decision_receipt(receipt["decision_id"]) == receipt


def test_case_id_is_a_diagnostic_label_not_native_request_identity(tmp_path):
    payload = review_payload(tmp_path, ACTIVE_CASES[0])
    assert payload["tool_use_id"] != ACTIVE_CASES[0].name
    assert payload["tool_input"] == {"command": ACTIVE_CASES[0].command}
    assert "phase" not in payload
