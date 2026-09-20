from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.native_policy_decision_context import (
    NativePolicyDecisionContext,
    capture_native_policy_decision,
    safe_native_policy_decision,
)
from codex_plugin_scanner.guard.policy_publication_binding import PolicyPublicationBinding
from codex_plugin_scanner.guard.policy_rule_identity import PolicyRuleIdentity
from tests.test_native_decision_receipt import _receipt
from tests.test_native_policy_snapshot_v4_barrier import _result_binding
from tests.test_native_policy_snapshot_v4_barrier import barrier as _barrier_fixture


@pytest.fixture(name="barrier")
def native_barrier(tmp_path, monkeypatch):
    yield from cast(Any, _barrier_fixture).__wrapped__(tmp_path, monkeypatch)


def _captured(*, observe=False):
    receipt = _receipt(
        event_name="PreToolUse",
        decision="allow",
        policy_action="allow",
        observe_mode=observe,
        observed_policy_action="block" if observe else None,
    )
    binding = {
        "policy_generation": receipt["policy_generation"],
        "policy_digest": receipt["policy_digest"],
        "runtime_identity": receipt["runtime_identity"],
        "source_input_digest": "e" * 64,
        "resident_generation": 9,
        "selected_decision_id": 7,
    }
    identity = PolicyRuleIdentity(
        "synthetic-policy",
        "synthetic-rule",
        "7",
        PolicyPublicationBinding(11, "sha256:" + "f" * 64, "synthetic-installation"),
    )
    context = capture_native_policy_decision(binding=binding, receipt=receipt, identity=identity)
    assert context is not None
    return receipt, context


@pytest.mark.parametrize("observe", [False, True])
def test_native_context_preserves_actual_outcome_and_original_time_without_mutating_receipt(observe):
    receipt, context = _captured(observe=observe)
    original = copy.deepcopy(receipt)
    encoded = context.to_dict()
    restored = NativePolicyDecisionContext.from_mapping(encoded)
    assert restored is not None
    assert restored == context and restored.matches_receipt(receipt)
    assert restored.recorded_at == context.recorded_at
    assert encoded["policyAction"] == "allow"
    assert encoded["observedPolicyAction"] == ("block" if observe else None)
    assert "policyExecutionOutcome" not in encoded
    assert receipt == original and safe_native_policy_decision(encoded) == encoded
    with pytest.raises(FrozenInstanceError):
        cast(Any, context).policy_generation = 99


@pytest.mark.parametrize(
    "field,value",
    [
        ("nativeDecisionId", "a" * 64),
        ("policyAction", "block"),
        ("observeMode", True),
        ("decision", "deny"),
        ("harness", "cursor"),
    ],
)
def test_context_cannot_be_attached_to_another_native_receipt(field, value):
    receipt, context = _captured()
    payload = context.to_dict()
    payload[field] = value
    changed = NativePolicyDecisionContext.from_mapping(payload)
    assert changed is None or not changed.matches_receipt(receipt)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(command="synthetic secret"),
        lambda value: value.update(policyVersion="01"),
        lambda value: value.update(policyVersion="9007199254740992"),
        lambda value: value.update(recordedAt="2026-09-17T00:00:00"),
        lambda value: value.update(observeMode=1),
        lambda value: value.update(
            observeMode=True, decision="deny", policyAction="block", observedPolicyAction="block"
        ),
        lambda value: value["snapshot"].update(source_input_digest="A" * 64),
        lambda value: value["snapshot"].update(policy_generation=True),
        lambda value: value["snapshot"].update(selected_decision_id=None),
        lambda value: value["snapshot"].update(command="synthetic secret"),
        lambda value: value["publication"].update(bundleVersion=True),
        lambda value: value["publication"].update(bundleVersion=9007199254740992),
        lambda value: value["publication"].update(command="synthetic secret"),
    ],
)
def test_context_decoder_refuses_unknown_fields_and_ambiguous_identity(mutation):
    _, context = _captured()
    payload = context.to_dict()
    mutation(payload)
    assert NativePolicyDecisionContext.from_mapping(payload) is None


def test_publisher_captures_from_frozen_source_and_refuses_changed_epoch(barrier):
    publisher, state = barrier
    publisher._publish_once()
    binding = _result_binding(publisher)
    receipt = _receipt(
        event_name="PreToolUse",
        policy_generation=binding["policy_generation"],
        policy_digest=binding["policy_digest"],
        runtime_identity=binding["runtime_identity"],
    )
    accepted, context = publisher.capture_policy_decision_context(binding, receipt)
    assert accepted and context is not None
    assert context.identity.policy_id == "synthetic-policy"
    assert context.identity.policy_version == "7"
    state.inputs = None  # Mutable source must never be read after the accepted snapshot capture.
    assert publisher.capture_policy_decision_context(binding, receipt)[0]
    publisher.request_publish()
    assert publisher.capture_policy_decision_context(binding, receipt) == (False, None)
    assert context.matches_receipt(receipt)


def test_unselected_native_default_does_not_invent_canonical_identity(barrier):
    publisher, _ = barrier
    publisher._publish_once()
    assert publisher.capture_policy_decision_context(_result_binding(publisher, None), _receipt()) == (True, None)


@pytest.mark.parametrize("changed_epoch", [False, True])
def test_actual_worker_captures_frozen_identity_under_same_barrier(barrier, tmp_path, monkeypatch, changed_epoch):
    from types import MethodType, SimpleNamespace

    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
    from tests.test_native_scoped_result import _bound_result

    publisher, _ = barrier
    publisher._publish_once()
    binding = _result_binding(publisher)
    edge, _ = _bound_result()
    edge["policy_binding"] = binding
    edge["receipt"] = _receipt(
        event_name="PreToolUse",
        policy_generation=binding["policy_generation"],
        policy_digest=binding["policy_digest"],
        runtime_identity=binding["runtime_identity"],
    )
    receipts = []
    original_check = publisher.result_binding_is_current

    def check_then_change(value):
        result = original_check(value)
        if changed_epoch:
            publisher.request_publish()
        return result

    monkeypatch.setattr(publisher, "result_binding_is_current", check_then_change)
    host: Any = SimpleNamespace(
        policy_snapshot_publisher=publisher,
        _native_policy_snapshot=lambda *args, **kwargs: publisher.current_snapshot_binding(),
        _review_raw_hook_native=lambda **kwargs: edge,
        _record_native_decision_receipt=lambda receipt: receipts.append(receipt) or receipt,
        metrics=SimpleNamespace(record_route=lambda value: None),
        activity_writer=None,
    )
    host._review_native_edge_with_snapshot = MethodType(HookWorker._review_native_edge_with_snapshot, host)
    result: dict[str, Any] = HookWorker._review_native_edge(
        host,
        payload={"tool_name": "Bash", "tool_input": {"command": "printf safe"}},
        harness="claude-code",
        event_name="PreToolUse",
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        deadline=None,
    )
    assert result["hookSpecificOutput"]["permissionDecision"] == ("deny" if changed_epoch else "allow")
    if changed_epoch:
        assert not receipts and host._last_native_policy_context is None
    else:
        assert receipts == [edge["receipt"]]
        assert host._last_native_policy_context.identity.policy_id == "synthetic-policy"
        assert host._last_native_policy_context.matches_receipt(edge["receipt"])


def test_scoped_context_capture_requires_a_real_capture_barrier():
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.daemon.hook_native_policy_context import capture_result_context

    receipt, context = _captured()
    assert capture_result_context(SimpleNamespace(), {"policy_binding": context.binding(), "receipt": receipt}) == (
        False,
        None,
    )


@pytest.mark.parametrize(
    "result", [None, True, (True,), [True, None], (1, None), (True, object()), (True, None, "extra")]
)
def test_scoped_context_capture_refuses_ambiguous_capture_results(result):
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.daemon.hook_native_policy_context import capture_result_context

    receipt, context = _captured()
    publisher = SimpleNamespace(capture_policy_decision_context=lambda *_args: result)
    assert capture_result_context(publisher, {"policy_binding": context.binding(), "receipt": receipt}) == (False, None)
