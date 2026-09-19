"""Would-enforce evidence remains distinct from the actual native decision."""

from __future__ import annotations

import hashlib

import pytest

from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from codex_plugin_scanner.guard.native_hook_edge import _decode_edge
from tests.test_native_scoped_result import _bound_result


@pytest.mark.parametrize("action", ["allow", "warn", "review", "require-reapproval", "sandbox-required", "block"])
def test_observe_action_is_retained_without_reinterpreting_the_native_decision(action: str) -> None:
    edge, binding = _bound_result(observe=True)
    original_decision = dict(edge["result"])
    edge["observed_policy_action"] = action
    edge["receipt"]["observed_policy_action"] = action
    edge["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(edge["receipt"])).hexdigest()
    assert _decode_edge(edge, snapshot_binding=binding) == edge
    assert edge["result"] == original_decision


def test_recomputed_receipt_cannot_disagree_with_the_observed_edge_action() -> None:
    edge, binding = _bound_result(observe=True)
    edge["receipt"]["observed_policy_action"] = "block"
    edge["observed_policy_action"] = "review"
    edge["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(edge["receipt"])).hexdigest()
    assert _decode_edge(edge, snapshot_binding=binding) is None


@pytest.mark.parametrize("action", [None, True, "unknown", {"policy_action": "block"}])
def test_observe_mode_requires_one_explicit_typed_would_enforce_action(action: object) -> None:
    edge, binding = _bound_result(observe=True)
    edge["observed_policy_action"] = action
    assert _decode_edge(edge, snapshot_binding=binding) is None


def test_enforcement_mode_never_claims_an_observed_only_action() -> None:
    edge, binding = _bound_result()
    edge["observed_policy_action"] = "review"
    edge["receipt"]["observed_policy_action"] = "review"
    edge["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(edge["receipt"])).hexdigest()
    assert _decode_edge(edge, snapshot_binding=binding) is None
