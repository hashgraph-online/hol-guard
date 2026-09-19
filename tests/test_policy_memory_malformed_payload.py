"""Malformed signed memory payloads must reject atomically with durable evidence."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.review_policy_memory_executor import execute_review_policy_memory
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_review_policy_memory_command import _bundle, _resign_bundle, _store

_REGISTRY = "guard_review_memory_registry"
_VERSION = "guard_review_memory_policy_version"
_ACK = "guard_review_memory_last_ack"
_EXISTING_RULE = "review-memory:receipt-1"


def _apply(store: GuardStore, bundle: dict[str, object]) -> dict[str, object]:
    return execute_review_policy_memory(
        {"decisionMemoryBundle": _resign_bundle(bundle)},
        store=store,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def _accepted_store(tmp_path: Path) -> GuardStore:
    store = _store(tmp_path)
    assert _apply(store, _bundle(store))["status"] == "accepted"
    assert len(store.list_policy_decisions()) == 1
    return store


def _candidate(store: GuardStore) -> dict[str, object]:
    bundle = _bundle(store)
    bundle["policyVersion"] = "policy-version-next"
    bundle["bundleVersion"] = "review-memory-receipt-next"
    return bundle


def _assert_rejected_without_mutation(
    store: GuardStore, candidate: dict[str, object], reason: str
) -> None:
    before_registry = deepcopy(store.get_sync_payload(_REGISTRY))
    before_version = deepcopy(store.get_sync_payload(_VERSION))
    before_policies = deepcopy(store.list_policy_decisions())

    result = _apply(store, candidate)

    assert result["status"] == "rejected"
    ack = result["decisionMemoryAck"]
    assert isinstance(ack, dict)
    assert ack["reason"] == reason
    assert ack["appliedRuleCount"] == 0
    assert ack["bundleHash"] == candidate["bundleHash"]
    assert ack["policyVersion"] == candidate["policyVersion"]
    assert store.get_sync_payload(_ACK) == ack
    assert store.get_sync_payload(_REGISTRY) == before_registry
    assert store.get_sync_payload(_VERSION) == before_version
    assert store.list_policy_decisions() == before_policies


@pytest.mark.parametrize("rule_id", [None, "", " ", 123, True])
def test_malformed_memory_rule_id_returns_durable_rejection(tmp_path: Path, rule_id: object) -> None:
    store = _accepted_store(tmp_path)
    candidate = _candidate(store)
    rules = candidate["memoryRules"]
    assert isinstance(rules, list) and isinstance(rules[0], dict)
    rules[0]["ruleId"] = rule_id
    candidate["revocations"] = [_EXISTING_RULE]

    _assert_rejected_without_mutation(store, candidate, "invalid_decision_memory_rule")


def test_missing_memory_rule_id_returns_durable_rejection(tmp_path: Path) -> None:
    store = _accepted_store(tmp_path)
    candidate = _candidate(store)
    rules = candidate["memoryRules"]
    assert isinstance(rules, list) and isinstance(rules[0], dict)
    del rules[0]["ruleId"]
    candidate["revocations"] = [_EXISTING_RULE]

    _assert_rejected_without_mutation(store, candidate, "invalid_decision_memory_rule")


@pytest.mark.parametrize("invalid_id", [None, "", " ", 123, True])
def test_invalid_revocation_rejects_before_revoking_any_rule(tmp_path: Path, invalid_id: object) -> None:
    store = _accepted_store(tmp_path)
    candidate = _candidate(store)
    candidate["memoryRules"] = []
    candidate["revocations"] = [_EXISTING_RULE, invalid_id]

    _assert_rejected_without_mutation(store, candidate, "invalid_decision_memory_revocation")


@pytest.mark.parametrize("revocations", [None, 123, {}, "review-memory:receipt-1"])
def test_non_list_revocations_cannot_advance_memory_version(tmp_path: Path, revocations: object) -> None:
    store = _accepted_store(tmp_path)
    candidate = _candidate(store)
    candidate["revocations"] = revocations

    _assert_rejected_without_mutation(store, candidate, "invalid_decision_memory_revocation")


def test_rejected_revocation_can_be_corrected_at_the_same_policy_version(tmp_path: Path) -> None:
    store = _accepted_store(tmp_path)
    candidate = _candidate(store)
    candidate["memoryRules"] = []
    candidate["revocations"] = [_EXISTING_RULE, 123]
    _assert_rejected_without_mutation(store, candidate, "invalid_decision_memory_revocation")
    candidate["revocations"] = [_EXISTING_RULE]

    result = _apply(store, candidate)

    assert result["status"] == "accepted"
    assert result["decisionMemoryAck"]["appliedRuleCount"] == 0
    assert store.get_sync_payload(_ACK) == result["decisionMemoryAck"]
    assert store.list_policy_decisions() == []
    version = store.get_sync_payload(_VERSION)
    assert isinstance(version, dict)
    assert version["policyVersion"] == candidate["policyVersion"]


def test_omitted_optional_revocations_preserves_rule_only_bundle_compatibility(tmp_path: Path) -> None:
    store = _store(tmp_path)
    candidate = _bundle(store)
    del candidate["revocations"]

    result = _apply(store, candidate)

    assert result["status"] == "accepted"
    assert result["decisionMemoryAck"]["appliedRuleCount"] == 1
    assert len(store.list_policy_decisions()) == 1
