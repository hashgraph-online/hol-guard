"""Signed memory recency remains bound to its authenticated materialization."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.review_memory_authority import REGISTRY_KEY
from tests.test_guard_review_policy_memory_command import _bundle, _resign_bundle, _store


def _fixture(tmp_path: Path):
    store = _store(tmp_path)
    now = datetime.now(timezone.utc)
    first = now.isoformat()
    second = (now + timedelta(seconds=1)).isoformat()
    third = (now + timedelta(seconds=2)).isoformat()
    bundle = _bundle(store, rule_scope="artifact")
    assert store.apply_review_policy_memory_state(bundle, now=first)["status"] == "accepted"
    return store, bundle, first, second, third


def _select(store, now: str, *, consume: bool = False):
    return store.resolve_policy_decision(
        "cursor",
        "plugin:hol/deploy",
        artifact_hash="b" * 64,
        workspace="/workspace/repo",
        now=now,
        consume_one_shot=consume,
    )


@pytest.mark.parametrize("mutate_registry", [False, True])
def test_tampered_memory_recency_cannot_displace_a_newer_authenticated_block(
    tmp_path: Path,
    mutate_registry: bool,
) -> None:
    store, _, _, second, third = _fixture(tmp_path)
    store.upsert_policy(
        PolicyDecision(
            harness="cursor",
            scope="artifact",
            action="block",
            artifact_id="plugin:hol/deploy",
            source="local",
        ),
        second,
    )
    assert {row["source"] for row in store.list_policy_decisions()} == {"local", "cloud-signed-memory"}
    assert _select(store, third)["action"] == "block"
    with store._connect() as connection:
        connection.execute(
            "update policy_decisions set updated_at = ? where source = 'cloud-signed-memory'",
            (third,),
        )
    if mutate_registry:
        registry = store.get_sync_payload(REGISTRY_KEY)
        registry["integrity"]["signed_at"] = third
        store.set_sync_payload(REGISTRY_KEY, registry, third)
    for consume in (False, True):
        assert _select(store, third, consume=consume)["action"] == "block"


def test_memory_timestamp_change_cannot_be_reused_without_a_competing_row(tmp_path: Path) -> None:
    store, _, _, _, third = _fixture(tmp_path)
    before = _select(store, third)
    assert before is not None and before["action"] == "allow"
    assert store.claim_approval_reuse_decision(before, now=third)
    with store._connect() as connection:
        connection.execute(
            "update policy_decisions set updated_at = ? where source = 'cloud-signed-memory'",
            (third,),
        )
    lookup = store.resolve_policy_decision_lookup(
        "cursor",
        "plugin:hol/deploy",
        artifact_hash="b" * 64,
        workspace="/workspace/repo",
        now=third,
        consume_one_shot=False,
    )
    stored = store.list_policy_decisions()[0]
    forged_preview = {**stored, "_approval_authority_revision": lookup["authority_revision"]}
    assert lookup["decision"] is None
    assert not store.claim_approval_reuse_decision(forged_preview, now=third)


def test_duplicate_memory_delivery_preserves_authenticated_recency(tmp_path: Path) -> None:
    store, bundle, first, _, third = _fixture(tmp_path)
    before = store.get_sync_payload(REGISTRY_KEY)
    assert store.apply_review_policy_memory_state(bundle, now=third)["status"] == "accepted"
    assert store.get_sync_payload(REGISTRY_KEY) == before
    selected = _select(store, third)
    assert selected is not None and selected["updated_at"] == first
    assert store.claim_approval_reuse_decision(selected, now=third)


def test_new_signed_memory_publication_rebinds_all_retained_rows(tmp_path: Path) -> None:
    store, _, _, second, third = _fixture(tmp_path)
    next_bundle = _bundle(store, rule_scope="artifact")
    next_bundle["policyVersion"] = "policy-version-next"
    next_bundle["memoryRules"][0].update(ruleId="synthetic.rule.second", artifactId="plugin:hol/second")
    assert store.apply_review_policy_memory_state(_resign_bundle(next_bundle), now=second)["status"] == "accepted"
    registry = store.get_sync_payload(REGISTRY_KEY)
    assert registry["integrity"]["signed_at"] == second
    assert len(store.list_policy_decisions()) == 2
    assert {row["updated_at"] for row in store.list_policy_decisions()} == {second}
    for artifact in ("plugin:hol/deploy", "plugin:hol/second"):
        selected = store.resolve_policy_decision(
            "cursor",
            artifact,
            artifact_hash="b" * 64,
            workspace="/workspace/repo",
            now=third,
            consume_one_shot=False,
        )
        assert selected is not None and selected["action"] == "allow"
        assert store.claim_approval_reuse_decision(selected, now=third)
