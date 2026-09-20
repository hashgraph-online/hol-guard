"""Real signed-source preflight; these tests do not claim resident acceptance."""

import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _hook_action_envelope, _normalize_hook_payload
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import (
    _artifact_id_from_event,
    _hook_runtime_artifact,
)
from codex_plugin_scanner.guard.exact_command import exact_command_sha256, exact_shell_command_from_hook
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from tests.native_scoped_resident_fixtures import ARTIFACT, COMMAND, HARNESS, prepare_store, publish_source, raw_payload


@pytest.mark.parametrize("source", ["canonical", "memory"])
def test_resident_fixture_preserves_authenticated_exact_source_and_review_baseline(tmp_path: Path, source: str):
    store, workspace = prepare_store(tmp_path)
    payload = _normalize_hook_payload(raw_payload(), harness=HARNESS)
    action = _hook_action_envelope(harness=HARNESS, payload=payload, home_dir=tmp_path, workspace=workspace)
    assert (
        _hook_runtime_artifact(
            harness=HARNESS,
            payload=payload,
            action_envelope=action,
            home_dir=tmp_path,
            guard_home=store.guard_home,
            workspace=workspace,
        )
        is None
    )
    assert _artifact_id_from_event(HARNESS, payload) == ARTIFACT
    publisher = NativePolicySnapshotPublisher(store=store)
    try:
        before = read_native_policy_authority_inputs(store, now=time.time())
        assert not before.authority.rows
        harness_actions = publisher._compiled_effective_policy()["harness_actions"]
        assert isinstance(harness_actions, dict) and harness_actions[HARNESS] == "review"
        publish_source(store, source)
        after = read_native_policy_authority_inputs(store, now=time.time())
        assert after.input_digest != before.input_digest
        assert len(after.authority.rows) == 1
        row = after.authority.rows[0]
        assert row.artifact_id == ARTIFACT and row.harness == HARNESS
        assert row.exact_command_sha256 == exact_command_sha256(COMMAND)
        assert row.action.value == "allow" and row.artifact_hash is None
        assert row.source_kind.value == ("signed-bundle" if source == "canonical" else "signed-memory")
        harness_actions = publisher._compiled_effective_policy(cloud_defaults=after.defaults)["harness_actions"]
        assert isinstance(harness_actions, dict) and harness_actions[HARNESS] == "review"
        assert exact_shell_command_from_hook(raw_payload()) == COMMAND
        if source == "canonical":
            assert after.rule_identities[0][0] == row.decision_id
            assert after.rule_identities[0][1].to_dict() == {
                "policyId": "synthetic-policy",
                "ruleId": "synthetic-rule",
                "policyVersion": "8",
            }
        else:
            assert after.rule_identities == ()
    finally:
        publisher.close()


@pytest.mark.parametrize("operation", ["apply", "clear"])
def test_signed_memory_commit_immediately_invalidates_native_publication_epoch(tmp_path: Path, operation: str):
    store, _ = prepare_store(tmp_path)
    if operation == "clear":
        publish_source(store, "memory")
    publisher = NativePolicySnapshotPublisher(store=store)
    try:
        before = publisher._epoch
        if operation == "apply":
            publish_source(store, "memory")
        else:
            store.clear_review_policy_memory_state()
        # No observer loop, manual notification, or elapsed poll interval can
        # conceal a missing notification at the real commit boundary.
        assert publisher._epoch > before
        rows = read_native_policy_authority_inputs(store, now=time.time()).authority.rows
        assert len(rows) == (1 if operation == "apply" else 0)
    finally:
        publisher.close()


def test_memory_duplicate_rejection_and_empty_clear_do_not_invalidate(tmp_path: Path):
    from copy import deepcopy
    from datetime import datetime, timezone

    from codex_plugin_scanner.guard.review_memory_authority import REGISTRY_KEY
    from codex_plugin_scanner.guard.review_oauth_binding import GuardReviewContractError

    store, _ = prepare_store(tmp_path)
    publish_source(store, "memory")
    registry = store.get_sync_payload(REGISTRY_KEY)
    assert isinstance(registry, dict)
    bundle = next(iter(registry["bundles"].values()))
    publisher = NativePolicySnapshotPublisher(store=store)
    try:
        before = publisher._epoch
        now = datetime.now(timezone.utc).isoformat()
        assert store.apply_review_policy_memory_state(bundle, now=now)["status"] == "accepted"
        assert publisher._epoch == before
        invalid = deepcopy(bundle)
        invalid["bundleHash"] = "0" * 64
        with pytest.raises(GuardReviewContractError):
            store.apply_review_policy_memory_state(invalid, now=now)
        assert publisher._epoch == before
        store.clear_review_policy_memory_state()
        after = publisher._epoch
        assert after > before
        store.clear_review_policy_memory_state()
        assert publisher._epoch == after
    finally:
        publisher.close()
