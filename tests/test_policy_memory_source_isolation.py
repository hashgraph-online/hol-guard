"""Memory/bundle ownership isolation and exact signed-target projection."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.runtime.review_policy_memory_executor import execute_review_policy_memory
from tests.test_guard_review_policy_memory_command import _bundle, _resign_bundle, _store


def test_memory_apply_does_not_rewrite_canonical_bundle_rows(tmp_path: Path) -> None:
    store = _store(tmp_path)
    now = "2026-07-16T12:00:00Z"
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="block",
                artifact_id="command:npm-test",
                reason="canonical block",
                owner="rule.block-command",
                source="policy-bundle-canonical",
            )
        ],
        now,
        remote_write_authorized=True,
    )
    execute_review_policy_memory(
        {"decisionMemoryBundle": _bundle(store)},
        store=store,
        generated_at=now,
    )
    after = store.list_policy_decisions()
    still_canonical = next(row for row in after if row["source"] == "policy-bundle-canonical")
    memory_rows = [row for row in after if row["source"] == "cloud-signed-memory"]
    assert still_canonical["artifact_id"] == "command:npm-test"
    assert still_canonical["action"] == "block"
    assert still_canonical["owner"] == "rule.block-command"
    assert len(memory_rows) == 1


def test_bundle_replace_preserves_separately_validated_memory(tmp_path: Path) -> None:
    store = _store(tmp_path)
    now = "2026-07-16T12:00:00Z"
    execute_review_policy_memory(
        {"decisionMemoryBundle": _bundle(store)},
        store=store,
        generated_at=now,
    )
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="block",
                artifact_id="command:npm-test",
                source="policy-bundle",
            )
        ],
        now,
        remote_write_authorized=True,
    )
    sources = {row["source"] for row in store.list_policy_decisions()}
    assert "cloud-signed-memory" in sources
    assert "policy-bundle" in sources


def test_memory_bundle_memory_sequence_does_not_duplicate_or_resurrect(tmp_path: Path) -> None:
    store = _store(tmp_path)
    now = "2026-07-16T12:00:00Z"
    execute_review_policy_memory(
        {"decisionMemoryBundle": _bundle(store)},
        store=store,
        generated_at=now,
    )
    first_memory = [row for row in store.list_policy_decisions() if row["source"] == "cloud-signed-memory"]
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="block",
                artifact_id="command:npm-test",
                source="policy-bundle",
            )
        ],
        now,
        remote_write_authorized=True,
    )
    execute_review_policy_memory(
        {"decisionMemoryBundle": _bundle(store)},
        store=store,
        generated_at="2026-07-16T12:01:00Z",
    )
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="block",
                artifact_id="command:npm-test",
                source="policy-bundle",
            )
        ],
        "2026-07-16T12:02:00Z",
        remote_write_authorized=True,
    )
    memory_rows = [row for row in store.list_policy_decisions() if row["source"] == "cloud-signed-memory"]
    bundle_rows = [row for row in store.list_policy_decisions() if row["source"] == "policy-bundle"]
    assert len(memory_rows) == 1
    assert len(bundle_rows) == 1
    assert memory_rows[0]["artifact_id"] == first_memory[0]["artifact_id"]
    assert memory_rows[0]["action"] == first_memory[0]["action"]


def test_machine_target_does_not_authorize_sibling_machine(tmp_path: Path) -> None:
    store = _store(tmp_path)
    sibling_bundle = _bundle(store)
    rules = sibling_bundle["memoryRules"]
    assert isinstance(rules, list) and isinstance(rules[0], dict)
    rules[0]["target"] = {"machineIds": ["sibling-install"], "workspaceIds": []}
    rejected = execute_review_policy_memory(
        {"decisionMemoryBundle": _resign_bundle(sibling_bundle)},
        store=store,
        generated_at="2026-07-16T12:00:00Z",
    )
    assert rejected["status"] == "rejected"
    assert store.list_policy_decisions() == []

    execute_review_policy_memory(
        {"decisionMemoryBundle": _bundle(store)},
        store=store,
        generated_at="2026-07-16T12:00:00Z",
    )
    owner = store.resolve_policy(
        "cursor",
        "plugin:hol/deploy",
        artifact_hash="b" * 64,
        workspace="/workspace/repo",
        now="2026-07-16T12:01:00Z",
    )
    assert owner == "allow"


def test_portal_cardinality_preserves_targets_without_broadening_portable_allow(tmp_path: Path) -> None:
    store = _store(tmp_path)
    workspace_id = (store.get_cloud_sync_profile() or {})["workspace_id"]
    installation_id = store.get_device_metadata()["installation_id"]
    project_id = "git-project:v1:" + "ab" * 32
    allow_bundle = _bundle(store)
    allow_rules = allow_bundle["memoryRules"]
    assert isinstance(allow_rules, list) and isinstance(allow_rules[0], dict)
    allow_rules[0]["projectIdentity"] = project_id
    allow_rules[0]["target"] = {
        "workspaceIds": [workspace_id, "workspace-sibling"],
        "machineIds": [installation_id, "other-machine"],
        "projectIds": [project_id],
    }
    allowed = execute_review_policy_memory(
        {"decisionMemoryBundle": _resign_bundle(allow_bundle)},
        store=store,
        generated_at="2026-07-16T12:00:00Z",
    )
    assert allowed["status"] == "rejected"
    assert store.list_policy_decisions() == []

    # Multiple machine/workspace targets are supported when no project permission is erased.
    allow_rules[0]["projectIdentity"] = None
    allow_rules[0]["target"].pop("projectIds")
    allowed = execute_review_policy_memory(
        {"decisionMemoryBundle": _resign_bundle(allow_bundle)},
        store=store,
        generated_at="2026-07-16T12:00:00Z",
    )
    assert allowed["status"] == "accepted"
    assert (
        store.resolve_policy(
            "cursor",
            "plugin:hol/deploy",
            artifact_hash="b" * 64,
            workspace="/workspace/repo",
            now="2026-07-16T12:01:00Z",
        )
        == "allow"
    )

    mismatched = _bundle(store)
    mismatched["policyVersion"] = "policy-version-y-mismatch"
    mismatched_rules = mismatched["memoryRules"]
    assert isinstance(mismatched_rules, list) and isinstance(mismatched_rules[0], dict)
    mismatched_rules[0]["projectIdentity"] = project_id
    mismatched_rules[0]["target"] = {
        "workspaceIds": [workspace_id],
        "machineIds": [installation_id],
        "projectIds": ["git-project:v1:" + "cd" * 32],
    }
    rejected = execute_review_policy_memory(
        {"decisionMemoryBundle": _resign_bundle(mismatched)},
        store=store,
        generated_at="2026-07-16T12:02:00Z",
    )
    assert rejected["status"] == "rejected"

    block_bundle = _bundle(store)
    block_bundle["policyVersion"] = "policy-version-z-block"
    block_rules = block_bundle["memoryRules"]
    assert isinstance(block_rules, list) and isinstance(block_rules[0], dict)
    block_rules[0]["action"] = "block"
    block_rules[0]["projectIdentity"] = project_id
    block_rules[0]["target"] = {
        "workspaceIds": [workspace_id],
        "machineIds": [installation_id],
        "projectIds": [project_id],
    }
    blocked = execute_review_policy_memory(
        {"decisionMemoryBundle": _resign_bundle(block_bundle)},
        store=store,
        generated_at="2026-07-16T12:03:00Z",
    )
    assert blocked["status"] == "accepted"
    assert (
        store.resolve_policy(
            "cursor",
            "plugin:hol/deploy",
            artifact_hash="b" * 64,
            workspace=project_id,
            now="2026-07-16T12:04:00Z",
        )
        == "block"
    )


def test_memory_target_above_portal_cardinality_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    workspace_id = (store.get_cloud_sync_profile() or {})["workspace_id"]
    bundle = _bundle(store)
    rules = bundle["memoryRules"]
    assert isinstance(rules, list) and isinstance(rules[0], dict)
    rules[0]["target"] = {"workspaceIds": [workspace_id, *[f"workspace-{index}" for index in range(50)]]}
    result = execute_review_policy_memory(
        {"decisionMemoryBundle": _resign_bundle(bundle)},
        store=store,
        generated_at="2026-07-16T12:00:00Z",
    )
    assert result["status"] == "rejected"
    assert store.list_policy_decisions() == []


def test_empty_memory_target_arrays_apply_on_this_device(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bundle = _bundle(store)
    rules = bundle["memoryRules"]
    assert isinstance(rules, list) and isinstance(rules[0], dict)
    rules[0]["target"] = {"workspaceIds": [], "machineIds": []}
    result = execute_review_policy_memory(
        {"decisionMemoryBundle": _resign_bundle(bundle)},
        store=store,
        generated_at="2026-07-16T12:00:00Z",
    )
    assert result["status"] == "accepted"
    assert (
        store.resolve_policy(
            "cursor",
            "plugin:hol/deploy",
            artifact_hash="b" * 64,
            workspace="/workspace/repo",
            now="2026-07-16T12:01:00Z",
        )
        == "allow"
    )
