from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import artifact_hash, evaluate_detection
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.store import GuardStore


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _identity_metadata(directory_hash: str, *, status: str = "complete") -> dict[str, object]:
    complete = status == "complete"
    return {
        "content_hash": _digest("primary SKILL.md"),
        "directory_hash": directory_hash,
        "skillDirectoryIdentity": {
            "schemaVersion": "guard.skill-directory-identity.v1",
            "status": status,
            "contentHash": directory_hash if complete else None,
            "entryCount": 4,
            "totalBytes": 128,
            "reusable": complete,
            **({"reason": "entry_limit", "incompleteStateHash": _digest("scan failure")} if not complete else {}),
        },
        "versionInfo": {
            "hashBasis": "skill-directory-v1",
            "contentHash": directory_hash if complete else _digest("scan failure"),
        },
    }


def _artifact(tmp_path: Path, metadata: dict[str, object]) -> GuardArtifact:
    workspace = tmp_path / "workspace"
    skill_path = workspace / ".gemini" / "skills" / "review" / "SKILL.md"
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    skill_path.write_text("# Review\n", encoding="utf-8")
    return GuardArtifact(
        artifact_id="gemini:skill:review",
        name="review",
        harness="gemini",
        artifact_type="skill",
        source_scope="project",
        config_path=str(skill_path),
        publisher="local",
        metadata=metadata,
    )


def _detection(artifact: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness=artifact.harness,
        installed=True,
        command_available=False,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )


def _config(tmp_path: Path, artifact_id: str) -> GuardConfig:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    return GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        artifact_actions={artifact_id: "review"},
    )


def _save_allow(
    store: GuardStore,
    *,
    artifact: GuardArtifact,
    context_hash: str,
    workspace: Path,
    request_id: str,
) -> None:
    approval_id = store.record_local_once_approval(
        request_id=request_id,
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=context_hash,
        workspace=str(workspace),
        publisher=artifact.publisher,
        action="allow",
        created_at="2026-07-19T00:00:00Z",
        expires_at="2099-07-19T00:00:00Z",
    )
    assert approval_id is not None


def test_complete_unchanged_directory_identity_reuses_exact_saved_approval(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path, _identity_metadata(_digest("directory-v1")))
    detection = _detection(artifact)
    config = _config(tmp_path, artifact.artifact_id)
    store = GuardStore(config.guard_home)
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _save_allow(
        store,
        artifact=artifact,
        context_hash=context_hash,
        workspace=config.workspace or tmp_path,
        request_id="complete-skill",
    )
    pending_claims: list[tuple[Mapping[str, object], str, str]] = []

    result = evaluate_detection(
        detection,
        store,
        config,
        persist=False,
        pending_approval_claims=pending_claims,
    )
    item = result["artifacts"][0]

    assert item["approval_context_hash"] == context_hash
    assert item["policy_action"] == "allow"
    assert item["approval_reuse_status"] == "accepted"
    assert item["approval_reuse_reason_code"] == "approval_reuse_accepted"
    assert len(pending_claims) == 1


def test_directory_identity_change_invalidates_prior_saved_approval(tmp_path: Path) -> None:
    original = _artifact(tmp_path, _identity_metadata(_digest("directory-v1")))
    config = _config(tmp_path, original.artifact_id)
    store = GuardStore(config.guard_home)
    initial = evaluate_detection(_detection(original), store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _save_allow(
        store,
        artifact=original,
        context_hash=context_hash,
        workspace=config.workspace or tmp_path,
        request_id="changed-skill",
    )
    changed = _artifact(tmp_path, _identity_metadata(_digest("directory-v2")))
    pending_claims: list[tuple[Mapping[str, object], str, str]] = []

    result = evaluate_detection(
        _detection(changed),
        store,
        config,
        persist=False,
        pending_approval_claims=pending_claims,
    )
    item = result["artifacts"][0]

    assert item["approval_context_hash"] != context_hash
    assert item["policy_action"] == "review"
    assert item["approval_reuse_status"] == "rejected"
    assert item["approval_reuse_reason_code"] in {
        "approval_reuse_content_changed",
        "approval_reuse_identity_changed",
    }
    assert pending_claims == []


@pytest.mark.parametrize(
    "marker",
    (
        _identity_metadata(_digest("partial"), status="incomplete")["skillDirectoryIdentity"],
        "malformed",
    ),
)
def test_incomplete_or_malformed_identity_blocks_saved_approval_reuse(
    tmp_path: Path,
    marker: object,
) -> None:
    metadata = _identity_metadata(_digest("partial"), status="incomplete")
    metadata["skillDirectoryIdentity"] = marker
    artifact = _artifact(tmp_path, metadata)
    detection = _detection(artifact)
    config = _config(tmp_path, artifact.artifact_id)
    store = GuardStore(config.guard_home)
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _save_allow(
        store,
        artifact=artifact,
        context_hash=context_hash,
        workspace=config.workspace or tmp_path,
        request_id=f"incomplete-skill-{type(marker).__name__}",
    )
    pending_claims: list[tuple[Mapping[str, object], str, str]] = []

    result = evaluate_detection(
        detection,
        store,
        config,
        persist=False,
        pending_approval_claims=pending_claims,
        claimed_saved_approval_overrides={artifact.artifact_id: context_hash},
    )
    item = result["artifacts"][0]

    assert item["policy_action"] == "require-reapproval"
    assert item["approval_reuse_status"] == "rejected"
    assert item["approval_reuse_reason_code"] == "approval_reuse_reapproval_required"
    assert item["policy_composition"]["skill_directory_identity_reusable"] is False
    assert item["policy_composition"]["skill_directory_identity_floor"] == "require-reapproval"
    assert item["scanner_evidence"][0]["reason_code"] == "skill_directory_identity_non_reusable"
    assert "approval_claim" not in item
    assert pending_claims == []
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(config.workspace),
            publisher=artifact.publisher,
            now="2026-07-19T00:01:00Z",
        )
        is not None
    )


def test_removed_incomplete_skill_also_uses_reapproval_floor(tmp_path: Path) -> None:
    artifact = _artifact(
        tmp_path,
        _identity_metadata(_digest("removed-partial"), status="incomplete"),
    )
    config = _config(tmp_path, artifact.artifact_id)
    store = GuardStore(config.guard_home)
    snapshot = artifact.to_dict()
    snapshot["env_keys"] = []
    snapshot_hash = artifact_hash(artifact)
    snapshot["artifact_hash"] = snapshot_hash
    store.save_snapshot(
        artifact.harness,
        artifact.artifact_id,
        snapshot,
        snapshot_hash,
        "2026-07-19T00:00:00Z",
    )
    removed_detection = HarnessDetection(
        harness=artifact.harness,
        installed=True,
        command_available=False,
        config_paths=(),
        artifacts=(),
    )
    initial = evaluate_detection(removed_detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _save_allow(
        store,
        artifact=artifact,
        context_hash=context_hash,
        workspace=config.workspace or tmp_path,
        request_id="removed-incomplete-skill",
    )
    pending_claims: list[tuple[Mapping[str, object], str, str]] = []

    result = evaluate_detection(
        removed_detection,
        store,
        config,
        persist=False,
        pending_approval_claims=pending_claims,
    )
    item = result["artifacts"][0]

    assert item["policy_action"] == "require-reapproval"
    assert item["approval_reuse_status"] == "rejected"
    assert item["policy_composition"]["skill_directory_identity_reusable"] is False
    assert pending_claims == []
