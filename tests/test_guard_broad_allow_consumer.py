"""Broad harness/global allows must not skip artifact-scoped hash checks."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import evaluate_detection
from codex_plugin_scanner.guard.consumer.service import _consumer_saved_allow_validation_reason
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection, PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore

_CURRENT_CONTEXT = "guard-approval-context:v1:deadbeefdeadbeef"


def _skill_artifact(tmp_path: Path) -> GuardArtifact:
    skill_md = tmp_path / "workspace" / "skills" / "apple" / "apple-notes" / "SKILL.md"
    skill_md.parent.mkdir(parents=True, exist_ok=True)
    skill_md.write_text("# Apple Notes\n\nRead notes.\n", encoding="utf-8")
    return GuardArtifact(
        artifact_id="hermes:skill:apple:apple-notes",
        name="apple-notes",
        harness="hermes",
        artifact_type="skill",
        source_scope="global",
        config_path=str(skill_md),
        command=str(skill_md),
        metadata={"action_class": "skill"},
    )


def _detection(artifact: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness=artifact.harness,
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )


def test_hashless_harness_allow_skips_context_validation() -> None:
    assert (
        _consumer_saved_allow_validation_reason(
            {"action": "allow", "artifact_hash": None, "scope": "harness"},
            approval_context_hash=_CURRENT_CONTEXT,
        )
        is None
    )


def test_hashless_global_allow_skips_context_validation() -> None:
    assert (
        _consumer_saved_allow_validation_reason(
            {"action": "allow", "artifact_hash": None, "scope": "global"},
            approval_context_hash=_CURRENT_CONTEXT,
        )
        is None
    )


def test_hashless_artifact_allow_still_fails_closed() -> None:
    assert (
        _consumer_saved_allow_validation_reason(
            {"action": "allow", "artifact_hash": None, "scope": "artifact"},
            approval_context_hash=_CURRENT_CONTEXT,
        )
        == "approval_reuse_content_changed"
    )


def test_hashless_workspace_allow_still_fails_closed() -> None:
    assert (
        _consumer_saved_allow_validation_reason(
            {"action": "allow", "artifact_hash": None, "scope": "workspace"},
            approval_context_hash=_CURRENT_CONTEXT,
        )
        == "approval_reuse_content_changed"
    )


def test_consumer_honors_broad_harness_allow_for_hermes_skill(tmp_path: Path) -> None:
    artifact = _skill_artifact(tmp_path)
    detection = _detection(artifact)
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        mode="prompt",
    )
    store.upsert_policy(
        PolicyDecision(
            harness="hermes",
            scope="harness",
            action="allow",
            artifact_hash=None,
            reason="broad harness allow",
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )

    item = evaluate_detection(
        detection,
        store,
        config,
        default_action="review",
        persist=False,
    )["artifacts"][0]

    assert item["approval_reuse_status"] == "accepted"
    assert item["policy_action"] == "allow"


def test_consumer_honors_broad_global_allow_for_hermes_skill(tmp_path: Path) -> None:
    artifact = _skill_artifact(tmp_path)
    detection = _detection(artifact)
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        mode="prompt",
    )
    store.upsert_policy(
        PolicyDecision(
            harness="hermes",
            scope="global",
            action="allow",
            artifact_hash=None,
            reason="broad global allow",
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )

    item = evaluate_detection(
        detection,
        store,
        config,
        default_action="review",
        persist=False,
    )["artifacts"][0]

    assert item["approval_reuse_status"] == "accepted"
    assert item["policy_action"] == "allow"


def test_consumer_rejects_hashless_artifact_allow_for_hermes_skill(tmp_path: Path) -> None:
    artifact = _skill_artifact(tmp_path)
    detection = _detection(artifact)
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        mode="prompt",
    )
    store.upsert_policy(
        PolicyDecision(
            harness="hermes",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=None,
            reason="legacy unbound artifact allow",
            source="approval-gate",
        ),
        "2026-07-17T00:00:00Z",
    )

    item = evaluate_detection(
        detection,
        store,
        config,
        default_action="review",
        persist=False,
    )["artifacts"][0]

    assert item["approval_reuse_status"] == "rejected"
    assert item["approval_reuse_reason_code"] == "approval_reuse_content_changed"
