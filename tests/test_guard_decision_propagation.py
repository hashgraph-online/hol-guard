"""Authenticated approvals permit exact retries without lowering stronger policy."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approvals import apply_approval_resolution, queue_blocked_approvals
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer.service import evaluate_detection
from codex_plugin_scanner.guard.models import (
    GuardArtifact,
    HarnessDetection,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture(autouse=True)
def _enroll_native_context(tmp_path: Path, native_mcp_probe) -> None:
    native_mcp_probe(tmp_path / "guard")


def _make_artifact(
    *,
    name: str = "test_tool",
    config_path: str = "/repo/workspace/.codex/config.toml",
) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=f"codex:project:{name}",
        name=name,
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=config_path,
        # Use a real, content-bound interpreter and stable inline entrypoint.
        # An absent ``server.js`` intentionally receives a fresh fail-closed
        # launch-identity nonce on every evaluation, which would turn this
        # propagation test into an identity-change test.
        command=sys.executable,
        args=("-c", "pass"),
        transport="stdio",
    )


def _make_detection(artifact: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )


class TestImmediateApproveDecisionPropagation:
    """Browser approval grants compose with current stronger policy."""

    def test_fresh_approval_satisfies_reapproval_but_cannot_lower_block(self, tmp_path: Path) -> None:
        """An exact authenticated approval permits retry, not a later terminal block."""
        guard_home = tmp_path / "guard"
        store = GuardStore(guard_home)
        artifact = _make_artifact(name="sync_tool", config_path=str(tmp_path / "ws/.codex/config.toml"))
        config = GuardConfig(guard_home=guard_home, workspace=None)
        detection = _make_detection(artifact)

        initial_eval = evaluate_detection(detection, store, config, persist=True)
        assert initial_eval.get("blocked") is True, "Tool must be blocked before approval"

        approvals = queue_blocked_approvals(
            detection=detection,
            evaluation=initial_eval,
            store=store,
            approval_center_url="http://127.0.0.1:6174",
        )
        assert len(approvals) > 0, "Must queue at least one approval request"
        request_id = str(approvals[0]["request_id"])

        apply_approval_resolution(
            store=store,
            request_id=request_id,
            action="allow",
            scope="artifact",
            workspace=None,
            reason=None,
        )

        retry_eval = evaluate_detection(detection, store, config, persist=False)
        assert retry_eval.get("blocked") is False
        artifact_result = (retry_eval.get("artifacts") or [{}])[0]
        assert artifact_result.get("policy_action") == "allow"
        assert artifact_result.get("approval_reuse_status") == "accepted"

        strict_config = replace(
            config,
            default_action="block",
            changed_hash_action="block",
            risk_actions={level: "block" for level in ("low", "medium", "high", "critical")},
        )
        strict_eval = evaluate_detection(detection, store, strict_config, persist=False)
        assert strict_eval.get("blocked") is True
        assert strict_eval["artifacts"][0]["policy_action"] == "block"


def test_unknown_evaluation_action_queues_conservative_reapproval(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    artifact = _make_artifact(name="future_action")

    approvals = queue_blocked_approvals(
        detection=_make_detection(artifact),
        evaluation={
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_hash": "sha256:future-action",
                    "policy_action": "future-action",
                    "risk_summary": "Unknown action from a newer producer.",
                }
            ]
        },
        store=store,
        approval_center_url="http://127.0.0.1:6174",
    )

    assert len(approvals) == 1
    assert approvals[0]["policy_action"] == "require-reapproval"
    assert approvals[0]["scanner_evidence"][-1] == {
        "source": "guard_action_normalizer",
        "reason_code": "guard_action_unknown",
        "original_action": "future-action",
        "normalized_action": "require-reapproval",
    }


class TestImmediateDenyDecisionPropagation:
    """T724: Browser deny writes decision before harness retry resumes."""

    def test_deny_decision_visible_to_evaluate_without_delay(self, tmp_path: Path) -> None:
        """T724: After apply_approval_resolution(block), re-running evaluate_detection
        immediately returns a blocked evaluation.
        """
        guard_home = tmp_path / "guard"
        store = GuardStore(guard_home)
        artifact = _make_artifact(name="denied_tool", config_path=str(tmp_path / "ws/.codex/config.toml"))
        config = GuardConfig(guard_home=guard_home, workspace=None)
        detection = _make_detection(artifact)

        initial_eval = evaluate_detection(detection, store, config, persist=True)
        approvals = queue_blocked_approvals(
            detection=detection,
            evaluation=initial_eval,
            store=store,
            approval_center_url="http://127.0.0.1:6174",
        )
        assert len(approvals) > 0
        request_id = str(approvals[0]["request_id"])

        apply_approval_resolution(
            store=store,
            request_id=request_id,
            action="block",
            scope="artifact",
            workspace=None,
            reason="Not permitted by security policy",
        )

        retry_eval = evaluate_detection(detection, store, config, persist=False)
        assert retry_eval.get("blocked") is True, "T724: Evaluation immediately after deny must be blocked"
        artifact_result = (retry_eval.get("artifacts") or [{}])[0]
        assert artifact_result.get("policy_action") == "block", (
            "T724: Evaluation immediately after deny must return block policy"
        )
