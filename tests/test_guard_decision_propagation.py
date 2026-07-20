"""Phase 25 — immediate decision propagation: browser approve/block writes
decision before harness retry resumes (T722-T724).
"""

from __future__ import annotations

import sys
from pathlib import Path

from codex_plugin_scanner.guard.approvals import apply_approval_resolution, queue_blocked_approvals
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer.service import evaluate_detection
from codex_plugin_scanner.guard.models import (
    GuardArtifact,
    HarnessDetection,
)
from codex_plugin_scanner.guard.store import GuardStore


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
    """T722-T723: Browser decisions propagate without bypassing current policy."""

    def test_approve_decision_is_visible_but_cannot_lower_current_reapproval(self, tmp_path: Path) -> None:
        """T723: A propagated approval remains evidence, not stronger policy authority."""
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
        assert retry_eval.get("blocked") is True
        artifact_result = (retry_eval.get("artifacts") or [{}])[0]
        assert artifact_result.get("policy_action") == "require-reapproval"
        assert artifact_result.get("approval_reuse_status") == "rejected"
        assert artifact_result.get("approval_reuse_reason_code") == "approval_reuse_reapproval_required"
        assert artifact_result.get("policy_composition", {}).get("saved_action") == "allow"

    def test_approve_propagation_occurs_before_request_resolution_response(self, tmp_path: Path) -> None:
        """T722: apply_approval_resolution writes the policy before marking the
        request resolved. Re-evaluation can observe it immediately, while the
        current reapproval result remains authoritative.
        """
        guard_home = tmp_path / "guard"
        store = GuardStore(guard_home)
        artifact = _make_artifact(name="ordered_tool", config_path=str(tmp_path / "ws/.codex/config.toml"))
        config = GuardConfig(guard_home=guard_home, workspace=None)
        detection = _make_detection(artifact)

        eval_before = evaluate_detection(detection, store, config, persist=True)
        approvals = queue_blocked_approvals(
            detection=detection,
            evaluation=eval_before,
            store=store,
            approval_center_url="http://127.0.0.1:6174",
        )
        request_id = str(approvals[0]["request_id"])

        apply_approval_resolution(
            store=store,
            request_id=request_id,
            action="allow",
            scope="artifact",
            workspace=None,
            reason=None,
        )

        resolved = store.get_approval_request(request_id)
        assert resolved is not None
        assert resolved["status"] == "resolved", "Request must be marked resolved after approval"

        immediate_eval = evaluate_detection(detection, store, config, persist=False)
        artifact_result = (immediate_eval.get("artifacts") or [{}])[0]
        assert immediate_eval.get("blocked") is True
        assert artifact_result.get("policy_composition", {}).get("saved_action") == "allow"
        assert artifact_result.get("approval_reuse_reason_code") == "approval_reuse_reapproval_required"


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
