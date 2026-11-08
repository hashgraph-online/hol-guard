"""Unsupported consumer bindings explain recovery without offering a futile retry."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.cli.render import _build_run_steps
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError
from codex_plugin_scanner.guard.runtime import consumer_launch_capability as capability


def detection():
    artifact = GuardArtifact("node", "node_repl", "codex", "mcp_server", "project", "/fixture/config", command="node")
    return HarnessDetection("codex", True, True, (), (artifact,))


def test_native_unavailable_capability_explains_without_retry_or_approval(monkeypatch):
    calls = []

    def answer(kind, args):
        calls.append((kind, args))
        return {
            "available": False,
            "unavailable_artifact_ids": ["node"],
            "reason_code": "consumer_launch_binding_unsupported_platform",
        }

    monkeypatch.setattr(capability, "native_runner_authority", answer)
    payload = capability.consumer_launch_review_capability(
        detection(), {"artifacts": [{"artifact_id": "node", "policy_action": "review"}]}
    )
    assert calls[0][0] == "consumer_launch_review_capability"
    assert calls[0][1]["artifacts"][0]["command"] == "node"
    assert "No launch approval is available" in payload["review_hint"]
    assert "Do not disable Guard" in payload["review_hint"]
    payload.update(harness="codex", rerun_command="hol-guard run codex", diff_command="hol-guard diff codex")
    steps = _build_run_steps(payload, blocked=True, dry_run=False)
    assert [step["command"] for step in steps] == ["hol-guard diff codex"]
    assert "unsupported" in steps[0]["title"]


def test_supported_capability_does_not_change_review_presentation(monkeypatch):
    monkeypatch.setattr(
        capability, "native_runner_authority", lambda *_: {"available": True, "unavailable_artifact_ids": []}
    )
    assert (
        capability.consumer_launch_review_capability(
            detection(), {"artifacts": [{"artifact_id": "node", "policy_action": "review"}]}
        )
        == {}
    )


def test_missing_capability_answer_never_claims_support(monkeypatch):
    monkeypatch.setattr(capability, "native_runner_authority", lambda *_: {})
    with pytest.raises(NativeRunnerAuthorityError, match="result_invalid"):
        capability.consumer_launch_review_capability(
            detection(), {"artifacts": [{"artifact_id": "node", "policy_action": "review"}]}
        )


def test_capability_passes_current_mixed_actions_to_native_owner(monkeypatch):
    from dataclasses import replace

    detected = detection()
    skill = GuardArtifact("skill", "skill", "codex", "skill", "project", "/fixture/SKILL.md")
    detected = replace(detected, artifacts=(*detected.artifacts, skill))
    evaluations = [
        {"artifact_id": "node", "policy_action": "allow"},
        {"artifact_id": "skill", "policy_action": "require-reapproval"},
    ]
    calls = []

    def answer(kind, args):
        calls.append(args)
        return {"available": True, "unavailable_artifact_ids": []}

    monkeypatch.setattr(capability, "native_runner_authority", answer)
    assert capability.consumer_launch_review_capability(detected, {"artifacts": evaluations}) == {}
    assert calls[0]["evaluations"] == evaluations
    assert [artifact["artifact_id"] for artifact in calls[0]["artifacts"]] == ["node", "skill"]
