"""Authenticated exact generic approvals satisfy reapproval, not changed requests."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli.commands_hook_native_generic import run_native_generic_payload
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_runtime_mcp_saved_blocks import _context


@pytest.mark.parametrize("remember", [False, True])
@pytest.mark.parametrize("live_revalidation", [False, True])
def test_exact_generic_approval_satisfies_reapproval(
    tmp_path,
    native_mcp_probe,
    capsys,
    remember,
    live_revalidation,
):
    context = _context(tmp_path)
    native_mcp_probe(context.guard_home)
    store = GuardStore(context.guard_home)
    config = GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        default_action="require-reapproval",
        blocked_request_mode="ask",
    )
    payload = {
        "artifact_id": "generic-test:project:extension:fixture",
        "artifact_name": "fixture.ts",
        "hook_event_name": "PreToolUse",
        "tool_name": "opaque_tool",
        "tool_input": {"content": "original"},
    }

    last_response = {}

    def evaluate(claimed_hash=None, fresh=False, durable=False):
        nonlocal last_response
        result = run_native_generic_payload(
            SimpleNamespace(harness="generic-test", json=True),
            action_envelope=None,
            config=config,
            home_dir=context.home_dir,
            payload=payload,
            runtime_workspace=context.workspace_dir,
            store=store,
            _claimed_saved_allow_hash=claimed_hash,
            _claimed_fresh_local_approval=fresh,
            _claimed_durable_exact_approval=durable,
            _claim_saved_approval=claimed_hash is None,
            post_claim_revalidator=(
                lambda current_hash, qualified_fresh, qualified_durable: evaluate(
                    current_hash,
                    qualified_fresh,
                    qualified_durable,
                )[0]
            )
            if live_revalidation and claimed_hash is None
            else None,
        )
        output = capsys.readouterr().out
        if output:
            last_response = json.loads(output)
        return result, last_response

    result, _ = evaluate()
    assert result == 1
    request = store.list_approval_requests()[0]
    resolved = apply_approval_resolution(
        store=store,
        request_id=request["request_id"],
        action="allow",
        scope="artifact",
        workspace=str(context.workspace_dir),
        reason="fixture review",
        persist_policy=remember,
    )
    assert resolved["status"] == "resolved"
    result, response = evaluate()
    assert result == 0, json.dumps(response, sort_keys=True)
    assert response["policy_action"] == "allow"
    payload["tool_input"] = {"content": "changed"}
    result, response = evaluate()
    assert result == 1
    assert response["policy_action"] == "require-reapproval"
    payload["tool_input"] = {"content": "original"}
    config = replace(config, default_action="block")
    result, response = evaluate()
    assert result == 1
    assert response["policy_action"] == "block"


@pytest.mark.parametrize("remember", [False, True])
def test_authentic_consumer_claim_preserves_native_reapproval_qualification(
    tmp_path,
    native_mcp_probe,
    remember,
):
    from codex_plugin_scanner.guard.approvals import queue_blocked_approvals
    from codex_plugin_scanner.guard.consumer import evaluate_detection
    from codex_plugin_scanner.guard.runtime.decisions import AuthoritativeGuardDecision
    from tests.test_guard_consumer_approval_precedence import _artifact, _detection

    artifact = _artifact(tmp_path)
    artifact = replace(artifact, metadata={**artifact.metadata, "guard_default_action": "require-reapproval"})
    detection = _detection(artifact)
    home = tmp_path / "consumer-guard"
    native_mcp_probe(home)
    store = GuardStore(home)
    config = GuardConfig(guard_home=home, workspace=tmp_path / "workspace", default_action="require-reapproval")
    initial = evaluate_detection(detection, store, config, persist=False)
    assert initial["artifacts"][0]["policy_action"] == "require-reapproval"
    requests = queue_blocked_approvals(
        detection=detection,
        evaluation=initial,
        store=store,
        approval_center_url="http://127.0.0.1:4455",
    )
    resolved = apply_approval_resolution(
        store=store,
        request_id=requests[0]["request_id"],
        action="allow",
        scope="artifact",
        workspace=str(config.workspace),
        reason="consumer fixture review",
        persist_policy=remember,
    )
    assert resolved["status"] == "resolved"
    claims = []
    preclaim = evaluate_detection(detection, store, config, persist=False, pending_approval_claims=claims)
    assert preclaim["artifacts"][0]["policy_action"] == "allow"
    decision, artifact_id, context_hash = claims[0]
    assert decision["fresh_local_approval"] is True
    assert store.claim_approval_reuse_decision(decision) is True
    retained = store.approval_reuse_claim_disposition(decision) == "retained"
    finalized = evaluate_detection(
        detection,
        store,
        config,
        persist=True,
        claimed_saved_approval_overrides={} if retained else {artifact_id: context_hash},
        retained_saved_approval_overrides={artifact_id: context_hash} if retained else {},
        saved_approval_qualification_overrides={artifact_id: decision},
    )
    item = finalized["artifacts"][0]
    assert finalized["blocked"] is False
    assert AuthoritativeGuardDecision.from_dict(item["authoritative_decision"]).action == "allow"
    changed = replace(artifact, args=("consumer-review.js", "--changed"))
    rejected = evaluate_detection(_detection(changed), store, config, persist=False)
    assert rejected["artifacts"][0]["policy_action"] == "require-reapproval"
