"""Default native denials never pause the agent, but approvable ones reach the inbox."""

from pathlib import Path

import pytest

from tests.silent_review_assertions import assert_silent_review_recorded
from tests.test_native_review_approval_coordination import _edge, _worker


@pytest.mark.parametrize(
    "harness",
    [
        "cursor",
        "zcode",
        "codex",
        "claude-code",
        "copilot",
        "gemini",
        "grok",
        "hermes",
        "pi",
        "omp",
        "opencode",
        "kimi",
        "devin",
    ],
)
@pytest.mark.parametrize("action", ["review", "require-reapproval"])
def test_native_review_defaults_to_safe_alternative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str, action: str
) -> None:
    edge = _edge(harness)
    edge["result"].update(policy_action=action, minimum_action=action)
    worker, store = _worker(tmp_path, monkeypatch, edge, ask=False)
    response = worker.review_http_payload(
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://example.test"},
        },
        params={},
        default_harness=harness,
        home_dir=tmp_path / "home",
        guard_home=store.guard_home,
        workspace=tmp_path / "workspace",
    )
    assert response["policy_action"] == "block"
    assert response["prompted"] is False
    assert response.get("approval_requests", []) == []
    assert_silent_review_recorded(store)
    reason = response.get("reason") or response["hookSpecificOutput"]["permissionDecisionReason"]
    assert "waiting for the user to approve it in the HOL Guard inbox" in reason
    assert "hol-guard approvals" in reason
    assert "Do not retry the same action until it is approved" in reason
    assert "safe, permitted alternative" not in reason
    # The agent hands the queued request's link to the user.
    request_id = store.list_approval_requests(status="pending")[0]["request_id"]
    if harness == "codex":
        # Codex gets only signed loopback links, and this daemon has no token to sign with.
        assert "could not create a signed approval link" in reason
    else:
        assert "Open HOL Guard to approve or keep this blocked:" in reason
        assert request_id in reason
    if "hookSpecificOutput" in response:
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    worker.close()


def test_malformed_config_denies_review_without_prompt(tmp_path, monkeypatch):
    worker, store = _worker(tmp_path, monkeypatch, _edge("cursor"), ask=False)
    (store.guard_home / "config.toml").write_text("invalid = [", encoding="utf-8")
    response = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_name": "WebFetch", "tool_input": {}},
        params={},
        default_harness="cursor",
        home_dir=tmp_path / "home",
        guard_home=store.guard_home,
        workspace=tmp_path / "workspace",
    )
    assert response["policy_action"] == "block"
    assert response["prompted"] is False
    assert_silent_review_recorded(store)
    worker.close()


def test_unbound_native_review_does_not_tell_the_agent_to_wait(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # git push and local scripts get no retry binding, so a one-time approval cannot let the agent's retry run.
    from codex_plugin_scanner.guard.daemon import hook_native_review_approval

    monkeypatch.setattr(hook_native_review_approval, "native_review_binding", lambda *_args, **_kwargs: None)
    worker, store = _worker(tmp_path, monkeypatch, _edge("omp"), ask=False)
    response = worker.review_http_payload(
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://example.test"},
        },
        params={},
        default_harness="omp",
        home_dir=tmp_path / "home",
        guard_home=store.guard_home,
        workspace=tmp_path / "workspace",
    )
    assert response["policy_action"] == "block"
    assert_silent_review_recorded(store)
    pending = store.list_approval_requests(status="pending")
    assert pending and pending[0]["artifact_hash"] == pending[0]["request_id"]
    reason = response.get("reason") or response["hookSpecificOutput"]["permissionDecisionReason"]
    assert "will not let you run it" in reason
    assert "Do not retry the same action until it is approved" not in reason
    worker.close()
