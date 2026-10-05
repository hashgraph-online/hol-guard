"""Default native denials never solicit operator approval."""

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
    assert "safe, permitted alternative" in reason
    assert "bypass Guard" in reason
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
