from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.daemon import hook_fail_closed
from codex_plugin_scanner.guard.daemon.hook_fail_closed import (
    fail_closed_pre_tool,
    render_accepted_allow,
    render_pre_tool,
    render_pre_tool_review,
    render_recording_only_pre_tool,
)


@pytest.mark.parametrize("harness", ["pi", "omp", "grok", "openclaw"])
def test_flat_harnesses_get_a_fixed_deny(harness: str) -> None:
    rendered = fail_closed_pre_tool(harness)
    assert rendered["decision"] == "deny"
    assert rendered["policy_action"] == "block"
    assert rendered["reason_code"] == "native_hook_render_unavailable"


def test_hermes_blocks_and_other_harnesses_use_the_hook_envelope() -> None:
    assert fail_closed_pre_tool("hermes")["decision"] == "block"
    rendered = fail_closed_pre_tool("claude_code")
    assert rendered["hookSpecificOutput"] == {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "HOL Guard could not complete native review safely.",
    }


def test_recording_only_render_forwards_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def render(*_args: object, **kwargs: object) -> dict[str, object]:
        seen.update(kwargs)
        return {"decision": "allow", "policy_action": "warn"}

    monkeypatch.setattr(hook_fail_closed, "native_render_recording_only_pre_tool", render)
    rendered = render_recording_only_pre_tool("pi", reason_code="x", reason="y", deadline=12.0)
    assert rendered["policy_action"] == "warn"
    assert seen["deadline"] == 12.0


def test_recording_only_render_denies_when_the_deadline_already_passed() -> None:
    rendered = render_recording_only_pre_tool("pi", reason_code="x", reason="y", deadline=0.0)
    assert rendered["decision"] == "deny"
    assert rendered["policy_action"] == "block"


def test_unavailable_resident_never_renders_an_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hook_fail_closed, "native_render_pre_tool", lambda *_a, **_k: None)
    monkeypatch.setattr(hook_fail_closed, "native_render_pre_tool_review", lambda *_a, **_k: None)
    monkeypatch.setattr(hook_fail_closed, "native_render_recording_only_pre_tool", lambda *_a, **_k: None)
    allowed = {"decision": "allow", "policy_action": "allow"}
    assert render_pre_tool("pi", allowed)["decision"] == "deny"
    assert render_pre_tool_review("codex", allowed, approval=None)["policy_action"] == "block"
    assert render_recording_only_pre_tool("pi", reason_code="x", reason="y")["decision"] == "deny"


def test_resident_response_is_returned_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def render(harness: str, verdict: object, *, guard_home: object = None) -> dict[str, object]:
        seen.update(harness=harness, verdict=verdict)
        return {"decision": "allow", "from": "resident"}

    monkeypatch.setattr(hook_fail_closed, "native_render_pre_tool", render)
    assert render_pre_tool("pi", {"decision": "allow"}) == {"decision": "allow", "from": "resident"}
    assert seen == {"harness": "pi", "verdict": {"decision": "allow"}}


def test_review_ships_the_linked_reason_only_with_an_approval_url(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []

    def render(harness: str, verdict: object, **kwargs: object) -> dict[str, object]:
        captured.append(kwargs)
        return {"ok": True}

    monkeypatch.setattr(hook_fail_closed, "native_render_pre_tool_review", render)
    monkeypatch.setattr(hook_fail_closed, "native_review_reason", lambda _h, reason, url, **_k: f"{reason} {url}")
    render_pre_tool_review("pi", {"reason": "Needs review."}, approval=None)
    render_pre_tool_review("pi", {"reason": "Needs review."}, approval={"approval_url": " http://x/a "})
    assert captured[0]["linked_reason"] is None
    assert captured[1]["linked_reason"] == "Needs review. http://x/a"


def test_accepted_allow_is_marked_only_when_the_resident_rendered_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hook_fail_closed, "native_render_pre_tool", lambda *a, **k: {"decision": "allow"})
    assert render_accepted_allow("pi", {"decision": "allow"}) == {
        "decision": "allow",
        "approval_reuse_status": "accepted",
    }
    monkeypatch.setattr(hook_fail_closed, "native_render_pre_tool", lambda *a, **k: None)
    failed = render_accepted_allow("pi", {"decision": "allow"})
    assert failed["decision"] == "deny"
    assert "approval_reuse_status" not in failed


def test_queued_review_deny_keeps_the_approval_link_when_render_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hook_fail_closed, "native_render_pre_tool_review", lambda *a, **k: None)
    monkeypatch.setattr(hook_fail_closed, "native_review_reason", lambda *a, **k: "Review at http://127.0.0.1/a")
    rendered = render_pre_tool_review(
        "pi", {"reason": "needs review"}, approval={"approval_url": "http://127.0.0.1/a", "request_id": "r"}
    )
    assert rendered["decision"] == "deny"
    assert "http://127.0.0.1/a" in str(rendered["reason"])
