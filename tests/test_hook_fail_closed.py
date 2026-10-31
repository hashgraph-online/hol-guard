from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import hook_fail_closed
from codex_plugin_scanner.guard.daemon.hook_fail_closed import (
    fail_closed_pre_tool,
    render_accepted_allow,
    render_pre_tool,
    render_pre_tool_review,
    render_recording_only_pre_tool,
    render_silent_review_block,
)
from codex_plugin_scanner.guard.native_hook_decision import NativeHookDecisionError

_HOME = Path("unused-guard-home")


def _resident_unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
    raise NativeHookDecisionError("resident unavailable")


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
    monkeypatch.setattr(hook_fail_closed, "native_review_response", _resident_unavailable)
    monkeypatch.setattr(hook_fail_closed, "native_render_recording_only_pre_tool", lambda *_a, **_k: None)
    allowed = {"decision": "allow", "policy_action": "allow"}
    assert render_pre_tool("pi", allowed)["decision"] == "deny"
    assert render_pre_tool_review("codex", allowed, approval=None, guard_home=_HOME)["policy_action"] == "block"
    assert render_recording_only_pre_tool("pi", reason_code="x", reason="y")["decision"] == "deny"


def test_resident_response_is_returned_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def render(harness: str, verdict: object, *, guard_home: object = None) -> dict[str, object]:
        seen.update(harness=harness, verdict=verdict)
        return {"decision": "allow", "from": "resident"}

    monkeypatch.setattr(hook_fail_closed, "native_render_pre_tool", render)
    assert render_pre_tool("pi", {"decision": "allow"}) == {"decision": "allow", "from": "resident"}
    assert seen == {"harness": "pi", "verdict": {"decision": "allow"}}


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


def test_paused_review_asks_the_resident_with_the_link_fields_only(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, object, object]] = []

    def respond(kind: str, inputs: object, *, guard_home: object, deadline: object = None) -> dict[str, object]:
        seen.append((kind, inputs, guard_home))
        return {"decision": "deny", "from": "resident"}

    monkeypatch.setattr(hook_fail_closed, "native_review_response", respond)
    approval = {"approval_url": "http://127.0.0.1/a", "request_id": "r", "status": "pending"}
    rendered = render_pre_tool_review("pi", {"reason": "needs review"}, approval=approval, guard_home=_HOME)
    assert rendered == {"decision": "deny", "from": "resident"}
    assert seen == [
        (
            "paused_review",
            {
                "harness": "pi",
                "verdict": {"reason": "needs review"},
                "approval": {"approval_url": "http://127.0.0.1/a", "request_id": "r"},
                "guard_home": str(_HOME),
            },
            _HOME,
        )
    ]


@pytest.mark.parametrize("harness", ["omp", "codex"])
def test_blocking_verdict_keeps_its_reason_when_render_fails(monkeypatch: pytest.MonkeyPatch, harness: str) -> None:
    monkeypatch.setattr(hook_fail_closed, "native_render_pre_tool", lambda *_a, **_k: None)
    verdict = {
        "decision": "deny",
        "minimum_action": "require-reapproval",
        "reason": "Copying .env needs a fresh approval.",
        "reason_code": "native_policy_reapproval_required",
    }
    rendered = render_pre_tool(harness, verdict)
    assert rendered["policy_action"] == "block"
    assert rendered["reason_code"] == "native_policy_reapproval_required"
    assert "Copying .env needs a fresh approval." in str(rendered)


def test_review_render_failure_keeps_the_verdict_reason_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hook_fail_closed, "native_review_response", _resident_unavailable)
    verdict = {"decision": "deny", "reason": "Needs review.", "reason_code": "native_pre_tool_review"}
    approval = {"approval_url": "http://127.0.0.1/a", "request_id": "r"}
    rendered = render_pre_tool_review("omp", verdict, approval=approval, guard_home=_HOME)
    assert rendered["decision"] == "deny"
    assert rendered["reason_code"] == "native_pre_tool_review"
    assert rendered["reason"] == "Needs review."


def test_allow_verdict_that_failed_to_render_keeps_the_unavailable_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hook_fail_closed, "native_render_pre_tool", lambda *_a, **_k: None)
    rendered = render_pre_tool(
        "omp", {"decision": "allow", "minimum_action": "allow", "reason_code": "native_allow", "reason": "fine"}
    )
    assert rendered["decision"] == "deny"
    assert rendered["reason_code"] == "native_hook_render_unavailable"
    assert rendered["reason"] == "HOL Guard could not complete native review safely."


def test_allow_decision_over_a_blocking_floor_keeps_the_verdict_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hook_fail_closed, "native_render_pre_tool", lambda *_a, **_k: None)
    verdict = {
        "decision": "allow",
        "minimum_action": "require-reapproval",
        "reason_code": "native_policy_reapproval_required",
        "reason": "Copying .env needs a fresh approval.",
    }
    rendered = render_pre_tool("omp", verdict)
    assert rendered["decision"] == "deny"
    assert rendered["reason_code"] == "native_policy_reapproval_required"
    assert rendered["reason"] == "Copying .env needs a fresh approval."


def test_a_reason_that_looks_like_a_placeholder_is_sent_verbatim() -> None:
    rendered = fail_closed_pre_tool("pi", reason="$reason_code", reason_code="$reason")
    assert rendered["reason"] == "$reason_code"
    assert rendered["reason_code"] == "$reason"


def test_every_event_kind_answers_from_the_shared_contract() -> None:
    assert hook_fail_closed.fail_closed_response("grok", "Stop") == {}
    assert hook_fail_closed.fail_closed_response("codex", "beforeShellExecution")["policy_action"] == "block"
    assert hook_fail_closed.fail_closed_response("copilot", "userPromptSubmitted", prompt_reason="Paused.") == {
        "behavior": "deny",
        "message": "Paused.",
        "interrupt": False,
        "policy_action": "block",
        "reason_code": "native_prompt_unavailable",
    }
    assert hook_fail_closed.fail_closed_response("claude_code", "Notification")["hookSpecificOutput"] == {
        "hookEventName": "Notification"
    }
    assert hook_fail_closed.unmanaged_passthrough("OMP") == {"decision": "allow", "reason_code": "harness_not_managed"}


def test_review_render_failure_drops_a_raw_approval_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fixed deny carries no signed link, so it carries no raw link either."""

    monkeypatch.setattr(hook_fail_closed, "native_review_response", _resident_unavailable)
    url = "http://127.0.0.1:8765/approvals/r"
    verdict = {
        "decision": "deny",
        "reason": f"Needs review. Open HOL Guard to approve or keep this blocked: {url}.",
        "reason_code": "native_pre_tool_review",
    }
    rendered = render_pre_tool_review("omp", verdict, approval={"approval_url": url}, guard_home=_HOME)
    assert rendered["decision"] == "deny"
    assert rendered["reason_code"] == "native_pre_tool_review"
    # The separator that introduced the link goes with it, the way the resident
    # strips the same text: no "keep this blocked: ." is left for the agent.
    assert rendered["reason"] == "Needs review. Open HOL Guard to approve or keep this blocked."


def test_silent_block_fallback_drops_a_raw_approval_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hook_fail_closed, "native_review_response", _resident_unavailable)
    url = "http://127.0.0.1:8765/approvals/r"
    inputs = {
        "harness": "pi",
        "result": {"reason": f"Blocked. Approve it at {url}.", "reason_code": "native_package_review"},
        "approval_url": url,
        "request_id": "r",
        "retry_reuses_approval": True,
    }
    rendered = render_silent_review_block("pi", inputs, guard_home=_HOME)
    assert rendered["policy_action"] == "block"
    assert rendered["prompted"] is False
    assert rendered["approval_resume"] == {"request_id": "r", "poll_path": "/v1/requests/r"}
    assert url not in str(rendered)


def test_silent_block_fallback_keeps_the_safe_alternative_guidance(monkeypatch: pytest.MonkeyPatch) -> None:
    """An outage must not hand the agent the bare native reason.

    The native text says what Guard stopped and offers an inbox approval. On its
    own it never tells the agent to stop retrying, and here no approval is waiting
    at all, so the fallback composes the same reason the resident would have.
    """

    monkeypatch.setattr(hook_fail_closed, "native_review_response", _resident_unavailable)
    inputs = {
        "harness": "pi",
        "result": {"reason": "HOL Guard requires review before this action.", "reason_code": "native_network_review"},
        "queued": False,
        "retry_reuses_approval": False,
    }
    reason = str(render_silent_review_block("pi", inputs, guard_home=_HOME)["reason"])
    assert reason.startswith("HOL Guard requires review before this action.")
    assert "This makes a network request that Guard has not seen before." in reason
    assert "No approval is waiting in HOL Guard for this action." in reason
    assert "Do not retry the same action" in reason


def test_silent_block_fallback_does_not_send_the_agent_to_an_approval_that_cannot_help(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A queued row bound to neither the retry nor an exact-action Always."""

    monkeypatch.setattr(hook_fail_closed, "native_review_response", _resident_unavailable)
    inputs = {
        "harness": "pi",
        "result": {
            "reason": (
                "HOL Guard requires review before this action."
                " Approve it in the HOL Guard inbox (choose Always for a repeated read-only command),"
                " or split it into simpler commands."
            ),
            "reason_code": "native_command_review_required",
        },
        "queued": True,
        "request_id": "r",
        "retry_reuses_approval": False,
        "exact_action_allowable": False,
    }
    reason = str(render_silent_review_block("pi", inputs, guard_home=_HOME)["reason"])
    assert "Approve it in the HOL Guard inbox" not in reason
    assert "approving it there will not let you run it" in reason


def test_silent_block_fallback_uses_the_connector_setup_text(monkeypatch: pytest.MonkeyPatch) -> None:
    """A queued setup review reads as a setup review, not as the raw native reason."""

    monkeypatch.setattr(hook_fail_closed, "native_review_response", _resident_unavailable)
    setup_reason = "HOL Guard has not been set up for `ripgrep` (local CLI) on this device."
    inputs = {
        "harness": "pi",
        "result": {
            "reason": "HOL Guard requires review before this action.",
            "reason_code": "native_command_review_required",
        },
        "setup_reason": setup_reason,
        "queued": True,
        "request_id": "r",
        "retry_reuses_approval": True,
    }
    assert render_silent_review_block("pi", inputs, guard_home=_HOME)["reason"] == setup_reason


def test_silent_block_fallback_drops_the_setup_text_when_nothing_was_queued(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A review that never reached the inbox has no setup row to point at."""

    monkeypatch.setattr(hook_fail_closed, "native_review_response", _resident_unavailable)
    inputs = {
        "harness": "pi",
        "result": {"reason": "HOL Guard requires review before this action.", "reason_code": "native_network_review"},
        "setup_reason": "HOL Guard has not been set up for `ripgrep` (local CLI) on this device.",
        "queued": False,
        "retry_reuses_approval": True,
    }
    reason = str(render_silent_review_block("pi", inputs, guard_home=_HOME)["reason"])
    assert "has not been set up" not in reason
    assert "No approval is waiting in HOL Guard for this action." in reason


def test_silent_block_fallback_falls_back_to_the_shared_blocked_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A native result with no reason of its own still reads as a block."""

    monkeypatch.setattr(hook_fail_closed, "native_review_response", _resident_unavailable)
    inputs = {"harness": "pi", "result": {"reason": "", "reason_code": ""}, "queued": False}
    reason = str(render_silent_review_block("pi", inputs, guard_home=_HOME)["reason"])
    assert reason.startswith("HOL Guard blocked this action.")
