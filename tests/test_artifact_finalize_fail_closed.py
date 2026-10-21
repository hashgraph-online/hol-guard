"""Fail closed: nothing is persisted for a verdict the harness never received.

A resident that cannot answer the final-action settle or the browser outcome
leaves no receipt, no observe-mode queue record and no silent inbox record, and
the hook answers with its outage response.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_hook_decision as decision
from codex_plugin_scanner.guard.cli import commands_hook_native_finish as finish
from codex_plugin_scanner.guard.cli import commands_hook_native_review as review
from codex_plugin_scanner.guard.cli import commands_hook_native_silent_review as silent_review
from codex_plugin_scanner.guard.cli import commands_hook_native_state as state_module
from tests.artifact_finalize_support import (
    load_recorder,
    load_vectors,
    plan_state,
    resident_stub,
    settle_reply,
    stub_renderers,
    unavailable,
    vector_key,
)


def test_a_browser_approval_the_resident_cannot_settle_leaves_no_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    effects: list[str] = []
    monkeypatch.setattr(finish, "_browser_approval_decision", lambda *_a, **_k: "allow")
    monkeypatch.setattr(
        finish,
        "native_artifact_browser_outcome",
        lambda *_a, **_k: {
            "settle": True,
            "action": "allow",
            "approval_source": "browser",
            "emit_native_allow": True,
            "finish_without_render": True,
        },
    )
    monkeypatch.setattr(state_module, "native_artifact_finalize", unavailable)
    monkeypatch.setattr(finish, "record_native_artifact_hook_receipt", lambda *_a, **_k: effects.append("receipt"))
    monkeypatch.setattr(finish, "_record_harness_usage_for_hook", lambda **_k: effects.append("usage"))
    monkeypatch.setattr(finish, "_emit_native_hook_response", lambda **_k: effects.append("native_allow"))
    state = plan_state()
    with pytest.raises(decision.NativeHookDecisionError):
        finish.finalize_native_artifact_hook(
            state,  # type: ignore[arg-type]
            SimpleNamespace(harness="codex", json=False),  # type: ignore[arg-type]
            config=None,  # type: ignore[arg-type]
            payload={},
            store=SimpleNamespace(guard_home=None),  # type: ignore[arg-type]
        )
    assert effects == []
    assert state.policy_action == "review"


def test_a_browser_outcome_the_resident_cannot_judge_settles_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    effects: list[str] = []
    monkeypatch.setattr(finish, "_browser_approval_decision", lambda *_a, **_k: "allow")
    monkeypatch.setattr(finish, "native_artifact_browser_outcome", unavailable)
    monkeypatch.setattr(finish, "set_native_artifact_hook_final_action", lambda *_a, **_k: effects.append("settle"))
    monkeypatch.setattr(finish, "record_native_artifact_hook_receipt", lambda *_a, **_k: effects.append("receipt"))
    monkeypatch.setattr(finish, "_emit_native_hook_response", lambda **_k: effects.append("native_allow"))
    with pytest.raises(decision.NativeHookDecisionError):
        finish.finalize_native_artifact_hook(
            plan_state(),  # type: ignore[arg-type]
            SimpleNamespace(harness="codex", json=False),  # type: ignore[arg-type]
            config=None,  # type: ignore[arg-type]
            payload={},
            store=SimpleNamespace(guard_home=None),  # type: ignore[arg-type]
        )
    assert effects == []


def test_a_watch_mode_settle_the_resident_cannot_give_queues_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    effects: list[str] = []
    monkeypatch.setattr(review, "_observe_mode_executable_action", lambda _state: "allow")
    monkeypatch.setattr(review, "queue_observe_mode_request", lambda **_k: effects.append("queue"))
    monkeypatch.setattr(state_module, "native_artifact_finalize", unavailable)
    state = plan_state()
    state.browser_approval_daemon_client = "client"
    with pytest.raises(decision.NativeHookDecisionError):
        review._record_observed_review(
            state,  # type: ignore[arg-type]
            config=SimpleNamespace(receipt_redaction_level="summary"),  # type: ignore[arg-type]
            store=None,  # type: ignore[arg-type]
        )
    assert effects == []
    assert state.policy_action == "review"
    assert state.browser_approval_daemon_client == "client"


def test_a_watch_mode_settle_is_planned_before_the_record_and_applied_after(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = load_recorder()
    order: list[str] = []
    stub_renderers(monkeypatch, recorder)
    monkeypatch.setattr(review, "_observe_mode_executable_action", lambda _state: "allow")
    monkeypatch.setattr(review, "queue_observe_mode_request", lambda **_k: order.append("queue"))
    plan = review.plan_native_artifact_hook_final_action
    apply = review.apply_native_artifact_hook_final_action
    monkeypatch.setattr(
        review, "plan_native_artifact_hook_final_action", lambda *a, **k: order.append("plan") or plan(*a, **k)
    )
    monkeypatch.setattr(
        review, "apply_native_artifact_hook_final_action", lambda *a, **k: order.append("apply") or apply(*a, **k)
    )
    data = load_vectors()
    vectors = {vector_key(vector["facts"]): vector for vector in data["settle"]}
    resident_stub(monkeypatch, lambda query: settle_reply(vectors[vector_key(query["inputs"])]))
    state = recorder.SettleCase(
        previous_action="review", policy_action="allow", observed_policy_action="review"
    ).state()
    state.browser_approval_daemon_client = "client"
    state.runtime_artifact_hash = "hash"
    review._record_observed_review(
        state,  # type: ignore[arg-type]
        config=SimpleNamespace(receipt_redaction_level="summary"),  # type: ignore[arg-type]
        store=None,  # type: ignore[arg-type]
    )
    assert order == ["plan", "queue", "apply"]
    assert state.policy_action == "allow"
    assert state.response_payload["observed_policy_action"] == "review"
    assert state.browser_approval_daemon_client is None


@pytest.mark.parametrize("kind", ["silent_review", "silent_block"])
def test_a_silent_denial_the_resident_cannot_settle_leaves_nothing_on_file(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    recorded: list[str] = []
    monkeypatch.setattr(silent_review, "record_unprompted_review", lambda **_k: recorded.append("inbox"))
    monkeypatch.setattr(silent_review, "_runtime_detection", lambda *_a: SimpleNamespace())
    monkeypatch.setattr(silent_review, "_runtime_request_summary", lambda _artifact: "summary")
    monkeypatch.setattr(silent_review, "_action_envelope_json", lambda _envelope: None)
    monkeypatch.setattr(state_module, "native_artifact_finalize", unavailable)
    state = plan_state()
    state.approval_prompted = None
    with pytest.raises(decision.NativeHookDecisionError):
        silent_review.apply_unprompted_native_review(
            state,  # type: ignore[arg-type]
            SimpleNamespace(harness="codex"),  # type: ignore[arg-type]
            None,  # type: ignore[arg-type]
            SimpleNamespace(receipt_redaction_level="summary"),  # type: ignore[arg-type]
            {"route": kind, "silent_review": {"action": "review", "reason": "Lead."}},
        )
    assert recorded == []
    assert state.policy_action == "review"
    assert state.approval_prompted is None
