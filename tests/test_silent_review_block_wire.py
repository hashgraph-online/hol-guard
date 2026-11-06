"""The silent review block, asked of the resident through ``HookDecide``.

The resident composes the block a native PreToolUse review shows the agent when
the user is not asked: the reason, the wait hint, the review link and the
rendered response. These pin the transport: the facts it sends, the reply it
accepts, and that anything else fails closed the way ``render_pre_tool`` does.
The composed text is tested in ``hook_decision_review_response_tests.rs``.
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_decision as decision_module
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.blocked_request_mode import safe_alternative_reason
from codex_plugin_scanner.guard.daemon import hook_fail_closed
from codex_plugin_scanner.guard.native_hook_decision import NativeHookDecisionError, native_review_response

_URL = "http://127.0.0.1:4781/requests/abc"
_RESULT = {
    "decision": "review",
    "minimum_action": "review",
    "policy_action": "review",
    "reason": "HOL Guard requires review before this action can execute.",
    "reason_code": "native_shell_review",
}
_RESPONSE = {"decision": "deny", "prompted": False, "blocked_request_mode": "safe-alternative"}


def _resident_answering(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any], asked: list[Any]) -> None:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(
            features={"resident-protocol-v2", decision_module.HOOK_DECISION_REVIEW_RESPONSE_FEATURE}
        ),
    )
    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/hook-decision-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)

    def transport(*, request: dict[str, Any], required_feature: str, **_kwargs: object) -> dict[str, Any]:
        asked.append((required_feature, request["query"]))
        return {
            "schema": "guard-hook-decision-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }

    monkeypatch.setattr(decision_module, "_resident_request", transport)


def _inputs(**changes: object) -> dict[str, Any]:
    return {
        "harness": "codex",
        "result": _RESULT,
        "setup_reason": None,
        "queued": True,
        "request_id": "abc",
        "approval_url": _URL,
        "ask": False,
        "retry_reuses_approval": True,
        "exact_action_allowable": False,
        "connector_is_local": False,
        "guard_home": "/home/dev/.hol-guard",
        "home_dir": "/home/dev",
        **changes,
    }


def _ask(deadline: float | None = None, **changes: object) -> dict[str, Any]:
    return native_review_response(
        "silent_review_block", _inputs(**changes), guard_home=Path("/home/dev/.hol-guard"), deadline=deadline
    )


def test_the_facts_are_sent_behind_their_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[Any] = []
    _resident_answering(monkeypatch, {"kind": "silent_review_block", "response": _RESPONSE}, asked)

    assert _ask(setup_reason="Set up lanectl.", connector_is_local=True) == _RESPONSE
    assert asked == [
        (
            decision_module.HOOK_DECISION_REVIEW_RESPONSE_FEATURE,
            {
                "kind": "silent_review_block",
                "inputs": {
                    "harness": "codex",
                    "result": _RESULT,
                    "setup_reason": "Set up lanectl.",
                    "queued": True,
                    "request_id": "abc",
                    "approval_url": _URL,
                    "ask": False,
                    "retry_reuses_approval": True,
                    "exact_action_allowable": False,
                    "connector_is_local": True,
                    "guard_home": "/home/dev/.hol-guard",
                    "home_dir": "/home/dev",
                },
            },
        )
    ]


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "silent_review_block", "response": "deny"},
        {"kind": "silent_review_block"},
        {"kind": "silent_review_block", "response": {}, "extra": True},
        {"kind": "containment_route", "route": "none"},
    ],
)
def test_a_malformed_block_is_an_outage_not_a_block(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]) -> None:
    _resident_answering(monkeypatch, payload, [])

    with pytest.raises(NativeHookDecisionError):
        _ask()


def test_a_spent_deadline_never_asks(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[Any] = []
    _resident_answering(monkeypatch, {"kind": "silent_review_block", "response": _RESPONSE}, asked)

    with pytest.raises(NativeHookDecisionError, match="native_hook_decision_unavailable"):
        _ask(deadline=time.monotonic() - 1)
    assert asked == []


@pytest.mark.parametrize(("retry", "resumed"), [(True, True), (False, False)])
def test_no_answer_fails_closed_like_render_pre_tool(
    monkeypatch: pytest.MonkeyPatch, retry: bool, resumed: bool
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> dict[str, Any]:
        raise NativeHookDecisionError("native_hook_decision_unavailable")

    monkeypatch.setattr(hook_fail_closed, "native_review_response", unavailable)
    response = hook_fail_closed.render_silent_review_block(
        "codex", _inputs(retry_reuses_approval=retry), guard_home=Path("/home/dev/.hol-guard")
    )

    blocked = {
        **_RESULT,
        "decision": "deny",
        "minimum_action": "block",
        "policy_action": "block",
        # The resident is what is unavailable here, so the fallback composes the
        # agent text itself from the same shared formatter the resident reads.
        "reason": safe_alternative_reason(
            _RESULT["reason"],
            reason_code=_RESULT["reason_code"],
            approval_queued=True,
            retry_reuses_approval=retry,
            exact_action_allowable=False,
        ),
    }
    expected = {
        **hook_fail_closed._verdict_deny("codex", blocked),
        "prompted": False,
        "blocked_request_mode": "safe-alternative",
    }
    if resumed:
        expected["approval_resume"] = {"request_id": "abc", "poll_path": "/v1/requests/abc"}
    assert response == expected
    assert _URL not in str(response)
