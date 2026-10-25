"""Claude Code's permission-dialog verdict comes from the resident.

The CLI hook gathers the notice and, only when asked, the artifact policy; the
resident picks the verdict (``claude_permission_verdict``) and the CLI renders
it. The vectors are the retired Python ladder, frozen in
``scripts/ci/record_claude_permission_verdict_vectors.py`` and replayed through
the resident by ``hook_decision_claude_permission_verdict_tests.rs``.
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_claude_permission_verdict as verdict_module
from codex_plugin_scanner.guard.cli import commands_hook_native_claude as claude_module
from codex_plugin_scanner.guard.cli import commands_hook_native_route_handlers as handlers
from codex_plugin_scanner.guard.native_claude_permission_verdict import (
    ARTIFACT_POLICY_FACT,
    HOOK_DECISION_CLAUDE_PERMISSION_VERDICT_FEATURE,
    ClaudePermissionVerdict,
    native_claude_permission_verdict,
)
from codex_plugin_scanner.guard.native_hook_artifact_compose import NativeHookComposeError
from codex_plugin_scanner.guard.native_hook_decision import _INVALID, NativeHookDecisionError

ROOT = Path(__file__).resolve().parents[1]
RECORDER = ROOT / "scripts/ci/record_claude_permission_verdict_vectors.py"
FIXTURE = ROOT / "rust/crates/guard-runtime/tests/fixtures/claude_permission_verdict_vectors.json"


def _recorder() -> Any:
    spec = importlib.util.spec_from_file_location("record_claude_permission_verdict_vectors", RECORDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _vectors() -> list[dict[str, Any]]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_the_frozen_ladder_still_reproduces_the_fixture() -> None:
    recorder = _recorder()
    assert FIXTURE.read_text(encoding="utf-8") == recorder.render(recorder.record())


def _resident_from_vectors(monkeypatch: pytest.MonkeyPatch, sent: list[dict[str, Any]]) -> None:
    """A resident that answers each query the way the recorded ladder did."""

    vectors = _vectors()

    def decide(query: dict[str, Any], _home: object, validate: Any, feature: str) -> dict[str, Any]:
        assert feature == HOOK_DECISION_CLAUDE_PERMISSION_VERDICT_FEATURE
        assert query["kind"] == "claude_permission_verdict"
        inputs = query["inputs"]
        sent.append(inputs)
        matches = [
            vector
            for vector in vectors
            if vector["inputs"]["notice"] == inputs["notice"]
            and vector["inputs"]["runtime_artifact_present"] == inputs["runtime_artifact_present"]
            and (inputs["artifact_policy"] is None or vector["artifact_policy"] == inputs["artifact_policy"])
        ]
        assert matches
        if inputs["artifact_policy"] is None and matches[0]["artifact_policy"] is not None:
            payload = {"kind": "claude_permission_verdict", "needs_facts": [ARTIFACT_POLICY_FACT], "verdict": None}
        else:
            assert len(matches) == 1
            payload = {"kind": "claude_permission_verdict", "needs_facts": [], "verdict": matches[0]["verdict"]}
        validate(payload)
        return payload

    monkeypatch.setattr(verdict_module, "_decide", decide)


@pytest.mark.parametrize("index", range(len(_vectors())))
def test_the_glue_asks_for_the_artifact_policy_only_when_the_resident_needs_it(
    monkeypatch: pytest.MonkeyPatch, index: int
) -> None:
    vector = _vectors()[index]
    sent: list[dict[str, Any]] = []
    gathered: list[int] = []
    _resident_from_vectors(monkeypatch, sent)

    def artifact_policy() -> dict[str, Any]:
        gathered.append(1)
        return vector["artifact_policy"]

    answer = native_claude_permission_verdict(
        notice=vector["inputs"]["notice"],
        runtime_artifact_present=vector["inputs"]["runtime_artifact_present"],
        artifact_policy=artifact_policy,
    )
    assert answer == ClaudePermissionVerdict(**vector["verdict"])
    assert len(gathered) == (vector["artifact_policy"] is not None)
    assert len(sent) == 1 + len(gathered)


def test_every_review_verdict_offers_a_way_to_approve() -> None:
    """Approval invariant: review defers to Claude's dialog, guard_question to
    the Guard approval question; only block and sandbox-required deny."""

    seen = set()
    for vector in _vectors():
        verdict = vector["verdict"]
        seen.add(verdict["verdict"])
        if verdict["verdict"] in {"review", "guard_question"}:
            assert verdict["offers_approval"] is True
        elif verdict["verdict"] == "deny":
            assert verdict["policy_action"] in {"block", "sandbox-required"}
        else:
            assert verdict["verdict"] == "passthrough"
            assert verdict["policy_action"] is None
    assert seen == {"passthrough", "guard_question", "review", "deny"}


_REVIEW = {
    "verdict": "review",
    "policy_action": "require-reapproval",
    "offers_approval": True,
    "reason": "HOL Guard is reviewing this Claude approval prompt.",
    "reason_from_artifact": False,
    "artifact_action": None,
}


_DENY = {**_REVIEW, "verdict": "deny", "policy_action": "block", "offers_approval": False}


def _answering(monkeypatch: pytest.MonkeyPatch, *payloads: dict[str, Any]) -> None:
    replies = list(payloads)

    def decide(_query: object, _home: object, validate: Any, _feature: str) -> dict[str, Any]:
        payload = replies.pop(0)
        validate(payload)
        return payload

    monkeypatch.setattr(verdict_module, "_decide", decide)


def _ok(verdict: dict[str, Any] | None, needs: list[str] | None = None) -> dict[str, Any]:
    return {"kind": "claude_permission_verdict", "needs_facts": needs or [], "verdict": verdict}


@pytest.mark.parametrize(
    ("payloads", "present"),
    [
        # A verdict whose shape does not match its kind.
        ((_ok({**_REVIEW, "offers_approval": False}),), False),
        ((_ok({**_REVIEW, "policy_action": "block"}),), False),
        ((_ok({**_REVIEW, "verdict": "deny"}),), False),
        ((_ok({**_REVIEW, "verdict": "guard_question"}),), False),
        ((_ok({**_REVIEW, "verdict": "allow"}),), False),
        ((_ok({**_REVIEW, "reason": None}),), False),
        ((_ok({**_REVIEW, "verdict": "passthrough", "policy_action": None, "offers_approval": False}),), False),
        # The artifact's reason without its policy having been sent.
        ((_ok({**_REVIEW, "reason_from_artifact": True, "artifact_action": "review"}),), True),
        ((_ok({**_REVIEW, "reason_from_artifact": True}),), True),
        # Extra or missing fields.
        ((_ok({**_REVIEW, "reason_code": "x"}),), False),
        (({"kind": "claude_permission_verdict", "verdict": _REVIEW},), False),
        # Asking for facts it cannot be given, or asking twice.
        ((_ok(None, [ARTIFACT_POLICY_FACT]),), False),
        ((_ok(None, ["notice"]),), True),
        ((_ok(None, [ARTIFACT_POLICY_FACT]), _ok(None, [ARTIFACT_POLICY_FACT])), True),
        ((_ok(None),), False),
        # An artifact action that contradicts the verdict it is rendered with.
        (
            (
                _ok(None, [ARTIFACT_POLICY_FACT]),
                _ok({**_REVIEW, "reason_from_artifact": True, "artifact_action": "block"}),
            ),
            True,
        ),
        (
            (
                _ok(None, [ARTIFACT_POLICY_FACT]),
                _ok({**_DENY, "reason_from_artifact": True, "artifact_action": "review"}),
            ),
            True,
        ),
        (
            (
                _ok(None, [ARTIFACT_POLICY_FACT]),
                _ok({**_DENY, "reason_from_artifact": True, "artifact_action": "sandbox-required"}),
            ),
            True,
        ),
    ],
)
def test_a_malformed_resident_answer_raises(
    monkeypatch: pytest.MonkeyPatch, payloads: tuple[dict[str, Any], ...], present: bool
) -> None:
    _answering(monkeypatch, *payloads)
    with pytest.raises(NativeHookDecisionError) as raised:
        native_claude_permission_verdict(
            notice=None,
            runtime_artifact_present=present,
            artifact_policy=lambda: {"config_action": "review", "package_action": None},
        )
    assert raised.value.code == _INVALID


class _Rendered:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, notice: dict[str, Any] | None) -> None:
        self.responses: list[dict[str, Any]] = []
        self.stderr: list[str] = []
        self.passthrough = 0
        self.gathered = 0
        self.stubs: list[dict[str, Any]] = []
        self.marked: list[object] = []
        patch = monkeypatch.setattr
        patch(claude_module, "_peek_claude_permission_notice", lambda _store, _payload: notice)
        patch(claude_module, "_mark_claude_pending_permission_prompt_seen", lambda **kw: self.marked.append(kw))
        patch(claude_module, "_emit_native_hook_response", lambda **kw: self.responses.append(kw))
        patch(claude_module, "_emit_native_hook_notification_stderr", self.stderr.append)
        patch(claude_module, "_emit_claude_permission_request_passthrough", self._passthrough)
        patch(claude_module, "_claude_permission_prompt_system_message", lambda **_kw: "prompt-system")
        patch(claude_module, "_claude_guard_approval_question_message", lambda _notice: "guard-question")
        patch(claude_module, "_claude_permission_request_system_message", lambda **kw: f"sys:{kw['native_reason']}")
        patch(claude_module, "_claude_permission_request_additional_context", lambda reason: f"ctx:{reason}")
        patch(claude_module, "_claude_permission_request_terminal_notice", lambda **kw: f"tty:{kw['native_reason']}")
        patch(claude_module, "_claude_permission_request_artifact_policy", self._policy)
        patch(claude_module, "_claude_permission_request_reason_stub", self._stub)

    def _passthrough(self, **_kwargs: object) -> None:
        self.passthrough += 1

    def _policy(self, **_kwargs: object) -> tuple[dict[str, Any], object]:
        self.gathered += 1
        return {"config_action": "block", "package_action": None}, "evaluation"

    def _stub(self, **kwargs: Any) -> dict[str, Any]:
        self.stubs.append(kwargs)
        return {"policy_action": kwargs["artifact_action"]}


def _run(monkeypatch: pytest.MonkeyPatch, answer: ClaudePermissionVerdict, *, artifact: object = None) -> int:
    def verdict(*, artifact_policy: Any, **_kwargs: object) -> ClaudePermissionVerdict:
        if answer.reason_from_artifact:
            artifact_policy()
        return answer

    monkeypatch.setattr(claude_module, "native_claude_permission_verdict", verdict)
    return claude_module.run_native_claude_permission_request(
        argparse.Namespace(harness="claude-code"),
        config=SimpleNamespace(),  # type: ignore[arg-type]
        output_stream=io.StringIO(),
        payload={"session_id": "s"},
        runtime_artifact=artifact,  # type: ignore[arg-type]
        runtime_workspace=None,
        store=SimpleNamespace(guard_home=None),  # type: ignore[arg-type]
    )


def test_passthrough_renders_no_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    rendered = _Rendered(monkeypatch, notice=None)
    answer = ClaudePermissionVerdict("passthrough", None, False, None, False, None)
    assert _run(monkeypatch, answer) == 0
    assert (rendered.passthrough, rendered.responses, rendered.stderr) == (1, [], [])


def test_guard_question_sends_claude_to_the_guard_approval_question(monkeypatch: pytest.MonkeyPatch) -> None:
    notice = {"artifact_type": "tool_action_request"}
    rendered = _Rendered(monkeypatch, notice=notice)
    reason = "HOL Guard is routing this approval through AskUserQuestion."
    assert _run(monkeypatch, ClaudePermissionVerdict("guard_question", "block", True, reason, False, None)) == 0
    assert len(rendered.marked) == 1
    assert rendered.stderr == []
    assert rendered.responses == [
        {
            "harness": "claude-code",
            "policy_action": "block",
            "event_name": "PermissionRequest",
            "reason": reason,
            "system_message": "prompt-system",
            "additional_context": "guard-question",
            "output_stream": rendered.responses[0]["output_stream"],
        }
    ]


@pytest.mark.parametrize(("verdict", "action"), [("review", "require-reapproval"), ("deny", "sandbox-required")])
def test_review_and_deny_render_the_resident_reason(monkeypatch: pytest.MonkeyPatch, verdict: str, action: str) -> None:
    rendered = _Rendered(monkeypatch, notice={"artifact_type": "package_request"})
    answer = ClaudePermissionVerdict(verdict, action, verdict == "review", "Notice reason.", False, None)
    assert _run(monkeypatch, answer) == 0
    assert rendered.stderr == ["tty:Notice reason."]
    (response,) = rendered.responses
    assert response["policy_action"] == action
    assert response["reason"] == "Notice reason."
    assert response["system_message"] == "sys:Notice reason."
    assert response["additional_context"] == "ctx:Notice reason."
    assert rendered.gathered == 0


@pytest.mark.parametrize(("rendered_reason", "shown"), [("Artifact reason.", "Artifact reason."), ("  ", "Fallback.")])
def test_the_artifact_reason_is_rendered_with_the_resident_action(
    monkeypatch: pytest.MonkeyPatch, rendered_reason: str, shown: str
) -> None:
    rendered = _Rendered(monkeypatch, notice=None)
    monkeypatch.setattr(claude_module, "_runtime_artifact_native_reason", lambda *_a, **_kw: rendered_reason)
    answer = ClaudePermissionVerdict("review", "require-reapproval", True, "Fallback.", True, "review")
    assert _run(monkeypatch, answer, artifact=object()) == 0
    assert rendered.gathered == 1
    (stub,) = rendered.stubs
    assert stub["artifact_action"] == "review"
    assert stub["package_evaluation"] == "evaluation"
    (response,) = rendered.responses
    assert (response["policy_action"], response["reason"]) == ("require-reapproval", shown)


@pytest.mark.parametrize(
    "error",
    [
        NativeHookDecisionError("native_hook_decision_unavailable"),
        # The artifact policy and reason are composed by the resident too.
        NativeHookComposeError("native_hook_decision_unavailable"),
    ],
    ids=("verdict", "composition"),
)
def test_a_verdict_the_resident_cannot_supply_is_the_host_outage(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    rendered = _Rendered(monkeypatch, notice={"artifact_type": "tool_action_request"})

    def outage(**_kwargs: object) -> ClaudePermissionVerdict:
        raise error

    monkeypatch.setattr(claude_module, "native_claude_permission_verdict", outage)
    unavailable: list[str] = []

    def record(code: str) -> int:
        unavailable.append(code)
        return 7

    run = SimpleNamespace(
        args=argparse.Namespace(harness="claude-code"),
        config=SimpleNamespace(),
        output_stream=io.StringIO(),
        payload={"session_id": "s"},
        runtime_artifact=None,
        runtime_workspace=None,
        store=SimpleNamespace(guard_home=None),
        unavailable=record,
    )
    assert handlers.claude_permission_request(run) == 7  # type: ignore[arg-type]
    assert unavailable == ["native_hook_decision_unavailable"]
    assert (rendered.responses, rendered.stderr, rendered.passthrough) == ([], [], 0)
