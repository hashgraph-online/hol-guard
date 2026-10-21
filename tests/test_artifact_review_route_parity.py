"""The artifact hook executes the resident's review route as Python's ladder ran it.

``scripts/ci/record_artifact_review_route_vectors.py`` recorded the retired
Python branch ladder of ``review_native_artifact_hook`` with every effect
stubbed. The Rust suite replays the route fields; this suite hands each
recorded route to the new executor, with the same stubs, and checks that it
gathers the same facts, runs the same effects in the same order and returns
the same exit code. It also pins the approval invariant on the recorded
routes: a review-tier verdict keeps its approval choice unless the operator
chose not to be asked.
"""

from __future__ import annotations

import gzip
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import codex_plugin_scanner.guard.cli.commands  # noqa: F401  (wires the shared command namespace)
from codex_plugin_scanner.guard import native_hook_decision as decision
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.cli import commands_hook_native_review as review
from codex_plugin_scanner.guard.cli import commands_hook_native_silent_review as silent_review

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "rust/crates/guard-runtime/tests/fixtures/artifact_review_route_vectors.json.gz"
RECORDER = ROOT / "scripts/ci/record_artifact_review_route_vectors.py"
REVIEW_TIER = {"review", "require-reapproval"}
SILENT = {"silent_review", "silent_block"}


def _recorder() -> Any:
    spec = importlib.util.spec_from_file_location("record_artifact_review_route_vectors", RECORDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _vectors() -> list[dict[str, Any]]:
    return json.loads(gzip.decompress(VECTORS.read_bytes()))


def _key(facts: object) -> str:
    return json.dumps(facts, sort_keys=True)


def _stub_effects(
    monkeypatch: pytest.MonkeyPatch, recorder: Any, trace: list[list[object]], reasons: list[int]
) -> None:
    """Replace every effect the executor runs with an entry in ``trace``."""

    def unprompted(_state: object, _args: object, _store: object, _config: object, route: dict[str, Any]) -> None:
        silent = route["silent_review"]
        trace.append(["unprompted", route["route"] == "silent_review", silent["action"], silent["reason"]])

    def terminalize(response_payload: dict[str, object], policy_action: str, mode: str) -> None:
        real_terminalize(response_payload, policy_action, mode)
        assert response_payload["approval_requests"] == []
        assert response_payload["terminal_action"] == policy_action
        if mode == "observe":
            assert response_payload["observed_terminal_action"] == policy_action
            assert "terminal" not in response_payload
        else:
            assert response_payload["terminal"] is True
            assert response_payload["operation_status"] == "blocked"
        trace.append(["terminalize", mode])

    def native_reason(*_args: object, **_kwargs: object) -> str:
        reasons.append(1)
        return recorder.REASON

    def emit_native(**kwargs: Any) -> None:
        trace.append(
            [
                "native_response",
                kwargs["policy_action"],
                kwargs["event_name"],
                kwargs["reason"],
                recorder.system_message_kind(kwargs["system_message"]),
                recorder.additional_context_kind(kwargs["additional_context"]),
            ]
        )

    real_terminalize = review._terminalize
    monkeypatch.setattr(review, "_terminalize", terminalize)
    monkeypatch.setattr(review, "_terminalize_runtime_action_copy", lambda _payload: None)
    monkeypatch.setattr(review, "apply_unprompted_native_review", unprompted)
    monkeypatch.setattr(review, "_record_observed_review", lambda *_a, **_k: trace.append(["observe"]))
    monkeypatch.setattr(review, "_runtime_artifact_native_reason", native_reason)
    monkeypatch.setattr(
        review,
        "_record_claude_permission_notice",
        lambda **kwargs: trace.append(["claude_notice_record", kwargs["reason"]]),
    )
    monkeypatch.setattr(review, "_claude_native_pretooluse_terminal_notice", lambda *, payload, reason: reason)
    monkeypatch.setattr(
        review, "_emit_native_hook_notification_stderr", lambda text: trace.append(["claude_notice_stderr", text])
    )
    monkeypatch.setattr(review, "_emit_native_hook_response", emit_native)
    monkeypatch.setattr(review, "record_native_artifact_hook_receipt", lambda *_a, **_k: trace.append(["receipt"]))
    monkeypatch.setattr(
        review, "_record_harness_usage_for_hook", lambda **kwargs: trace.append(["usage", kwargs["policy_action"]])
    )
    monkeypatch.setattr(review, "_copilot_hook_reason", lambda *_values: "COPILOT")
    monkeypatch.setattr(
        review,
        "_emit_copilot_hook_response",
        lambda *, policy_action, **_k: trace.append(["copilot_response", policy_action]),
    )
    monkeypatch.setattr(
        review,
        "queue_native_approval",
        lambda *_a, attach_cursor_request_ids, **_k: (
            trace.append(["queue_approval", attach_cursor_request_ids]) or (None, None)
        ),
    )


def test_executor_reproduces_the_recorded_python_ladder(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _recorder()
    trace: list[list[object]] = []
    reasons: list[int] = []
    _stub_effects(monkeypatch, recorder, trace, reasons)
    vectors = {_key(vector["facts"]): vector for vector in _vectors()}
    assert len(vectors) > 20_000
    asked: list[dict[str, object]] = []
    current: list[Any] = []

    def route(inputs: dict[str, object], *, guard_home: object = None) -> dict[str, Any]:
        asked.append(dict(inputs))
        return vectors[_key(current[-1].facts())]["route"]

    monkeypatch.setattr(review, "native_artifact_review_route", route)
    monkeypatch.setattr(review, "harness_is_recording_only", lambda _config, _harness: current[-1].observe_mode)
    monkeypatch.setattr(review, "asks_for_approval", lambda _config: current[-1].asks_for_approval)

    def run(case: Any) -> tuple[list[list[object]], int | None]:
        trace.clear()
        reasons.clear()
        state = SimpleNamespace(
            action_envelope=None,
            event_name=case.event,
            guard_home=None,
            policy_action=case.action,
            response_payload={"why_now": None},
            runtime_artifact=case.artifact(),
            runtime_artifact_hash="hash",
            browser_approval_daemon_client="stale",
            browser_approval_wait_bound=True,
        )
        current.append(case)
        try:
            rc = review.review_native_artifact_hook(
                state,  # type: ignore[arg-type]
                SimpleNamespace(harness=case.harness, json=case.json),  # type: ignore[arg-type]
                config=None,  # type: ignore[arg-type]
                context=None,  # type: ignore[arg-type]
                guard_home=Path("/guard-home"),
                managed_install=None,
                output_stream=object() if case.output_stream else None,  # type: ignore[arg-type]
                payload={},
                store=None,  # type: ignore[arg-type]
                workspace=None,
            )
        finally:
            current.pop()
        assert len(reasons) <= 1, "the native reason is composed once, where a branch shows it"
        if rc is None and vectors[_key(case.facts())]["route"]["route"] in {"continue", "queue_approval"}:
            # A route that goes on to the final response leaves no browser wait bound.
            assert state.browser_approval_daemon_client is None
            assert state.browser_approval_wait_bound is None
        return [list(entry) for entry in trace], rc

    failures: list[str] = []
    replayed = 0
    for case in recorder.cases():
        replayed += 1
        expected = vectors[_key(case.facts())]
        asked.clear()
        actual = recorder.record(case, run=run)
        if asked != [case.facts()]:
            failures.append(f"{case.facts()}: asked {asked}")
        for key in ("trace", "rc"):
            if actual[key] != expected[key]:
                failures.append(f"{case.facts()}: {key} {actual[key]!r} != {expected[key]!r}")
        if len(failures) > 10:
            break
    assert failures == []
    assert replayed == len(vectors)


def test_review_tier_verdicts_keep_allow_once_and_always_allow() -> None:
    offered = 0
    for vector in _vectors():
        facts, route = vector["facts"], vector["route"]
        if facts["policy_action"] not in REVIEW_TIER or facts["observe_mode"]:
            continue
        assert route["terminalize"] == "none"
        if route["route"] in SILENT:
            assert facts["asks_for_approval"] is False, facts
            continue
        if route["route"] == "continue":
            assert facts["prompt_hard_block"] is True, facts
            continue
        offered += 1
    assert offered > 1_000


def test_terminal_verdicts_are_never_queued() -> None:
    for vector in _vectors():
        facts, route = vector["facts"], vector["route"]
        if facts["policy_action"] in {"block", "sandbox-required"}:
            assert route["route"] not in {"queue_approval", "silent_review"}, facts
        if route["route"] == "silent_review":
            assert facts["policy_action"] in REVIEW_TIER


def test_a_route_the_resident_cannot_give_stops_the_hook(monkeypatch: pytest.MonkeyPatch) -> None:
    effects: list[str] = []

    def unavailable(_inputs: dict[str, object], *, guard_home: object = None) -> dict[str, Any]:
        raise decision.NativeHookDecisionError("native_hook_decision_unavailable")

    monkeypatch.setattr(review, "native_artifact_review_route", unavailable)
    monkeypatch.setattr(review, "harness_is_recording_only", lambda *_a: False)
    monkeypatch.setattr(review, "asks_for_approval", lambda _config: True)
    monkeypatch.setattr(review, "apply_unprompted_native_review", lambda *_a: effects.append("unprompted"))
    monkeypatch.setattr(review, "queue_native_approval", lambda *_a, **_k: effects.append("queue"))
    monkeypatch.setattr(review, "_emit_native_hook_response", lambda **_k: effects.append("native"))
    state = SimpleNamespace(
        event_name="PreToolUse",
        guard_home=None,
        policy_action="require-reapproval",
        response_payload={},
        runtime_artifact=SimpleNamespace(artifact_type="tool_action_request", metadata={}),
    )
    with pytest.raises(decision.NativeHookDecisionError):
        review.review_native_artifact_hook(
            state,  # type: ignore[arg-type]
            SimpleNamespace(harness="cursor", json=False),  # type: ignore[arg-type]
            config=None,  # type: ignore[arg-type]
            context=None,  # type: ignore[arg-type]
            guard_home=Path("/guard-home"),
            managed_install=None,
            payload={},
            store=None,  # type: ignore[arg-type]
            workspace=None,
        )
    assert effects == []


def test_a_silent_review_records_the_inbox_denial_and_a_silent_block_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: list[str] = []
    monkeypatch.setattr(silent_review, "record_unprompted_review", lambda **kwargs: recorded.append("inbox"))
    monkeypatch.setattr(silent_review, "_runtime_detection", lambda *_a: SimpleNamespace())
    monkeypatch.setattr(silent_review, "_runtime_request_summary", lambda _artifact: "summary")
    monkeypatch.setattr(silent_review, "_action_envelope_json", lambda _envelope: None)
    monkeypatch.setattr(silent_review, "_terminalize_runtime_action_copy", lambda _payload: None)
    monkeypatch.setattr(silent_review, "set_native_artifact_hook_final_action", lambda *_a, **_k: None)

    def state() -> SimpleNamespace:
        return SimpleNamespace(
            action_envelope=None,
            artifact_id="artifact",
            artifact_name="name",
            approval_prompted=None,
            changed_capabilities=[],
            decision_v2_payload={},
            package_evaluation=None,
            response_payload={},
            risk_summary="Risk.",
            runtime_artifact=SimpleNamespace(artifact_type="t", source_scope="s", config_path="c"),
            runtime_artifact_hash="hash",
            scanner_evidence_payload=[],
        )

    lead = "HOL Guard blocked this action."
    for kind, action, inbox in (("silent_review", "review", ["inbox"]), ("silent_block", "block", [])):
        recorded.clear()
        review_state = state()
        silent_review.apply_unprompted_native_review(
            review_state,  # type: ignore[arg-type]
            SimpleNamespace(harness="codex"),  # type: ignore[arg-type]
            None,  # type: ignore[arg-type]
            SimpleNamespace(receipt_redaction_level="summary"),  # type: ignore[arg-type]
            {"route": kind, "silent_review": {"action": action, "reason": lead}},
        )
        assert recorded == inbox
        assert review_state.approval_prompted is False
        assert review_state.response_payload["prompted"] is False
        assert review_state.response_payload["terminal_action"] == "block"
        assert lead in review_state.response_payload["review_hint"]


_FACTS = {
    "harness": "cursor",
    "canonical_harness": "cursor",
    "event": "PreToolUse",
    "policy_action": "review",
    "artifact_type": "tool_action_request",
    "observe_mode": False,
    "asks_for_approval": True,
    "json": False,
    "output_stream_present": False,
    "prompt_hard_block": False,
    "prompt_secret_read": False,
}
_ROUTE = {
    "kind": "artifact_review_route",
    "route": "queue_approval",
    "terminalize": "none",
    "record_claude_notice": False,
    "attach_cursor_request_ids": True,
    "system_message": "none",
    "additional_context": "none",
    "silent_review": None,
}


def _resident_answering(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any], asked: list[str]) -> None:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(
            features={"resident-protocol-v2", decision.HOOK_DECISION_ARTIFACT_REVIEW_ROUTE_FEATURE}
        ),
    )
    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/hook-decision-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)

    def transport(*, request: dict[str, Any], required_feature: str, **_kwargs: object) -> dict[str, Any]:
        asked.append(required_feature)
        assert request["query"] == {"kind": "artifact_review_route", "inputs": _FACTS}
        return {
            "schema": "guard-hook-decision-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }

    monkeypatch.setattr(decision, "_resident_request", transport)


def test_a_bound_route_is_decoded_behind_its_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []
    _resident_answering(monkeypatch, _ROUTE, asked)
    answer = decision.native_artifact_review_route(_FACTS)
    assert answer == {key: value for key, value in _ROUTE.items() if key != "kind"}
    assert asked == [decision.HOOK_DECISION_ARTIFACT_REVIEW_ROUTE_FEATURE]


@pytest.mark.parametrize(
    "overrides",
    [
        {"route": "queue_everything"},
        {"terminalize": "sometimes"},
        {"system_message": "codex_prompt"},
        {"additional_context": "claude_punctuated"},
        {"record_claude_notice": "yes"},
        {"attach_cursor_request_ids": None},
        {"silent_review": {"action": "review", "reason": "x"}},
        {"route": "silent_review"},
        {"route": "silent_review", "silent_review": {"action": "block", "reason": "x"}},
        {"route": "silent_block", "silent_review": {"action": "review", "reason": "x", "extra": 1}},
        {"extra": True},
    ],
)
def test_a_malformed_route_fails_closed(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]) -> None:
    _resident_answering(monkeypatch, {**_ROUTE, **overrides}, [])
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_artifact_review_route(_FACTS)


def test_incomplete_inputs_are_refused_before_the_resident_is_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []
    _resident_answering(monkeypatch, _ROUTE, asked)
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_artifact_review_route({key: value for key, value in _FACTS.items() if key != "json"})
    assert asked == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_the_recorded_routes() -> None:
    failures: list[str] = []
    for vector in _vectors()[::47]:
        answer = decision.native_artifact_review_route(vector["facts"])
        failures.extend(
            f"{vector['facts']}: {key} {answer[key]!r} != {expected!r}"
            for key, expected in vector["route"].items()
            if answer[key] != expected
        )
    assert failures == []
