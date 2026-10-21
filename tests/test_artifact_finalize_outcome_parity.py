"""The artifact hook applies the resident's browser outcome as Python decided it.

The recorder froze the browser-outcome section of the retired
``finalize_native_artifact_hook``. This suite runs the new executor against the
recorded outcome vectors and checks the order of effects, the facts the
resident is asked, and that a missing browser decision asks nothing.
"""

from __future__ import annotations

import contextlib
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_artifact_finalize as finalize
from codex_plugin_scanner.guard.cli import commands_hook_native_finish as finish
from tests.artifact_finalize_support import load_recorder, load_vectors, resident_stub, vector_key


class _RenderedError(Exception):
    """The browser section handed the verdict to the directive."""


def test_executor_reproduces_the_recorded_browser_outcome_section(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = load_recorder()
    data = load_vectors()
    vectors = {vector_key(vector["facts"]): vector for vector in data["browser"]}
    assert len(vectors) == len(data["browser"]) > 60
    trace: list[list[object]] = []
    current: list[tuple[str, str]] = []
    asked = resident_stub(
        monkeypatch,
        lambda query: {"kind": "artifact_browser_outcome", **vectors[vector_key(query["inputs"])]["answer"]},
    )

    def fresh_state(event: str) -> SimpleNamespace:
        return SimpleNamespace(
            action_envelope=None,
            artifact_id="artifact",
            event_name=event,
            initial_policy_action="stale",
            policy_action="review",
            response_payload={},
            runtime_artifact=SimpleNamespace(artifact_type="tool_action_request"),
            runtime_artifact_hash="hash",
            browser_approval_daemon_client=None,
        )

    fresh: list[SimpleNamespace] = []

    def decide(*_args: object, fresh_context_provider: Any, **_kwargs: object) -> str:
        fresh_context_provider()
        return current[-1][0]

    def settle(state: SimpleNamespace, action: str, **kwargs: Any) -> None:
        if state is fresh[-1]:
            trace.append(["adopt"])
        assert kwargs["queued_request_id"] == "queued-1"
        assert kwargs["approval_request_id"] == "req-1"
        trace.append(["settle", action, kwargs["approval_source"]])
        state.policy_action = action

    def directive(*_args: object, **_kwargs: object) -> dict[str, object]:
        trace.append(["render"])
        raise _RenderedError

    monkeypatch.setattr(finish, "_browser_approval_decision", decide)
    monkeypatch.setattr(finish, "set_native_artifact_hook_final_action", settle)
    monkeypatch.setattr(finish, "live_hook_approval_context", lambda *_a, **_k: None)
    monkeypatch.setattr(finish, "native_artifact_directive", directive)
    monkeypatch.setattr(finish, "record_native_artifact_hook_receipt", lambda *_a, **_k: trace.append(["receipt"]))
    monkeypatch.setattr(
        finish,
        "_record_harness_usage_for_hook",
        lambda **kwargs: trace.append(["usage", kwargs["policy_action"]]),
    )
    monkeypatch.setattr(
        finish,
        "_emit_native_hook_response",
        lambda **kwargs: trace.append(["native_allow", kwargs["event_name"], kwargs["reason"]]),
    )

    def run(decision_text: str, event: str) -> list[list[object]]:
        trace.clear()
        asked.clear()
        current.append((decision_text, event))
        fresh.append(fresh_state(event))
        state = SimpleNamespace(
            action_envelope=None,
            artifact_id="artifact",
            event_name=event,
            initial_policy_action="review",
            policy_action="review",
            response_payload={
                "approval_requests": [{"request_id": "queued-1"}],
                "browser_resolution_request_id": "req-1",
            },
            runtime_artifact=SimpleNamespace(artifact_type="tool_action_request"),
            runtime_artifact_hash="hash",
            browser_approval_daemon_client="client",
        )
        try:
            rc = finish.finalize_native_artifact_hook(
                state,  # type: ignore[arg-type]
                SimpleNamespace(harness="codex", json=False),  # type: ignore[arg-type]
                config=None,  # type: ignore[arg-type]
                payload={},
                store=SimpleNamespace(guard_home=None),  # type: ignore[arg-type]
                post_wait_revalidator=lambda: fresh[-1],  # type: ignore[arg-type,return-value]
            )
        except _RenderedError:
            pass
        else:
            trace.append(["return", rc])
        finally:
            current.pop()
        assert [query["inputs"] for query in asked] == [{"decision": decision_text, "event": event}]
        return [list(entry) for entry in trace]

    failures: list[str] = []
    for decision_text, event in recorder.browser_cases():
        expected = vectors[vector_key({"decision": decision_text, "event": event})]
        actual = recorder.record_browser(decision_text, event, run=run)
        for key in ("facts", "trace", "answer"):
            if actual[key] != expected[key]:
                failures.append(f"{decision_text!r} {event!r}: {key} {actual[key]!r} != {expected[key]!r}")
    assert failures == []


_REQUEST_FACTS = [
    ({"browser_resolution_request_id": "req-1"}, ("req-1", None)),
    ({"browser_resolution_request_id": ""}, ("", None)),
    ({"browser_resolution_request_id": 5}, (None, None)),
    ({}, (None, None)),
    ({"approval_requests": [{"request_id": "queued-1"}, {"request_id": "queued-2"}]}, (None, "queued-1")),
    ({"approval_requests": [{"request_id": 5}]}, (None, None)),
    ({"approval_requests": ["queued-1"]}, (None, None)),
    ({"approval_requests": []}, (None, None)),
    ({"approval_requests": "queued-1"}, (None, None)),
    (
        {"browser_resolution_request_id": "req-1", "approval_requests": [{"request_id": "queued-1"}]},
        ("req-1", "queued-1"),
    ),
]


@pytest.mark.parametrize(("response", "expected"), _REQUEST_FACTS)
@pytest.mark.parametrize("browser_decision", ["allow", "block", "sandbox-required"])
def test_request_ids_reach_the_resident_as_facts(
    monkeypatch: pytest.MonkeyPatch,
    response: dict[str, object],
    expected: tuple[str | None, str | None],
    browser_decision: str,
) -> None:
    seen: list[dict[str, object]] = []
    monkeypatch.setattr(finish, "_browser_approval_decision", lambda *_a, **_k: browser_decision)
    monkeypatch.setattr(
        finish,
        "native_artifact_browser_outcome",
        lambda inputs, **_k: {
            "settle": True,
            "action": inputs["decision"],
            "approval_source": "browser",
            "emit_native_allow": False,
            "finish_without_render": inputs["decision"] == "allow",
        },
    )
    monkeypatch.setattr(finish, "set_native_artifact_hook_final_action", lambda _state, _action, **kw: seen.append(kw))
    monkeypatch.setattr(finish, "record_native_artifact_hook_receipt", lambda *_a, **_k: None)
    monkeypatch.setattr(finish, "_record_harness_usage_for_hook", lambda **_k: None)
    monkeypatch.setattr(finish, "live_hook_approval_context", lambda *_a, **_k: None)
    monkeypatch.setattr(finish, "native_artifact_directive", lambda *_a, **_k: (_ for _ in ()).throw(_RenderedError()))
    state = SimpleNamespace(
        action_envelope=None,
        event_name="PreToolUse",
        policy_action="review",
        response_payload=dict(response),
        runtime_artifact=SimpleNamespace(artifact_type="tool_action_request"),
    )
    with contextlib.suppress(_RenderedError):
        finish.finalize_native_artifact_hook(
            state,  # type: ignore[arg-type]
            SimpleNamespace(harness="codex", json=False),  # type: ignore[arg-type]
            config=None,  # type: ignore[arg-type]
            payload={},
            store=SimpleNamespace(guard_home=None),  # type: ignore[arg-type]
        )
    assert len(seen) == 1
    assert (seen[0]["approval_request_id"], seen[0]["queued_request_id"]) == expected
    assert seen[0]["approval_source"] == "browser"


def test_a_missing_browser_decision_asks_the_resident_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[object] = []
    monkeypatch.setattr(finish, "_browser_approval_decision", lambda *_a, **_k: None)
    monkeypatch.setattr(finish, "native_artifact_browser_outcome", lambda *_a, **_k: asked.append("outcome"))
    monkeypatch.setattr(finish, "live_hook_approval_context", lambda *_a, **_k: None)
    monkeypatch.setattr(finish, "native_artifact_directive", lambda *_a, **_k: (_ for _ in ()).throw(_RenderedError()))
    state = SimpleNamespace(
        action_envelope=None,
        event_name="PreToolUse",
        policy_action="review",
        response_payload={},
        runtime_artifact=SimpleNamespace(artifact_type="tool_action_request"),
    )
    with pytest.raises(_RenderedError):
        finish.finalize_native_artifact_hook(
            state,  # type: ignore[arg-type]
            SimpleNamespace(harness="codex", json=False),  # type: ignore[arg-type]
            config=None,  # type: ignore[arg-type]
            payload={},
            store=SimpleNamespace(guard_home=None),  # type: ignore[arg-type]
        )
    assert asked == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_the_recorded_browser_outcomes() -> None:
    failures: list[str] = []
    for vector in load_vectors()["browser"]:
        answer = finalize.native_artifact_browser_outcome(vector["facts"])
        failures.extend(
            f"{vector['facts']}: {key} {answer[key]!r} != {value!r}"
            for key, value in vector["answer"].items()
            if answer[key] != value
        )
    assert failures == []
