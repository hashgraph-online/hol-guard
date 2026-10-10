"""Generic-hook decisions are answered by the native runtime.

The language-neutral vectors under ``rust/crates/guard-runtime/tests/fixtures``
are the contract; the Rust suite runs them against the op directly and this
suite runs them through the real resident and the Python transport.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_decision as decision

_VECTORS = json.loads(
    (
        Path(__file__).resolve().parent.parent / "rust/crates/guard-runtime/tests/fixtures/hook_decision_vectors.json"
    ).read_text(encoding="utf-8")
)["vectors"]
_BASE_INPUTS: dict[str, Any] = {
    "harness": "codex",
    "canonical_harness": "codex",
    "event_fields": {"hook_event_name": "PreToolUse"},
    "tool_name_text": "Bash",
    "configured_action": "review",
    "has_configured_override": False,
    "has_narrow_override": False,
    "runtime_artifact_checked": False,
    "prompt_nonblank": False,
    "has_command_text": True,
    "facts": {},
    "cli_action": None,
    "has_payload_action": False,
    "payload_action": None,
    "native_edge": None,
    "daemon_status": None,
    "fail_mode": None,
    "permission_decision_reason": None,
}


def _subset(expected: object, actual: object, path: str = "payload") -> list[str]:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [f"{path}: expected object"]
        problems: list[str] = []
        for key, value in expected.items():
            if key not in actual:
                problems.append(f"{path}.{key}: missing")
            else:
                problems.extend(_subset(value, actual[key], f"{path}.{key}"))
        return problems
    return [] if expected == actual else [f"{path}: expected {expected!r}, got {actual!r}"]


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_matches_language_neutral_vectors() -> None:
    failures: list[str] = []
    for vector in _VECTORS:
        try:
            payload = decision._decide(vector["query"], None, lambda _payload: None)
        except decision.NativeHookDecisionError as error:
            # A resident-side rejection never yields a decision; the transport
            # reports it as a failure (the exact code is asserted in Rust).
            if "error" not in vector:
                failures.append(f"{vector['name']}: unexpected {error.code}")
            continue
        if "error" in vector:
            failures.append(f"{vector['name']}: expected error {vector['error']}")
            continue
        failures.extend(f"{vector['name']}: {problem}" for problem in _subset(vector["expect"], payload))
    assert failures == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_classifiers_run_only_when_the_resident_asks() -> None:
    asked: list[tuple[str, str | None]] = []

    def provider(name: str, verdict: bool):
        def run(event: str | None) -> bool:
            asked.append((name, event))
            return verdict

        return run

    classifiers = {
        name: provider(name, name == "benign_tool_action")
        for name in (
            "prompt_clean",
            "post_tool_read_only_inspection",
            "verified_apply_patch",
            "benign_native_file_read",
            "benign_tool_action",
        )
    }
    composition, facts = decision.native_compose_current(_BASE_INPUTS, classifiers)
    assert composition["composed_action"] == "warn"
    assert facts == {"verified_apply_patch": False, "benign_native_file_read": False, "benign_tool_action": True}
    assert [name for name, _ in asked] == list(facts)
    assert {event for _, event in asked} == {"PreToolUse"}

    asked.clear()
    composition, facts = decision.native_compose_current({**_BASE_INPUTS, "configured_action": "allow"}, classifiers)
    assert composition["composed_action"] == "allow"
    assert facts == {} and asked == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_unrequested_or_missing_classifier_fails_closed() -> None:
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_compose_current(_BASE_INPUTS, {})


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_finalize_and_post_claim_round_trip() -> None:
    action, reason = decision.native_post_claim_reuse(
        {
            "current_policy_action": "allow",
            "reuse_action": "allow",
            "reuse_saved_action": "allow",
            "post_claim_refresh_failed": False,
            "context_changed": True,
            "has_ignored_integrity": False,
            "claim_row_invalid": False,
        }
    )
    assert (action, reason) == ("require-reapproval", "approval_reuse_context_changed_after_claim")
    vector = next(item for item in _VECTORS if item["name"] == "unprompted_review_blocks_when_harness_cannot_ask")
    final = decision.native_finalize(vector["query"]["inputs"], vector["query"]["settled"])
    assert final["policy_action"] == "block"
    assert final["silent_review"]["action"] == "review"
    assert final["directive"]["route"] == "render"


def _resident_returning(monkeypatch: pytest.MonkeyPatch, reply: Any) -> None:
    monkeypatch.setattr(decision, "_resolve_digest_home", lambda _home: Path("/tmp/hook-decision-home"))
    monkeypatch.setattr(decision, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(decision, "_resident_request", lambda *, request, **_kwargs: reply(request))


def _good(request: dict[str, Any], **overrides: object) -> dict[str, Any]:
    reply: dict[str, Any] = {
        "schema": "guard-hook-decision-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + decision._canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "payload": {"kind": "post_claim_reuse", "current_action": "allow", "validation_reason": None},
    }
    reply.update(overrides)
    return reply


_CLAIM = {
    "current_policy_action": "allow",
    "reuse_action": "allow",
    "reuse_saved_action": None,
    "post_claim_refresh_failed": False,
    "context_changed": False,
    "has_ignored_integrity": False,
    "claim_row_invalid": False,
}


@pytest.mark.parametrize(
    "overrides",
    [
        {"request_sha256": "sha256:" + "0" * 64},
        {"request_id": "someone-else"},
        {"schema": "wrong"},
        {"status": "error", "code": "arbitrary text", "payload": None},
        {"payload": None},
        {"payload": {"kind": "finalize"}},
        {"payload": {"kind": "post_claim_reuse", "current_action": "bogus", "validation_reason": None}},
        {"payload": {"kind": "post_claim_reuse", "current_action": "allow", "validation_reason": 3}},
        {"payload": {"kind": "post_claim_reuse", "current_action": "allow"}},
    ],
)
def test_unbound_or_malformed_answers_raise(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request, **overrides))
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_post_claim_reuse(_CLAIM)


def test_resident_error_code_is_surfaced(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(
        monkeypatch,
        lambda request: _good(request, status="error", code="native_hook_decision_action_invalid", payload=None),
    )
    with pytest.raises(decision.NativeHookDecisionError) as error:
        decision.native_post_claim_reuse(_CLAIM)
    assert error.value.code == "native_hook_decision_action_invalid"


def test_missing_resident_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda _request: None)
    with pytest.raises(decision.NativeHookDecisionError) as error:
        decision.native_post_claim_reuse(_CLAIM)
    assert error.value.code == "native_hook_decision_unavailable"


def test_bound_answer_is_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    assert decision.native_post_claim_reuse(_CLAIM) == ("allow", None)
