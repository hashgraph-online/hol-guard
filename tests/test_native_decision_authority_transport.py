from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import native_decisions, native_runner_authority
from codex_plugin_scanner.guard.native_decisions import NativeDecisionAuthorityError, NativeDecisionUnavailableError
from codex_plugin_scanner.guard.runtime.decisions import (
    AuthoritativeGuardDecision,
    GuardDecisionV2,
    authoritative_decision_from_artifact,
    build_authoritative_decision,
    decision_from_legacy_policy_action,
)


@pytest.mark.parametrize("operation", ("v2", "authoritative", "build", "artifact", "legacy"))
def test_native_unavailability_has_no_local_decision_fallback(monkeypatch: pytest.MonkeyPatch, operation: str) -> None:
    def unavailable(*args: object, **kwargs: object) -> object:
        raise native_runner_authority.NativeRunnerAuthorityError("native_runtime_unavailable")

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", unavailable)
    with pytest.raises(NativeDecisionUnavailableError, match="native_runtime_unavailable") as caught:
        if operation == "v2":
            GuardDecisionV2.from_dict({"guard_action": "allow"})
        elif operation == "authoritative":
            AuthoritativeGuardDecision.from_dict({"action": "allow", "launch_permitted": True})
        elif operation == "build":
            build_authoritative_decision("allow", reason="fixture", composition_trace={}, authority_finalized=True)
        elif operation == "artifact":
            authoritative_decision_from_artifact({"policy_action": "allow"})
        else:
            decision_from_legacy_policy_action("allow", reason="fixture")
    assert not isinstance(caught.value, ValueError)
    assert isinstance(caught.value.__cause__, native_runner_authority.NativeRunnerAuthorityError)


@pytest.mark.parametrize("value", ({}, {"action": "allow", "launch_permitted": True}, [], None))
def test_incomplete_native_result_cannot_be_projected_as_a_decision(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    monkeypatch.setattr(native_decisions, "_request", lambda *args: {"status": "ok", "value": value})
    with pytest.raises(NativeDecisionAuthorityError, match="result_invalid"):
        native_decisions.decision_authority("decision_authoritative_decode", {"payload": {}})


def test_native_validation_error_preserves_the_public_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        native_decisions,
        "_request",
        lambda *args: {
            "status": "error",
            "error_type": "ValueError",
            "message": "runtime detector block cannot be overridden",
        },
    )
    with pytest.raises(ValueError, match="runtime detector block cannot be overridden"):
        build_authoritative_decision("allow", reason="fixture", composition_trace={}, authority_finalized=True)


@pytest.mark.parametrize("code", ("native_runner_authority_request_too_large", "native_decision_authority_invalid"))
def test_healthy_native_refusal_is_validation_not_an_outage(monkeypatch: pytest.MonkeyPatch, code: str) -> None:
    def refuse(*args: object, **kwargs: object) -> object:
        raise native_runner_authority.NativeRunnerAuthorityRefusalError(code)

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", refuse)
    with pytest.raises(NativeDecisionAuthorityError, match=code) as caught:
        build_authoritative_decision("allow", reason="fixture", composition_trace={}, authority_finalized=True)
    assert not isinstance(caught.value, NativeDecisionUnavailableError)
    assert isinstance(caught.value.__cause__, native_runner_authority.NativeRunnerAuthorityRefusalError)


def test_artifact_transport_omits_unread_values_but_preserves_hidden_action_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[dict[str, object]] = []

    def request(kind: str, args: dict[str, object]) -> dict[str, object]:
        captured.append(args)
        return {"status": "error", "error_type": "ValueError", "message": "fixture refusal"}

    monkeypatch.setattr(native_decisions, "_request", request)
    with pytest.raises(ValueError, match="fixture refusal"):
        native_decisions.decision_authority(
            "decision_artifact_decode",
            {"payload": {"policy_action": "deny", "future_action": "allow", "raw_source": "unread"}},
        )
    assert captured == [{"payload": {"policy_action": "deny", "future_action": None, "raw_source": None}}]
