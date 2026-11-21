"""Transport never accepts public runtime facts as local installation authority."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_context_assistance as api


def state() -> dict[str, object]:
    return {
        "schema": "guard-context-assistance-status.v2",
        "availability": "off",
        "requested_enabled": False,
        "effective_enabled": False,
        "preferences": {},
        "effective_preferences": {},
        "restriction": None,
        "verification_permitted": True,
        "generation": "9007199254740993",
        "diagnostic": None,
        "runtime": None,
        "last_check": None,
        "qualification": None,
        "capabilities": {"shared_agents": True, "private_persistence": False},
        "installation_options": None,
        "job": None,
    }


def test_body_cannot_replace_the_bound_home_or_control_action(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured = {}
    monkeypatch.setattr(api, "_resolve_digest_home", lambda _: tmp_path)

    def decide(query, home, fields, validate, **kwargs):
        captured.update(query=query, home=home, operation=kwargs["operation"])
        answer = {"kind": "activate", "state": state()}
        validate(answer)
        return answer

    monkeypatch.setattr(api, "_decide", decide)
    forged = {"guard_home": "/foreign", "kind": "status", "implementation": "cpython", "version": [3, 14, 7]}
    result = api.control("activate", guard_home=tmp_path, payload=forged)
    assert captured["query"] == {"kind": "activate", "guard_home": str(tmp_path), "input": forged}
    assert captured["home"] == tmp_path
    assert captured["operation"].feature == "context-assistance-control-v2"
    assert result["generation"] == "9007199254740993"
    assert result["effective_enabled"] is False
    assert result["capabilities"] == {"shared_agents": True, "private_persistence": False}


@pytest.mark.parametrize(
    "capabilities",
    [
        {},
        {"shared_agents": "true", "private_persistence": False},
        {"shared_agents": True, "private_persistence": False, "grant": True},
    ],
)
def test_native_capability_projection_keeps_strict_types_and_rejects_unknown_fields(capabilities):
    value = state()
    value["capabilities"] = capabilities
    with pytest.raises(api.ContextAssistanceError, match="payload_invalid"):
        api._validate_state({"state": value})


def test_execution_projection_is_optional_for_older_cores_and_strict_when_present():
    value = state()
    api._validate_state({"state": value})
    value["capabilities"]["execution_context"] = True
    value["execution_ready"] = False
    value["execution_observations"] = []
    value["runtime"] = {"execution_handoff_verified": True}
    api._validate_state({"state": value})
    for malformed in (None, 1, "true"):
        value["execution_ready"] = malformed
        with pytest.raises(api.ContextAssistanceError, match="payload_invalid"):
            api._validate_state({"state": value})
    value["execution_ready"] = False
    for malformed in (None, 1, "true"):
        value["runtime"]["execution_handoff_verified"] = malformed
        with pytest.raises(api.ContextAssistanceError, match="payload_invalid"):
            api._validate_state({"state": value})
    value["runtime"] = None
    value["capabilities"]["execution_context"] = "true"
    with pytest.raises(api.ContextAssistanceError, match="payload_invalid"):
        api._validate_state({"state": value})


def test_execution_projection_does_not_allow_untyped_state_or_observation_containers():
    for malformed in (None, [], "state"):
        with pytest.raises(api.ContextAssistanceError, match="payload_invalid"):
            api._validate_state({"state": malformed})
    value = state()
    value["execution_observations"] = {"ticket": "untyped"}
    with pytest.raises(api.ContextAssistanceError, match="payload_invalid"):
        api._validate_state({"state": value})


def test_incomplete_native_availability_payload_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(api, "_resolve_digest_home", lambda _: tmp_path)

    def decide(query, home, fields, validate, **kwargs):
        answer = {"kind": "status", "state": {"effective_enabled": True}}
        validate(answer)
        return answer

    monkeypatch.setattr(api, "_decide", decide)
    with pytest.raises(api.ContextAssistanceError, match="payload_invalid"):
        api.control("status", guard_home=tmp_path)


@pytest.mark.parametrize("field", ["runtime", "last_check"])
@pytest.mark.parametrize("flag", [None, 1, "true"])
def test_persistence_qualification_projection_rejects_non_boolean_native_flags(field, flag):
    value = state()
    value[field] = {"persistence_compile_verified": flag}
    with pytest.raises(api.ContextAssistanceError, match="payload_invalid"):
        api._validate_state({"state": value})


def test_runtime_qualification_flag_is_projected_without_inventing_effective_state():
    value = state()
    value["last_check"] = {"persistence_compile_verified": True}
    api._validate_state({"state": value})
    assert value["effective_enabled"] is False
    assert value["last_check"]["persistence_compile_verified"] is True
