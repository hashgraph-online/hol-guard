"""The resident resolves risk-class actions; Python only ships the configuration.

Python used to resolve the action for a risk class and send the verdict with
the request, which made it a second evaluator for an authority input. These
tests pin the opposite: the cutover sites project the loaded configuration and
the harness, and carry no resolved action at all.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.config import GuardConfig, risk_action_config_facts
from codex_plugin_scanner.guard.models import GuardArtifact

_CONFIG_FIELDS = {
    "security_level",
    "protection_posture",
    "protection_posture_explicit",
    "managed_locked_settings",
    "risk_actions",
    "harness_risk_actions",
    "harness_postures",
}


def _config(**overrides: Any) -> GuardConfig:
    return GuardConfig(guard_home=Path("/nonexistent-guard-home"), workspace=None, **overrides)


def test_risk_action_config_facts_ships_the_maps_as_loaded() -> None:
    config = _config(
        security_level="balanced",
        protection_posture="extra-careful",
        risk_actions={"local_secret_read": "review"},
        harness_risk_actions={"Codex": {"local_secret_read": "block"}},
        harness_postures={"codex": "relaxed"},
    )

    facts = risk_action_config_facts(config)

    assert set(facts) == _CONFIG_FIELDS
    # ``harness_risk_actions`` keeps the caller's spelling and ``harness_postures``
    # stays canonical, because that is how each is looked up when it is resolved.
    assert facts["harness_risk_actions"] == {"Codex": {"local_secret_read": "block"}}
    assert facts["harness_postures"] == {"codex": "relaxed"}
    assert facts["risk_actions"] == {"local_secret_read": "review"}
    assert facts["protection_posture"] == "extra-careful"


def test_risk_action_config_facts_copies_rather_than_aliasing() -> None:
    risk_actions: dict[str, Any] = {"local_secret_read": "review"}
    harness_risk_actions: dict[str, dict[str, Any]] = {"codex": {"local_secret_read": "review"}}
    config = _config(risk_actions=risk_actions, harness_risk_actions=harness_risk_actions)

    facts = risk_action_config_facts(config)
    risk_actions["local_secret_read"] = "allow"
    harness_risk_actions["codex"]["local_secret_read"] = "allow"

    assert facts["risk_actions"] == {"local_secret_read": "review"}
    assert facts["harness_risk_actions"] == {"codex": {"local_secret_read": "review"}}


def test_cisco_policy_query_sends_the_configuration_and_not_a_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import native_cisco_preflight as preflight

    captured: dict[str, object] = {}

    def fake_query(query: dict[str, object], guard_home: Path | None = None) -> dict[str, object]:
        captured.update(query)
        return {"policy_action": "block"}

    monkeypatch.setattr(preflight, "_query", fake_query)
    config = _config(risk_actions={"malicious_skill": "allow"})

    action = preflight.policy_action_for_cisco_signals((), config=config, harness="codex")

    assert action == "block"
    assert captured["check"] == "policy_action"
    assert captured["harness"] == "codex"
    assert set(captured["guard_config"]) == _CONFIG_FIELDS  # type: ignore[arg-type]
    assert "configured_actions" not in captured
    assert "risk_action" not in captured


def test_sensitive_read_facts_send_the_configuration_and_not_a_verdict() -> None:
    from codex_plugin_scanner.guard.native_mcp_sensitive_read import _config_facts

    config = _config(risk_actions={"local_secret_read": "block"})
    artifact = GuardArtifact(
        artifact_id="server:reader",
        name="reader",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path="/workspace/.mcp.json",
    )

    facts = _config_facts(config, artifact=artifact, harness="codex")

    assert facts is not None
    assert "risk_action" not in facts
    assert facts["harness"] == "codex"
    sent = facts["guard_config"]
    assert isinstance(sent, dict)
    assert set(sent) == _CONFIG_FIELDS
    assert sent["risk_actions"] == {"local_secret_read": "block"}
