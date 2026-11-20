"""The approval-hash bridge sends the configuration, never a resolved action."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.native_package_approval_hash import package_config_facts


def _config(**overrides: object) -> GuardConfig:
    return GuardConfig(guard_home=Path("/tmp/guard-home-facts"), workspace=None, **overrides)  # type: ignore[arg-type]


def test_no_bound_configuration_sends_no_fields() -> None:
    assert package_config_facts(None) is None


def test_the_fields_go_over_as_they_were_loaded() -> None:
    facts = package_config_facts(
        _config(
            mode="enforce",
            security_level="strict",
            risk_actions={"package_script": "review"},
            harness_risk_actions={"codex": {"package_script": "block"}},
            harness_postures={"codex": "extra-careful"},
            harness_actions={"codex": "warn"},
            publisher_actions={"acme": "review"},
            artifact_actions={"command:npm-install": "block"},
            managed_policy_status="locked",
            managed_policy_hash="mh",
            managed_locked_settings=("mode",),
        )
    )
    assert facts == {
        "artifact_actions": {"command:npm-install": "block"},
        "harness_actions": {"codex": "warn"},
        "harness_postures": {"codex": "extra-careful"},
        "harness_risk_actions": {"codex": {"package_script": "block"}},
        "managed_locked_settings": ["mode"],
        "managed_policy_hash": "mh",
        "managed_policy_status": "locked",
        "mode": "enforce",
        "protection_posture": "protected",
        "protection_posture_explicit": False,
        "publisher_actions": {"acme": "review"},
        "risk_actions": {"package_script": "review"},
        "security_level": "strict",
    }


def test_no_resolved_action_is_sent() -> None:
    facts = package_config_facts(_config(risk_actions={"package_script": "review"}))
    assert facts is not None
    # The resident resolves the class; a resolved verdict never leaves Python.
    assert not any("effective" in key or "resolved" in key for key in facts)


def test_an_unset_override_map_stays_unset() -> None:
    facts = package_config_facts(_config())
    assert facts is not None
    for key in ("artifact_actions", "publisher_actions", "harness_actions"):
        assert facts[key] is None
