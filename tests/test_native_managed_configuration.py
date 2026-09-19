"""Actual loaded managed sources retain a separate, bounded native projection."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.native_managed_configuration import (
    MANAGED_CONFIGURATION_SCHEMA,
    NativeManagedConfiguration,
    project_managed_configuration,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from tests.test_managed_action_origin import loaded


def projection(tmp_path: Path, settings: dict[str, object], local: str = "") -> dict[str, object]:
    config = loaded(tmp_path, local, settings)
    result = project_managed_configuration(config)
    assert result is not None
    assert config.managed_policy is not None
    assert result.source_digest == config.managed_policy.content_hash
    return result.to_mapping()


def effective(value: dict[str, object]) -> dict[str, object]:
    policy = value["effective_policy"]
    assert isinstance(policy, dict)
    return policy


def test_absent_or_non_action_managed_profile_adds_no_authority(tmp_path: Path) -> None:
    assert project_managed_configuration(load_guard_config(tmp_path)) is None
    assert project_managed_configuration(loaded(tmp_path, "", {})) is None
    assert project_managed_configuration(loaded(tmp_path, "", {"receipt_redaction_level": "full"})) is None


def test_original_source_hierarchy_survives_flattened_local_overrides(tmp_path: Path) -> None:
    value = projection(
        tmp_path,
        {
            "default_action": "block",
            "artifacts": {"target": {"action": "allow"}},
            "risk_actions": {"local_secret_read": "block"},
            "harness_risk_actions": {"codex": {"local_secret_read": "review"}},
        },
        '[artifacts]\nother="allow"\n[harness_risk_actions.codex]\nlocal_secret_read="allow"\n',
    )
    policy = effective(value)
    assert value["schema"] == MANAGED_CONFIGURATION_SCHEMA
    assert policy["default_action"] == "block"
    assert policy["artifact_actions"] == {"target": "allow"}
    assert policy["harness_actions"] == {}
    risks = policy["risk_actions"]
    assert isinstance(risks, dict)
    assert risks["local_secret_read"] == "block"
    assert policy["harness_risk_actions"] == {"codex": {"local_secret_read": "review"}}


@pytest.mark.parametrize("representation", ["warn", {"action": "warn"}, {"default_action": "warn"}])
def test_projection_normalizes_accepted_action_representations(tmp_path: Path, representation: object) -> None:
    value = projection(tmp_path, {"artifacts": {"target": representation}})
    assert effective(value)["artifact_actions"] == {"target": "warn"}
    assert effective(value)["default_action"] == "allow"


def test_only_explicit_managed_posture_introduces_managed_risk_defaults(tmp_path: Path) -> None:
    value = projection(tmp_path, {"default_action": "warn"})
    risks = effective(value)["risk_actions"]
    assert isinstance(risks, dict) and set(risks.values()) == {"allow"}
    value = projection(tmp_path, {"security_level": "paranoid"})
    risks = effective(value)["risk_actions"]
    assert isinstance(risks, dict) and risks["credential_exfiltration"] == "block"


@pytest.mark.parametrize(
    "settings",
    [
        {"risk_actions": {"unsupported": "allow"}},
        {"harness_risk_actions": {"off-target": {"unsupported": "block"}}},
        {"artifacts": {"": "allow"}},
    ],
)
def test_complete_projection_refuses_unrepresentable_settings(tmp_path: Path, settings: dict[str, object]) -> None:
    config = loaded(tmp_path, "", settings)
    with pytest.raises(NativePolicySnapshotError):
        project_managed_configuration(config)


def test_mode_is_actual_resolved_mode_and_mapping_is_detached(tmp_path: Path) -> None:
    config = loaded(tmp_path, "", {"protection_posture": "watch", "default_action": "block"})
    result = project_managed_configuration(config)
    assert result is not None and config.mode == "observe" and result.mode == "observe"
    mapping = result.to_mapping()
    effective(mapping)["default_action"] = "allow"
    assert effective(result.to_mapping())["default_action"] == "block"
    restored = NativeManagedConfiguration.from_mapping(result.to_mapping())
    assert restored == result


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("schema", "future"),
        ("mode", "prompt"),
        ("mode", True),
        ("default_action_present", 1),
        ("default_action_present", "true"),
        ("source_digest", "A" * 64),
        ("effective_policy", None),
        ("extra", True),
    ],
)
def test_unknown_or_malformed_wire_values_refuse(tmp_path: Path, key: str, value: object) -> None:
    mapping = projection(tmp_path, {"default_action": "block"})
    mapping[key] = value
    with pytest.raises(NativePolicySnapshotError):
        NativeManagedConfiguration.from_mapping(mapping)


@pytest.mark.parametrize("field", ["default_action", "risk_actions", "protection_posture"])
def test_incomplete_policy_never_fills_implicit_defaults(tmp_path: Path, field: str) -> None:
    mapping = deepcopy(projection(tmp_path, {"default_action": "block"}))
    del effective(mapping)[field]
    with pytest.raises(NativePolicySnapshotError):
        NativeManagedConfiguration.from_mapping(mapping)


def test_omitted_default_is_not_an_explicit_managed_allow(tmp_path: Path) -> None:
    missing = projection(tmp_path, {"risk_actions": {"local_secret_read": "block"}})
    present = projection(tmp_path, {"risk_actions": {"local_secret_read": "block"}, "default_action": "allow"})
    assert missing["effective_policy"] == present["effective_policy"]
    assert missing["default_action_present"] is False
    assert present["default_action_present"] is True
    del present["default_action_present"]
    with pytest.raises(NativePolicySnapshotError):
        NativeManagedConfiguration.from_mapping(present)
