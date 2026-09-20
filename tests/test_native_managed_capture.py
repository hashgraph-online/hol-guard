"""Original loaded origins reach authenticated source and generation identities."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_managed_capture import bind_configuration_origin, compile_configuration_origins
from codex_plugin_scanner.guard.native_managed_configuration import (
    MANAGED_CONFIGURATION_FEATURE,
    MANAGED_CONFIGURATION_INPUT_KEY,
)
from codex_plugin_scanner.guard.native_policy_authority_contract import NativePolicyAuthorityCapabilities
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_contract import build_policy_snapshot_v3
from codex_plugin_scanner.guard.native_policy_snapshot_policy import (
    _merge_effective_native_policies,
    effective_native_policy_v3,
)
from codex_plugin_scanner.guard.native_policy_snapshot_v4_generation import reserve_snapshot_v4
from tests.test_managed_action_origin import loaded
from tests.test_native_policy_snapshot_v4_publication import _inputs


def mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return value


def test_capture_keeps_local_and_managed_risk_hierarchies_separate(tmp_path: Path) -> None:
    config = loaded(
        tmp_path,
        '[risk_actions]\nlocal_secret_read="block"\n',
        {"harness_risk_actions": {"codex": {"local_secret_read": "allow"}}},
    )
    compiled = compile_configuration_origins((config,))
    assert mapping(compiled["risk_actions"])["local_secret_read"] == "block"
    assert compiled["harness_risk_actions"] == {}
    managed = mapping(compiled[MANAGED_CONFIGURATION_INPUT_KEY])
    assert mapping(managed["effective_policy"])["harness_risk_actions"] == {"codex": {"local_secret_read": "allow"}}


def test_no_managed_action_preserves_prior_bytes_and_capture_object(tmp_path: Path) -> None:
    config = loaded(tmp_path, "", {})
    compiled = compile_configuration_origins((config,))
    expected = _merge_effective_native_policies((effective_native_policy_v3(config) | {"mode": config.mode},))
    assert compiled == expected and MANAGED_CONFIGURATION_INPUT_KEY not in compiled
    inputs = _inputs()
    assert bind_configuration_origin(compiled, inputs) is inputs


def test_origin_only_source_change_enters_capture_digest(tmp_path: Path) -> None:
    config = loaded(
        tmp_path, '[risk_actions]\nlocal_secret_read="block"\n', {"risk_actions": {"local_secret_read": "warn"}}
    )
    first = compile_configuration_origins((config,))
    second_config = loaded(
        tmp_path, '[risk_actions]\nlocal_secret_read="block"\n', {"risk_actions": {"local_secret_read": "review"}}
    )
    second = compile_configuration_origins((second_config,))
    assert effective_native_policy_v3(config) == effective_native_policy_v3(second_config)
    inputs = _inputs()
    assert (
        bind_configuration_origin(first, inputs).input_digest != bind_configuration_origin(second, inputs).input_digest
    )
    assert inputs.authority.managed_config is None


def test_disagreeing_or_missing_original_sources_refuse(tmp_path: Path) -> None:
    config = loaded(tmp_path, "", {"default_action": "block"})
    other = loaded(tmp_path, "", {"default_action": "warn"})
    with pytest.raises(NativePolicySnapshotError, match="source_mismatch"):
        compile_configuration_origins((config, other))
    with pytest.raises(NativePolicySnapshotError, match="origin_missing"):
        compile_configuration_origins((replace(config, local_policy_origin=None),))


@pytest.mark.parametrize("compiled", [False, True])
def test_v3_cannot_silently_drop_required_origin(tmp_path: Path, compiled: bool) -> None:
    config = loaded(tmp_path, "", {"default_action": "block"})
    with pytest.raises(NativePolicySnapshotError, match="requires_v4"):
        build_policy_snapshot_v3(
            config=compile_configuration_origins((config,)) if compiled else config,
            guard_home=tmp_path,
            runtime_identity="a" * 64,
            rule_digest="b" * 64,
            verifier_key=b"k" * 32,
            generation=1,
        )


def test_actual_generation_reservation_retains_origin_on_second_build(tmp_path: Path) -> None:
    config = loaded(tmp_path, "", {"default_action": "block"})
    compiled = compile_configuration_origins((config,))
    inputs = bind_configuration_origin(compiled, _inputs())
    capabilities = NativePolicyAuthorityCapabilities(
        4, frozenset({"policy-scoped-authority-v1", MANAGED_CONFIGURATION_FEATURE})
    )

    def reserve(candidate: dict[str, object]):
        return reserve_snapshot_v4(
            config=candidate,
            guard_home=tmp_path,
            runtime_identity="a" * 64,
            rule_digest="b" * 64,
            master_key=b"s" * 32,
            inputs=inputs,
            capabilities=capabilities,
            issued_at_ms=1000,
        )

    first = reserve(compiled)
    second = reserve(compiled)
    first_generation = first.snapshot["generation"]
    assert type(first_generation) is int
    assert second.snapshot["generation"] == first_generation + 1
    assert mapping(second.snapshot["scoped_authority"])["managed_config"] == compiled[MANAGED_CONFIGURATION_INPUT_KEY]
    assert second.snapshot["policy_digest"] == first.snapshot["policy_digest"]
    assert second.snapshot["source_input_digest"] == inputs.input_digest
    mismatched = deepcopy(compiled)
    mapping(mismatched[MANAGED_CONFIGURATION_INPUT_KEY])["source_digest"] = "f" * 64
    with pytest.raises(NativePolicySnapshotError, match="source_mismatch"):
        reserve(mismatched)


def test_capture_preserves_composed_privacy_sandbox_and_posture_scalars(tmp_path: Path) -> None:
    config = loaded(
        tmp_path,
        'receipt_redaction_level="none"\nsandbox_analysis="off"\nsecurity_level="gentle"\n',
        {
            "default_action": "block",
            "receipt_redaction_level": "full",
            "sandbox_analysis": "strict",
            "security_level": "paranoid",
        },
    )
    effective = effective_native_policy_v3(config)
    assert effective["receipt_redaction_level"] == "full"
    assert effective["sandbox_analysis"] == "strict"
    assert effective["security_level"] == "paranoid"
    compiled = compile_configuration_origins((config,))
    for field in ("receipt_redaction_level", "sandbox_analysis", "security_level", "protection_posture"):
        assert compiled[field] == effective[field], field
    assert config.local_policy_origin is not None
    assert compiled["risk_actions"] == effective_native_policy_v3(config.local_policy_origin)["risk_actions"]
    assert config.managed_policy is not None
    assert mapping(compiled[MANAGED_CONFIGURATION_INPUT_KEY])["source_digest"] == config.managed_policy.content_hash
