"""Actual local/MDM loader and runtime evidence for separate policy origins."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
from codex_plugin_scanner.guard.mdm.policy import parse_managed_policy
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.native_managed_configuration import project_managed_configuration
from codex_plugin_scanner.guard.native_policy_snapshot_policy import effective_native_policy_v3
from tests import native_sensitive_read_policy_vectors as ordinary
from tests.test_native_sensitive_read_sources import FIXTURE as SOURCE_FIXTURE
from tests.test_native_sensitive_read_sources import produce_sensitive_read

SELECTORS = ("default", "harness", "artifact", "risk", "harness-risk")


@dataclass(frozen=True)
class MixedConfiguration:
    name: str
    local: dict[str, object]
    managed: dict[str, object]
    required_action: GuardAction | None = None


def action_setting(selector: str, action: GuardAction, harness: str, artifact_id: str) -> dict[str, object]:
    settings: dict[str, dict[str, object]] = {
        "default": {"default_action": action},
        "harness": {"harnesses": {harness: action}},
        "artifact": {"artifacts": {artifact_id: action}},
        "risk": {"risk_actions": {"local_secret_read": action}},
        "harness-risk": {"harness_risk_actions": {harness: {"local_secret_read": action}}},
    }
    return settings[selector]


def configurations(harness: str, artifact_id: str) -> list[MixedConfiguration]:
    cases: list[MixedConfiguration] = []
    for local_selector in SELECTORS:
        for managed_selector in SELECTORS:
            if harness != "codex" and local_selector != managed_selector:
                continue
            for restricted in ("local", "managed"):
                local_action = "block" if restricted == "local" else "allow"
                managed_action = "block" if restricted == "managed" else "allow"
                cases.append(
                    MixedConfiguration(
                        f"local-{local_selector}-{local_action}-managed-{managed_selector}-{managed_action}",
                        action_setting(local_selector, local_action, harness, artifact_id),
                        action_setting(managed_selector, managed_action, harness, artifact_id),
                        required_action="block",
                    )
                )
    if harness == "codex":
        # More-specific exceptions apply within one origin, never across origins.
        for origin in ("local", "managed"):
            for broad, specific in (("default", "artifact"), ("harness", "artifact"), ("risk", "harness-risk")):
                settings = {
                    **action_setting(broad, "block", harness, artifact_id),
                    **action_setting(specific, "allow", harness, artifact_id),
                }
                cases.append(
                    MixedConfiguration(
                        f"{origin}-{broad}-block-{specific}-allow-exception",
                        settings if origin == "local" else {},
                        settings if origin == "managed" else {"default_action": "allow"},
                        required_action="allow",
                    )
                )
        for action in ordinary.ACTIONS:
            cases.append(
                MixedConfiguration(
                    f"managed-risk-{action}",
                    {},
                    action_setting("risk", action, harness, artifact_id),
                    required_action=action,
                )
            )
        for present in (False, True):
            cases.append(
                MixedConfiguration(
                    f"managed-risk-block-default-{'explicit-allow' if present else 'absent'}",
                    {"default_action": "warn", "risk_actions": {"local_secret_read": "allow"}},
                    {
                        "risk_actions": {"local_secret_read": "block"},
                        **({"default_action": "allow"} if present else {}),
                    },
                    required_action="block",
                )
            )
    return cases


def _toml(payload: dict[str, object], prefix: tuple[str, ...] = ()) -> str:
    lines = [f"[{'.'.join(json.dumps(key) for key in prefix)}]"] if prefix else []
    for key, value in payload.items():
        if not isinstance(value, dict):
            assert isinstance(value, str)
            lines.append(f"{json.dumps(key)} = {json.dumps(value)}")
    for key, value in payload.items():
        if isinstance(value, dict):
            lines.append(_toml(value, (*prefix, key)))
    return "\n".join(lines) + "\n"


def evaluate_case(
    source: dict[str, object], case: MixedConfiguration, mode: ordinary.Mode, guard_home: Path
) -> dict[str, object]:
    artifact = produce_sensitive_read(source)
    local: dict[str, object] = {
        "mode": mode,
        "security_level": "balanced",
        "default_action": "allow",
        "unknown_publisher_action": "review",
        "risk_actions": {"local_secret_read": "allow"},
        **deepcopy(case.local),
    }
    managed = deepcopy(case.managed)
    policy_input: dict[str, object] = {
        "schemaVersion": "hol-guard-mdm-policy.v1",
        "settings": managed,
        "lockedSettings": list(managed),
    }
    guard_home.mkdir(parents=True)
    (guard_home / "config.toml").write_text(_toml(local))
    policy = parse_managed_policy(policy_input)
    config = load_guard_config(
        guard_home, managed_policy_state=ManagedPolicyState("active", "synthetic-vector", policy=policy)
    )
    assert config.managed_policy is policy and config.local_policy_origin is not None
    # Replace only the configuration injection seam; producer, evaluator, review
    # and renderer are the actual implementations shared with the ordinary vectors.
    with patch.object(ordinary, "config_for", return_value=config):
        result = ordinary.evaluate_case(source, ordinary.Configuration(case.name), mode, guard_home)
    expected = result["expected"]
    assert isinstance(expected, dict)
    assert expected["evaluatedPolicyAction"] == case.required_action, case.name
    assert result["artifactId"] == artifact.artifact_id
    projection = project_managed_configuration(config)
    assert projection is not None
    result["configInputs"] = {"local": local, "managed": policy_input}
    result["localEffectivePolicy"] = effective_native_policy_v3(config.local_policy_origin)
    result["managedConfiguration"] = projection.to_mapping()
    return result


def generate_vectors(root: Path) -> dict[str, object]:
    sources = json.loads(SOURCE_FIXTURE.read_text())["cases"]
    selected: dict[str, dict[str, object]] = {}
    for source in sources:
        selected.setdefault(source["harness"], source)
    cases: list[dict[str, object]] = []
    for harness, source in sorted(selected.items()):
        artifact = produce_sensitive_read(source)
        for case in configurations(harness, artifact.artifact_id):
            for mode in ("enforce", "observe"):
                cases.append(evaluate_case(source, case, mode, root / str(len(cases))))
    return {
        "schema": "native-sensitive-read-mixed-origin-fixtures.v1",
        "source": "actual local/MDM loader, normalized producer, runtime evaluator and Observe review/finalizer",
        "contentBinding": "request path and tool identity only; no secret file bytes",
        "scope": "source component evidence; no native, installed, approval-consumption or capability acceptance",
        "projectionScope": "effectivePolicy is flattened; localEffectivePolicy and managedConfiguration retain origins",
        "cases": cases,
    }
