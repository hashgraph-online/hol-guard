"""Real loaded selectors retain independent managed policy requirements."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import load_guard_config, resolve_risk_action
from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
from codex_plugin_scanner.guard.mdm.policy import parse_managed_policy


def loaded(tmp_path: Path, local: str, settings: dict[str, object]):
    (tmp_path / "config.toml").write_text('mode="enforce"\ndefault_action="allow"\n' + local)
    policy = parse_managed_policy(
        {"schemaVersion": "hol-guard-mdm-policy.v1", "settings": settings, "lockedSettings": list(settings)}
    )
    config = load_guard_config(
        tmp_path, managed_policy_state=ManagedPolicyState("active", "synthetic-origin", policy=policy)
    )
    assert config.managed_policy is policy
    return config


@pytest.mark.parametrize(
    ("local", "settings", "artifact", "publisher", "expected"),
    [
        ('[artifacts]\ntarget="allow"\n', {"default_action": "block"}, "target", None, "block"),
        ('[publishers]\nvendor="allow"\n', {"default_action": "block"}, "other", "vendor", "block"),
        ('[harnesses]\ncodex="allow"\n', {"default_action": "block"}, "other", None, "block"),
        ('[artifacts]\ntarget="allow"\n', {"harnesses": {"codex": "block"}}, "target", None, "block"),
        ('[artifacts]\ntarget="allow"\n', {"publishers": {"vendor": "block"}}, "target", "vendor", "block"),
        ('[artifacts]\ntarget="allow"\n', {"publishers": {"other": "block"}}, "target", "vendor", "allow"),
        ("", {"default_action": "block", "artifacts": {"target": "allow"}}, "target", None, "allow"),
        ("", {"default_action": "block", "artifacts": {"target": "allow"}}, "other", None, "block"),
        ("", {"default_action": "block", "harnesses": {"codex": "review"}}, "other", None, "review"),
        ("", {"default_action": "block", "artifacts": {"target": {"action": "allow"}}}, "target", None, "allow"),
        ('[artifacts]\ntarget="block"\n', {"artifacts": {"target": "allow"}}, "target", None, "block"),
        ('[artifacts]\ntarget="warn"\n', {}, "target", None, "warn"),
        ("", {}, "target", None, None),
        ('[artifacts]\ntarget="allow"\n', {"default_action": "unrecognized"}, "target", None, "block"),
    ],
)
def test_managed_selector_precedence_stays_within_its_source(
    tmp_path: Path, local: str, settings: dict[str, object], artifact: str, publisher: str | None, expected: str | None
) -> None:
    config = loaded(tmp_path, local, settings)
    assert config.resolve_action_override("codex", artifact, publisher) == expected


@pytest.mark.parametrize(
    ("local", "settings", "risk", "expected"),
    [
        (
            '[harness_risk_actions.codex]\nlocal_secret_read="allow"\n',
            {"risk_actions": {"local_secret_read": "block"}},
            "local_secret_read",
            "block",
        ),
        (
            '[risk_actions]\nlocal_secret_read="allow"\n',
            {
                "risk_actions": {"local_secret_read": "block"},
                "harness_risk_actions": {"codex": {"local_secret_read": "review"}},
            },
            "local_secret_read",
            "review",
        ),
        (
            '[risk_actions]\nlocal_secret_read="block"\n',
            {"risk_actions": {"local_secret_read": "warn"}},
            "local_secret_read",
            "block",
        ),
        (
            '[harness_risk_actions.codex]\ncredential_exfiltration="allow"\n',
            {"security_level": "paranoid"},
            "credential_exfiltration",
            "block",
        ),
        (
            '[risk_actions]\nlocal_secret_read="allow"\n',
            {},
            "local_secret_read",
            "allow",
        ),
        (
            '[harness_risk_actions.codex]\ncredential_exfiltration="allow"\n',
            {"security_level": "paranoid", "protection_posture": "watch"},
            "credential_exfiltration",
            "block",
        ),
    ],
)
def test_managed_risk_is_independent_from_local_risk_priority(
    tmp_path: Path, local: str, settings: dict[str, object], risk: str, expected: str
) -> None:
    config = loaded(tmp_path, local, settings)
    assert resolve_risk_action(config, risk, harness="codex") == expected
