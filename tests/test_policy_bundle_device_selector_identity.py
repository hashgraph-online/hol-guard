"""HGP-161: device selectors match stable installation identity."""

from __future__ import annotations

from codex_plugin_scanner.guard.policy_bundle_decisions import build_policy_bundle_decisions
from codex_plugin_scanner.guard.policy_bundle_device_selector import (
    device_selector_matches_installation,
    selected_installation_acknowledgement,
)


def _bundle(devices: list[str], artifact_id: str = "codex:project:target") -> dict[str, object]:
    return {
        "rules": [
            {
                "ruleId": "device-rule",
                "action": "block",
                "reason": "device targeted",
                "artifactId": artifact_id,
                "scope": {"harnesses": ["codex"], "devices": devices, "environments": []},
            }
        ]
    }


def test_human_name_collision_does_not_widen_policy() -> None:
    bundle = _bundle(["Laptop"])
    host_a = build_policy_bundle_decisions(bundle, device_id="install-a", device_name="Laptop")
    host_b = build_policy_bundle_decisions(bundle, device_id="install-b", device_name="Laptop")
    assert host_a == []
    assert host_b == []


def test_installation_id_targets_only_selected_device() -> None:
    bundle = _bundle(["install-a"])
    selected = build_policy_bundle_decisions(bundle, device_id="install-a", device_name="Laptop")
    other = build_policy_bundle_decisions(bundle, device_id="install-b", device_name="Laptop")
    assert [row.artifact_id for row in selected] == ["codex:project:target"]
    assert other == []
    ack = selected_installation_acknowledgement(device_id="install-a", device_name="Laptop")
    assert ack["deviceId"] == "install-a"
    assert ack["targetingIdentity"] == "installation_id"


def test_rename_keeps_installation_identity() -> None:
    assert device_selector_matches_installation(["install-a"], device_id="install-a") is True
    assert device_selector_matches_installation(["Old Name"], device_id="install-a") is False


def test_reinstall_with_new_identity_is_not_selected() -> None:
    bundle = _bundle(["install-old"])
    assert build_policy_bundle_decisions(bundle, device_id="install-new", device_name="Laptop") == []
