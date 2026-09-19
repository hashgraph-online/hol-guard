"""Actual session projection advertises descriptive source support without readiness."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.policy_runtime_posture import cloud_policy_runtime_posture
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.version import __version__


def test_session_carries_source_catalog_without_claiming_an_active_lane(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(runner, "_safe_hostname", lambda: "fixture-host")
    monkeypatch.setattr(runner, "_safe_private_ip", lambda: None)
    monkeypatch.setattr(runner, "_safe_private_ipv6", lambda: None)
    session: dict[str, object] = {
        "session_id": "fixture-session",
        "workspace": str(tmp_path),
        "created_at": "2026-09-18T00:00:00Z",
        "updated_at": "2026-09-18T00:00:00Z",
        "capabilities": ["existing-capability"],
        "policy_bundle_versions": ["guard-policy-bundle.v1"],
        "runtimeLaneProfile": {"selectedLane": "forged", "readiness": "ready"},
    }
    payload = runner._cloud_runtime_session_payload(store, session)
    assert payload["runtimeLaneProfile"] == {
        "contractVersion": "guard.runtime-lane-observation.v1",
        "profileId": "guard.runtime-lanes.v1",
        "runtimeVersion": __version__,
        "selectedLane": None,
        "readiness": "unavailable",
    }
    assert payload["capabilities"] == ["existing-capability"]
    assert payload["policyBundleVersions"] == ["guard-policy-bundle.v1"]
    assert "canonicalPolicyEnforcement" not in payload
    expected = cloud_policy_runtime_posture(store, device_id=str(payload["deviceId"]))
    for name, value in expected.items():
        assert payload[name] == value
    labels = payload["localIdentitySource"]
    profile = payload["runtimeLaneProfile"]
    assert isinstance(labels, dict) and isinstance(profile, dict)
    assert labels["hostname"] == "local-guard"
    profile["readiness"] = "forged"
    second = runner._cloud_runtime_session_payload(store, session)
    next_profile = second["runtimeLaneProfile"]
    assert isinstance(next_profile, dict) and next_profile["readiness"] == "unavailable"


def test_extracted_identity_labels_preserve_only_present_fields():
    assert runner._cloud_local_identity_source_payload({"hostname": "fixture", "publicIpAddress": "fixture"}) == {
        "daemonId": "local-guard",
        "daemonVersion": "local-guard",
        "daemonStatus": "local-guard",
        "relayState": "local-guard",
        "hostname": "local-guard",
        "publicIpAddress": "local-guard",
    }
