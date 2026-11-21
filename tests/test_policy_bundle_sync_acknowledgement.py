"""The stored policy bundle acknowledgement the cloud sync may report."""

from __future__ import annotations

from codex_plugin_scanner.guard import policy_bundle_delivery
from codex_plugin_scanner.guard.native_policy_bundle import PolicyBundleNativeUnavailableError
from codex_plugin_scanner.guard.policy_bundle_delivery import reportable_policy_bundle_acknowledgement

_LEGACY = {
    "bundleHash": "sha256:bundle-3",
    "bundleVersion": "3",
    "deviceId": "dev-1",
    "deviceName": "Dev One",
    "status": "synced",
    "appliedAt": "2026-07-15T12:00:00Z",
}
_V2 = {
    "contractVersion": "guard-policy-bundle.v2",
    "workspaceId": "workspace-alpha",
    "deviceId": "dev-1",
    "bundleVersion": 8,
    "bundleHash": "sha256:" + "1" * 64,
    "sequence": 1,
    "status": "applied",
    "observedAt": "2026-07-15T12:00:00Z",
    "errorCode": None,
}


def _report(acknowledgement: dict[str, object], bundle: object) -> tuple[object, int]:
    calls = 0

    def validated_bundle() -> object:
        nonlocal calls
        calls += 1
        return bundle

    reported = reportable_policy_bundle_acknowledgement(
        acknowledgement,
        device_id="dev-1",
        device_name="Dev One",
        validated_bundle=validated_bundle,
    )
    return reported, calls


def test_a_legacy_acknowledgement_matching_the_validated_bundle_is_reported() -> None:
    bundle = {"bundleHash": "sha256:bundle-3", "bundleVersion": "3", "payload": {"rules": []}}
    assert _report(dict(_LEGACY), bundle) == (_LEGACY, 1)


def test_a_legacy_acknowledgement_for_another_bundle_is_dropped() -> None:
    bundle = {"bundleHash": "sha256:bundle-4", "bundleVersion": "4"}
    assert _report(dict(_LEGACY), bundle) == (None, 1)


def test_a_legacy_acknowledgement_without_a_validated_bundle_is_dropped() -> None:
    assert _report(dict(_LEGACY), None) == (None, 1)


def test_a_v2_acknowledgement_never_validates_the_bundle() -> None:
    assert _report(dict(_V2), None) == (_V2, 0)
    assert _report({**_V2, "status": "unknown"}, None) == (None, 0)


def test_nothing_is_reported_when_the_native_runtime_is_unavailable(monkeypatch) -> None:
    def unavailable(_kind: str, _request: dict[str, object]) -> dict[str, object]:
        raise PolicyBundleNativeUnavailableError("native_policy_bundle_unavailable", {})

    monkeypatch.setattr(policy_bundle_delivery, "policy_bundle_verdict", unavailable)
    assert _report(dict(_LEGACY), {"bundleHash": "sha256:bundle-3", "bundleVersion": "3"}) == (None, 0)
