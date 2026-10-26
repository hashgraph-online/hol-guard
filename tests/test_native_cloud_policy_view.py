"""Actual native policy consumer bindings with synthetic local session IO."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import discovery
from codex_plugin_scanner.guard.managed_controls_policy_fields import ManagedControlsPolicyError
from codex_plugin_scanner.guard.runtime import extension_catalog_completion as cloud
from codex_plugin_scanner.guard.runtime import extension_catalog_pages as pages
from tests.native_cloud_helpers import native_bridge as native_bridge
from tests.native_cloud_helpers import prepare_native, synthetic_completion


def test_completed_local_policy_view_uses_native_bindings(tmp_path, monkeypatch, native_bridge):
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    view = prepare_native(count=1, home=tmp_path.resolve(), generated_at=now)
    handle = SimpleNamespace(root=view.discovery_root, authority=view.discovery_authority)
    monkeypatch.setattr(discovery, "installed_discovery", lambda _home: handle)
    monkeypatch.setattr(discovery, "require_handle", lambda value, _home: value)
    identity = dict(ownerUserId="owner", workspaceId="workspace", deviceId="device", runtimeId="runtime")
    summary = {
        "policyMetadataIdentity": identity,
        "runtime_credential_id": "runtime",
        "runtime_device_id": "device",
        "extensionCatalogViewDigest": view.manifest["catalogDigest"],
        "extensionCatalogEnforcementDigest": "a" * 64,
        "extensionCatalogGeneratedAt": now,
    }
    registry = SimpleNamespace(catalog_digest="a" * 64)
    summary["policyMetadataObservedAt"] = synthetic_completion(view, identity, now, native_bridge)["observedAt"]
    # Keep the production decoder, supplying only its already verified transport reply.
    from codex_plugin_scanner.guard import native_execution
    from tests.native_cloud_helpers import ORIGINAL_NATIVE_CALL

    monkeypatch.setattr(
        native_execution,
        "_resident_request",
        lambda *, request, **_kwargs: {
            "schema": "guard-cloud-catalog-result.v2",
            "payload": native_bridge(tmp_path, **{key: value for key, value in request.items() if key != "guard_home"}),
        },
    )
    monkeypatch.setattr(pages, "native_call", ORIGINAL_NATIVE_CALL)
    local = cloud.local_policy_view(guard_home=tmp_path, runtime_summary=summary, registry=registry)
    assert local["identity"] == identity
    assert local["observation"]["enforcement_catalog_digest"] == registry.catalog_digest
    assert local["token"] == view.token
    assert local["observed_at"] == summary["policyMetadataObservedAt"]
    for field, value, code in (
        ("runtime_credential_id", "other", "policy_observation_identity_mismatch"),
        ("runtime_device_id", "other", "policy_observation_identity_mismatch"),
        ("policyMetadataIdentity", {}, "policy_observation_identity_missing"),
        ("policyMetadataObservedAt", "", "policy_completed_observation_missing"),
        ("policyMetadataObservedAt", "2000-01-01T00:00:00Z", "policy_local_view_invalid"),
    ):
        with pytest.raises(ManagedControlsPolicyError) as caught:
            cloud.local_policy_view(guard_home=tmp_path, runtime_summary={**summary, field: value}, registry=registry)
        assert caught.value.code == code
    with pytest.raises(ManagedControlsPolicyError) as caught:
        cloud.local_policy_view(
            guard_home=tmp_path, runtime_summary=summary, registry=SimpleNamespace(catalog_digest="f" * 64)
        )
    assert caught.value.code == "policy_enforcement_digest_mismatch"
    handle.root = "f" * 64
    with pytest.raises(ManagedControlsPolicyError) as caught:
        cloud.local_policy_view(guard_home=tmp_path, runtime_summary=summary, registry=registry)
    assert caught.value.code == "policy_local_view_invalid"


def test_native_policy_error_keeps_public_error_code(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard import native_execution

    monkeypatch.setattr(
        native_execution,
        "_resident_request",
        lambda **_kwargs: {
            "schema": "guard-cloud-catalog-result.v2",
            "payload": {
                "policy_error": "policy_observation_identity_mismatch",
                "message": "Policy observation session identity changed.",
            },
        },
    )
    with pytest.raises(ManagedControlsPolicyError, match="Policy observation session identity changed") as caught:
        pages.native_call(tmp_path, action="policy_view")
    assert caught.value.code == "policy_observation_identity_mismatch"
