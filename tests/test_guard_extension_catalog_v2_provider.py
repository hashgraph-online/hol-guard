"""CAS adapter and runtime integration tests with factory/transport test doubles."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import extension_catalog_pages as pages
from codex_plugin_scanner.guard.runtime import runner
from tests.native_cloud_helpers import native_bridge as native_bridge
from tests.native_cloud_helpers import prepare_native, raw
from tests.test_guard_extension_catalog_v2 import NOW, Receiver, posture, prepare, signal

pytestmark = pytest.mark.usefixtures("native_bridge")


@pytest.fixture(autouse=True)
def unit_active_authority(monkeypatch):
    # These are factory/transport seam units. Authenticated active authority and
    # actual completion are exercised by native integration/HTTP suites.
    from codex_plugin_scanner.guard.runtime import managed_controls_sync as controls
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    monkeypatch.setattr(controls, "current_catalog_registry", lambda _: BUILT_IN_COMMAND_EXTENSION_REGISTRY)


@pytest.mark.parametrize("known", [False, True])
def test_runtime_v2_uses_existing_authenticated_request_transport(monkeypatch, known):
    view = prepare(166)
    session = posture(view)
    receiver = Receiver()
    auth = {"synthetic": "context"}

    def request(context, *, request_url, method, data, extra_headers):
        assert context is auth and method == "POST" and extra_headers is None
        return request_url, data

    def transport(*, request, max_response_bytes, **kwargs):
        assert max_response_bytes == 4096
        return receiver.send(*request)

    monkeypatch.setattr(runner, "_guard_sync_request", request)
    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", transport)
    from codex_plugin_scanner.guard.runtime import extension_catalog_completion as completion

    completed = []

    def observe(**kwargs):
        completed.append(kwargs)
        return {"completion_adapter_invoked": True}

    monkeypatch.setattr(completion, "complete_authenticated_view", observe)
    store = SimpleNamespace(guard_home=view.guard_home)
    summary = runner._sync_extension_catalog_from_runtime_handshake(
        store=store,
        guard_home=view.guard_home,
        auth_context=auth,
        runtime_sync_url="https://example.test/api/guard/runtime/sessions/sync?tenant=fixture",
        runtime_response=signal(view, known=known),
        session_payload=session,
    )
    assert receiver.accepted is not known
    assert summary["extension_catalog_sync_status"] == ("already_known" if known else "uploaded")
    assert completed[0]["store"] is store and completed[0]["auth_context"] is auth
    assert completed[0]["url"] == "https://example.test/api/guard/runtime/extension-catalog/sync-v2?tenant=fixture"


def test_same_root_heartbeat_retry_reuses_manifest_and_key():
    first = prepare(7)
    again = prepare_native(7, home=first.guard_home, generated_at="2026-10-18T01:00:00Z")
    assert again.manifest == first.manifest and again.token == first.token
    observed = pages.observed_view(posture(first), first.guard_home)
    assert observed.manifest == first.manifest


def test_active_catalog_change_during_preparation_withdraws_the_view(monkeypatch):
    from codex_plugin_scanner.guard.runtime import managed_controls_sync as controls

    monkeypatch.setenv("GUARD_EXTENSION_CATALOG_SYNC_V1", "true")
    view = prepare(166)
    registries = iter([SimpleNamespace(catalog_digest="a" * 64), SimpleNamespace(catalog_digest="f" * 64)])
    monkeypatch.setattr(controls, "current_catalog_registry", lambda _: next(registries))
    monkeypatch.setattr(pages, "prepare_installed_catalog_view", lambda *_, **__: view)
    assert controls.managed_controls_runtime_sync_posture(
        SimpleNamespace(guard_home=view.guard_home), generated_at=NOW
    ) == {"managedControlsCapabilities": []}


def test_missing_factory_never_advertises_sparse_active_catalog(monkeypatch):
    from codex_plugin_scanner.guard.runtime.managed_controls_sync import managed_controls_runtime_sync_posture

    monkeypatch.setenv("GUARD_EXTENSION_CATALOG_SYNC_V1", "true")

    def unavailable(*args, **kwargs):
        raise ImportError("metadata factory not integrated")

    monkeypatch.setattr(pages, "prepare_installed_catalog_view", unavailable)
    with pytest.raises(RuntimeError, match="discovery factory is unavailable"):
        managed_controls_runtime_sync_posture(SimpleNamespace(guard_home=Path("/fixture")), generated_at=NOW)


def test_oversized_posture_advertises_prepared_transport_only(monkeypatch):
    from codex_plugin_scanner.guard.runtime import managed_controls_sync as controls

    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(name, "true")
    view = prepare(1660)
    monkeypatch.setattr(pages, "prepare_installed_catalog_view", lambda *args, **kwargs: view)
    monkeypatch.setattr(
        controls, "_authority_posture", lambda *args, **kwargs: pytest.fail("legacy delivery advertised")
    )
    result = controls.managed_controls_runtime_sync_posture(
        SimpleNamespace(guard_home=Path("/fixture")),
        generated_at=NOW,
    )
    assert result["managedControlsCapabilities"] == ["extension-catalog.v2"]
    assert "extensionCatalogDigest" not in result
    assert result["extensionCatalogViewDigest"] == view.manifest["catalogDigest"]


def test_native_cache_loss_withdraws_posture_capabilities(monkeypatch):
    from codex_plugin_scanner.guard.runtime import extension_catalog_sync as wire
    from codex_plugin_scanner.guard.runtime import managed_controls_sync as controls

    monkeypatch.setenv("GUARD_EXTENSION_CATALOG_SYNC_V1", "true")
    view = prepare(1)
    monkeypatch.setattr(pages, "prepare_installed_catalog_view", lambda *_, **__: view)

    def unavailable(_):
        raise ValueError("native cache observation was evicted")

    monkeypatch.setattr(wire, "build_v1_catalog_from_view", unavailable)
    assert controls.managed_controls_runtime_sync_posture(
        SimpleNamespace(guard_home=view.guard_home), generated_at=NOW
    ) == {"managedControlsCapabilities": []}


def test_old_server_uploads_same_observed_complete_view(monkeypatch):
    from codex_plugin_scanner.guard.runtime.extension_catalog_sync import build_v1_catalog_from_view

    view = prepare(166)
    catalog = build_v1_catalog_from_view(view)
    session = {**posture(view), "extensionCatalogDigest": catalog["catalogDigest"]}
    uploads = []

    def request(context, **kwargs):
        uploads.append(json.loads(kwargs["data"]))
        return object()

    def response(**kwargs):
        return {
            "schemaVersion": "guard.extension-catalog-sync.v1",
            "accepted": True,
            "catalogDigest": catalog["catalogDigest"],
            "alreadyKnown": False,
            "deviceCount": 1,
            "firstSeenAt": NOW,
            "lastSeenAt": NOW,
        }

    monkeypatch.setattr(runner, "_guard_sync_request", request)
    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", response)
    monkeypatch.setattr(
        runner, "build_builtin_extension_catalog_wire", lambda **kwargs: pytest.fail("rebuilt sparse view")
    )
    result = runner._sync_extension_catalog_from_runtime_handshake(
        guard_home=view.guard_home,
        auth_context={},
        runtime_sync_url="https://example.test/api/guard/runtime/sessions/sync",
        session_payload=session,
        runtime_response={
            "extensionCatalogSync": {
                "catalogDigest": catalog["catalogDigest"],
                "catalogKnown": False,
                "uploadRequired": True,
                "uploadPath": "/api/guard/runtime/extension-catalog/sync",
            }
        },
    )
    assert uploads[0]["catalog"] == catalog
    assert result["extension_catalog_sync_status"] == "uploaded"


def test_runtime_json_reply_budget(monkeypatch):
    import io

    class Reply(io.BytesIO):
        pass

    monkeypatch.setattr(runner, "managed_urlopen", lambda *args, **kwargs: Reply(b"x" * 4097))
    with pytest.raises(RuntimeError, match="byte budget"):
        runner._urlopen_json_with_timeout_retry(
            request=object(),
            timeout_seconds=1,
            retry_timeout_seconds=1,
            max_response_bytes=4096,
        )


def test_provider_delegates_raw_active_metadata_and_factory_authentication(monkeypatch, tmp_path):

    view = prepare_native(2)
    handle = SimpleNamespace(root=view.discovery_root, authority=view.discovery_authority)
    factory_calls = []

    def require(value, home):
        assert value is handle and home == view.guard_home
        factory_calls.append(value)
        return value

    monkeypatch.setitem(
        sys.modules,
        "codex_plugin_scanner.guard.catalog_delivery.discovery",
        SimpleNamespace(installed_discovery=lambda _: handle, require_handle=require),
    )
    active = SimpleNamespace(**{**raw(1), "name": "Active authoritative", "permissions": ()})
    result = pages.prepare_installed_catalog_view(
        view.guard_home,
        registry=SimpleNamespace(extensions=(active,), catalog_digest="a" * 64),
        guard_version="3.49.0",
        generated_at=NOW,
    )
    assert len(factory_calls) == 3
    assert next(iter(result.pages()))["entries"][1]["name"] == "Active authoritative"
    assert "PRIVATE-SENTINEL" not in pages.encoded(list(result.pages())).decode()


def test_native_resident_delegation_has_no_python_fallback(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard import native_execution

    # Undo the CLI fixture bridge only for this unit-level resident contract check.
    from tests.native_cloud_helpers import ORIGINAL_NATIVE_CALL

    original = ORIGINAL_NATIVE_CALL
    calls = []

    def resident(**kwargs):
        calls.append(kwargs)
        return {"schema": "guard-cloud-catalog-result.v2", "payload": {"native": True}}

    monkeypatch.setattr(native_execution, "_resident_request", resident)
    assert original(tmp_path, action="observe") == {"native": True}
    assert calls[0]["operation"] == "cloud_catalog"
    assert calls[0]["required_feature"] == "cloud-catalog-producer-v2"
    assert calls[0]["guard_home"] == tmp_path
    monkeypatch.setattr(native_execution, "_resident_request", lambda **_: None)
    with pytest.raises(RuntimeError, match="unavailable"):
        original(tmp_path, action="observe")


def test_actual_resident_accepts_native_catalog_payload_without_status(native_hook_force):
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.native_cloud_helpers import ORIGINAL_NATIVE_CALL

    view = prepare_native(2)
    provision_native_verifier_key_for_store(GuardStore(view.guard_home))
    try:
        result = ORIGINAL_NATIVE_CALL(
            view.guard_home,
            action="observe",
            view_digest=view.manifest["catalogDigest"],
            enforcement_digest=view.manifest["enforcementCatalogDigest"],
            generated_at=view.manifest["generatedAt"],
        )
        assert result["token"] == view.token
    finally:
        close_native_residents(view.guard_home)


@pytest.mark.parametrize(
    "frame",
    [
        {"schema": "guard-cloud-catalog-result.v2", "error": {}},
        {"schema": "guard-cloud-catalog-result.v2", "payload": []},
        {"schema": "guard-cloud-catalog-result.v2", "payload": {}, "status": "ok"},
        {"schema": "wrong", "payload": {}},
        {"schema": "guard-cloud-catalog-result.v2", "error": "unknown"},
        {"schema": "guard-cloud-catalog-result.v2"},
    ],
)
def test_catalog_reply_union_rejects_malformed_frames(monkeypatch, tmp_path, frame):
    # Negative transport-decoder unit only; this is not native/HTTP evidence.
    from codex_plugin_scanner.guard import native_execution

    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "synthetic-runtime", sha256="a" * 64),
        capabilities=SimpleNamespace(features=["resident-protocol-v2", "cloud-catalog-producer-v2"]),
    )
    monkeypatch.setattr(native_execution, "native_resident_client_request", lambda **_: json.dumps(frame).encode())
    assert (
        native_execution._resident_request(
            operation="cloud_catalog",
            request={},
            guard_home=tmp_path,
            timeout_seconds=1,
            required_feature="cloud-catalog-producer-v2",
            status=status,
            response_schema="guard-cloud-catalog-result.v2",
            record_resilience=False,
            record_success=False,
        )
        is None
    )
