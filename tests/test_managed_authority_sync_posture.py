from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import discovery
from codex_plugin_scanner.guard.runtime import (
    extension_catalog_completion,
    extension_catalog_pages,
    extension_catalog_posture_cache,
    extension_catalog_sync,
    managed_controls_sync,
    runner,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_catalog_handshake import runtime_session_success_summary
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import build_managed_controls_runtime_posture
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture
def completed_catalog(monkeypatch):
    """Supply verified catalog/completion IO; revisions still come from the authority read."""
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    state = SimpleNamespace(captured=True, completed=True, registry=registry)

    def capture(_store):
        if not state.captured:
            raise ValueError("Authenticated active catalog unavailable")
        return registry

    manifest = {
        "catalogDigest": "b" * 64,
        "enforcementCatalogDigest": registry.catalog_digest,
        "generatedAt": "2026-08-25T00:00:00Z",
        "controlSchemaVersion": "guard.extension-controls.v1",
    }
    monkeypatch.setattr(managed_controls_sync, "current_catalog_registry", capture)
    monkeypatch.setattr(
        extension_catalog_pages,
        "prepare_installed_catalog_view",
        lambda *_args, **_kwargs: SimpleNamespace(manifest=manifest),
    )
    monkeypatch.setattr(extension_catalog_sync, "build_v1_catalog_from_view", lambda _view: {"catalogDigest": "c" * 64})
    monkeypatch.setattr(extension_catalog_completion, "policy_view_ready", lambda **_kwargs: state.completed)
    read = GuardStore.get_sync_payload
    summary = {
        "policyMetadataIdentity": {
            "ownerUserId": "owner",
            "workspaceId": "workspace",
            "deviceId": "device",
            "runtimeId": "runtime",
        }
    }
    monkeypatch.setattr(
        GuardStore,
        "get_sync_payload",
        lambda store, key: summary if key == "runtime_session_summary" else read(store, key),
    )
    return state


def test_connected_install_advertises_the_catalog_without_a_manual_switch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, completed_catalog
) -> None:
    monkeypatch.delenv("GUARD_EXTENSION_CATALOG_SYNC_V1", raising=False)
    # Stop before the authority read: the flag gate is what this test pins.
    completed_catalog.completed = False
    store = GuardStore(tmp_path / "guard-home")
    posture = runner._managed_controls_runtime_sync_posture(store, generated_at="2026-08-25T00:00:00Z")
    assert posture["managedControlsCapabilities"] == ["extension-catalog.v2"]
    assert posture["extensionCatalogDigest"] == "c" * 64

    monkeypatch.setenv("GUARD_EXTENSION_CATALOG_SYNC_V1", "false")
    assert runner._managed_controls_runtime_sync_posture(store, generated_at="2026-08-25T00:00:00Z") == {}


def test_connected_syncs_reuse_one_prepared_catalog_view(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, completed_catalog
) -> None:
    monkeypatch.delenv("GUARD_EXTENSION_CATALOG_SYNC_V1", raising=False)
    monkeypatch.setattr(extension_catalog_posture_cache, "_entries", {})
    completed_catalog.completed = False
    store = GuardStore(tmp_path / "guard-home")
    current = {"handle": SimpleNamespace(root="root-1", authority="authority-1")}
    monkeypatch.setattr(discovery, "installed_discovery", lambda _home: current["handle"])
    monkeypatch.setattr(discovery, "require_handle", lambda handle, _home: handle)
    resident = {"evicted": False}

    def native_call(_home: Path, **request: object) -> dict[str, object]:
        if request["action"] == "acquire":
            if resident["evicted"]:
                raise ValueError("Native complete catalog producer rejected metadata")
            return {"lease": "lease"}
        assert request["action"] == "release"
        return {}

    prepared: list[str] = []

    def prepare(guard_home: Path, **_kwargs: object) -> extension_catalog_pages.PreparedCatalogView:
        prepared.append(str(guard_home))
        manifest = {
            "catalogDigest": "b" * 64,
            "enforcementCatalogDigest": completed_catalog.registry.catalog_digest,
            "generatedAt": "2026-08-25T00:00:00Z",
            "controlSchemaVersion": "guard.extension-controls.v1",
        }
        handle = current["handle"]
        return extension_catalog_pages.PreparedCatalogView(
            guard_home, f"token-{len(prepared)}", json.dumps(manifest).encode(), handle.root, handle.authority
        )

    monkeypatch.setattr(extension_catalog_pages, "native_call", native_call)
    monkeypatch.setattr(extension_catalog_pages, "prepare_installed_catalog_view", prepare)

    def posture() -> dict[str, object]:
        return runner._managed_controls_runtime_sync_posture(store, generated_at="2026-08-25T00:00:00Z")

    # Repeated syncs advertise the same catalog from one preparation.
    assert posture()["extensionCatalogDigest"] == "c" * 64
    assert posture()["extensionCatalogViewDigest"] == "b" * 64
    assert len(prepared) == 1

    # A view the resident no longer holds is prepared again.
    resident["evicted"] = True
    posture()
    assert len(prepared) == 2
    resident["evicted"] = False

    # So is one observed under a different discovery handle.
    current["handle"] = SimpleNamespace(root="root-2", authority="authority-1")
    posture()
    assert len(prepared) == 3
    posture()
    assert len(prepared) == 3


@pytest.mark.parametrize(("local_revision", "managed_revision"), [(0, 0), (0, 1), (7, 1), (7, 2)])
def test_cloud_sync_preserves_independent_protected_revisions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, local_revision: int, managed_revision: int, completed_catalog
) -> None:
    monkeypatch.setenv("GUARD_EXTENSION_CATALOG_SYNC_V1", "true")
    monkeypatch.setenv("GUARD_MANAGED_EXTENSION_CONTROLS_V1", "true")
    authority = ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED,
        local_revision,
        completed_catalog.registry.catalog_digest,
        (),
        managed_revision=managed_revision,
    )
    monkeypatch.setattr(
        GuardStore, "read_extension_control_authority_for_registry", lambda *_args, **_kwargs: authority
    )
    payload = runner._cloud_runtime_session_payload(
        GuardStore(tmp_path / "guard-home"),
        {"session_id": "runtime-session-1", "updated_at": "2026-08-25T00:00:00Z"},
    )
    assert payload["extensionAuthorityRevision"] == local_revision
    assert payload["managedExtensionAuthorityRevision"] == managed_revision
    summary = runtime_session_success_summary(
        session_payload=payload, response_payload={}, synced_at="2026-08-25T00:00:00Z", catalog_sync={}
    )
    assert summary["extensionAuthorityRevision"] == local_revision
    assert summary["managedExtensionAuthorityRevision"] == managed_revision


def test_unavailable_authority_does_not_fabricate_managed_revision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, completed_catalog
) -> None:
    monkeypatch.setenv("GUARD_EXTENSION_CATALOG_SYNC_V1", "true")
    monkeypatch.setenv("GUARD_MANAGED_EXTENSION_CONTROLS_V1", "true")
    authority = ExtensionControlAuthorityView(
        AuthorityHealth.TAMPERED, 7, completed_catalog.registry.catalog_digest, (), managed_revision=2
    )
    monkeypatch.setattr(
        GuardStore, "read_extension_control_authority_for_registry", lambda *_args, **_kwargs: authority
    )
    posture = runner._managed_controls_runtime_sync_posture(
        GuardStore(tmp_path / "guard-home"), generated_at="2026-08-25T00:00:00Z"
    )
    assert "managedExtensionAuthorityRevision" not in posture
    assert posture["extensionAuthorityRevision"] is None
    summary = runtime_session_success_summary(
        session_payload={
            **posture,
            "sessionId": "runtime-session-1",
            "deviceId": "device-1",
            "harness": "codex",
            "surface": "cli",
            "workspace": "local-machine",
        },
        response_payload={},
        synced_at="2026-08-25T00:00:00Z",
        catalog_sync={},
    )
    assert "managedExtensionAuthorityRevision" not in summary


@pytest.mark.parametrize("boundary", ["captured", "completed"])
def test_unavailable_catalog_or_completion_never_advertises_managed_authority(
    monkeypatch, tmp_path, completed_catalog, boundary
):
    monkeypatch.setenv("GUARD_EXTENSION_CATALOG_SYNC_V1", "true")
    monkeypatch.setenv("GUARD_MANAGED_EXTENSION_CONTROLS_V1", "true")
    setattr(completed_catalog, boundary, False)
    posture = runner._managed_controls_runtime_sync_posture(
        GuardStore(tmp_path / "guard-home"), generated_at="2026-08-25T00:00:00Z"
    )
    assert "managedExtensionAuthorityRevision" not in posture
    assert "extension-control-layer.v1" not in posture["managedControlsCapabilities"]
    if boundary == "captured":
        assert posture == {"managedControlsCapabilities": []}


@pytest.mark.parametrize("revision", [True, -1, 1.5, "1", 2**53])
def test_wire_rejects_non_integer_or_unrepresentable_managed_revision(revision: object) -> None:
    with pytest.raises(ValueError, match="nonnegative safe integer"):
        build_managed_controls_runtime_posture(
            catalog_digest="a" * 64,
            managed_extension_authority_revision=revision,  # type: ignore[arg-type]
        )


def test_unknown_managed_revision_is_distinct_from_initial_zero() -> None:
    assert "managedExtensionAuthorityRevision" not in build_managed_controls_runtime_posture(catalog_digest="a" * 64)
    assert (
        build_managed_controls_runtime_posture(catalog_digest="a" * 64, managed_extension_authority_revision=0)[
            "managedExtensionAuthorityRevision"
        ]
        == 0
    )
