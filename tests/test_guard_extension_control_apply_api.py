"""Daemon Extension control apply flow: proof checks, runtime refresh and managed layers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon import extension_control_api as extension_control_api_module
from codex_plugin_scanner.guard.daemon.extension_control_api import (
    ExtensionControlApiError,
    ExtensionControlApiService,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
    layers_to_json,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_proof import ExtensionControlProof
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_extension_control_api import _mutation_payload, _service


@dataclass
class _FakeProof:
    proof_id: str = "proof-1"


class _ApplyingStore:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.events: list[tuple[str, dict[str, object], str]] = []
        self.commits = 0
        self.committed_layers: tuple[ExtensionControlLayer, ...] | None = None
        self.managed_layers: tuple[ExtensionControlLayer, ...] = ()
        self.managed_revision = 0
        self.current_view = ExtensionControlAuthorityView(
            AuthorityHealth.PROTECTED,
            4,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            (),
        )

    def commit_extension_control_layers(
        self,
        layers: tuple[ExtensionControlLayer, ...],
        **_kwargs: object,
    ) -> ExtensionControlAuthorityView:
        self.commits += 1
        self.committed_layers = layers
        self.current_view = ExtensionControlAuthorityView(
            AuthorityHealth.PROTECTED,
            5,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers,
        )
        return self.current_view

    def read_extension_control_authority(
        self,
        *,
        catalog_digest: str,
    ) -> ExtensionControlAuthorityView:
        assert catalog_digest == self.current_view.catalog_digest
        return self.current_view

    def read_extension_control_authority_for_registry(
        self,
        _registry: object,
        **kwargs: object,
    ) -> ExtensionControlAuthorityView:
        if kwargs.get("include_managed_controls") is False:
            return self.current_view
        base_layers = (
            tuple(layer for layer in self.current_view.layers if layer.kind is ControlLayerKind.LOCAL_ADMIN)
            if self.managed_layers
            else self.current_view.layers
        )
        return ExtensionControlAuthorityView(
            self.current_view.health,
            self.current_view.revision,
            self.current_view.catalog_digest,
            (*base_layers, *self.managed_layers),
            self.managed_revision,
        )

    def add_event(self, event_name: str, payload: dict[str, object], now: str) -> None:
        self.events.append((event_name, payload, now))


def test_apply_requires_matching_server_held_proof_and_refreshes_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _ApplyingStore(tmp_path / "guard-home")
    service = _service(cast(GuardStore, store))
    monkeypatch.setattr(
        extension_control_api_module,
        "issue_extension_control_proof",
        lambda *_args, **_kwargs: cast(ExtensionControlProof, _FakeProof()),
    )
    payload = _mutation_payload()
    payload.update(
        {
            "session_nonce": "session-1",
            "approval_password": "not-persisted",
        }
    )

    preview = service.preview(payload)
    apply_payload = {**payload, "proof_id": preview["proof_id"]}
    result = service.apply(apply_payload)

    assert result["revision"] == 5
    assert store.commits == 1
    assert store.events[0][0] == "extension_control_authority_changed"
    assert "local-admin" not in json.dumps(store.events[0][1])
    assert service.apply(apply_payload) == result
    assert store.commits == 1
    assert len(store.events) == 1
    with pytest.raises(ExtensionControlApiError) as mismatch:
        service.apply({**apply_payload, "nonce": "different"})
    assert mismatch.value.code == "proof_mismatch"


def test_local_apply_does_not_persist_composed_managed_layer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _ApplyingStore(tmp_path / "guard-home")
    managed_layer = ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind.SIGNED_CLOUD,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        False,
        (),
    )
    service = ExtensionControlApiService(
        store=cast(GuardStore, store),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(
            ExtensionControlAuthorityView(
                AuthorityHealth.PROTECTED,
                4,
                BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
                (managed_layer,),
                1,
            )
        ),
    )
    store.managed_layers = (managed_layer,)
    store.managed_revision = 1
    monkeypatch.setattr(
        extension_control_api_module,
        "issue_extension_control_proof",
        lambda *_args, **_kwargs: cast(ExtensionControlProof, _FakeProof()),
    )
    payload = _mutation_payload()
    payload["layers"] = json.loads(layers_to_json((managed_layer,)))
    payload.update({"session_nonce": "session-1", "approval_password": "not-persisted"})

    preview = service.preview(payload)
    _ = service.apply({**payload, "proof_id": preview["proof_id"]})

    assert store.committed_layers == ()


def test_local_apply_preserves_signed_layer_from_raw_base(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _ApplyingStore(tmp_path / "guard-home")
    signed_layer = ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind.SIGNED_CLOUD,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        False,
        (),
    )
    store.current_view = ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED,
        4,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (signed_layer,),
    )
    service = ExtensionControlApiService(
        store=cast(GuardStore, store),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(store.current_view),
    )
    monkeypatch.setattr(
        extension_control_api_module,
        "issue_extension_control_proof",
        lambda *_args, **_kwargs: cast(ExtensionControlProof, _FakeProof()),
    )
    payload = _mutation_payload()
    payload["layers"] = json.loads(layers_to_json((signed_layer,)))
    payload.update({"session_nonce": "session-1", "approval_password": "not-persisted"})

    preview = service.preview(payload)
    _ = service.apply({**payload, "proof_id": preview["proof_id"]})

    assert store.committed_layers == (signed_layer,)
    assert service.effective()["layers"] == json.loads(layers_to_json((signed_layer,)))


def test_local_apply_persists_raw_signed_but_previews_active_managed_layer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _ApplyingStore(tmp_path / "guard-home")
    raw_signed = ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind.SIGNED_CLOUD,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        False,
        (),
    )
    managed_signed = ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind.SIGNED_CLOUD,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        True,
        (),
    )
    store.current_view = ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED,
        4,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (raw_signed,),
    )
    store.managed_layers = (managed_signed,)
    store.managed_revision = 1
    service = ExtensionControlApiService(
        store=cast(GuardStore, store),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(
            ExtensionControlAuthorityView(
                AuthorityHealth.PROTECTED,
                4,
                BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
                (managed_signed,),
                1,
            )
        ),
    )
    monkeypatch.setattr(
        extension_control_api_module,
        "issue_extension_control_proof",
        lambda *_args, **_kwargs: cast(ExtensionControlProof, _FakeProof()),
    )
    payload = _mutation_payload()
    payload["layers"] = json.loads(layers_to_json((managed_signed,)))
    payload.update({"session_nonce": "session-1", "approval_password": "not-persisted"})

    preview = service.preview(payload)
    _ = service.apply({**payload, "proof_id": preview["proof_id"]})

    assert store.committed_layers == (raw_signed,)
    assert service.effective()["layers"] == json.loads(layers_to_json((managed_signed,)))
