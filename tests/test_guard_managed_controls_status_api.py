from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore


class _FailingSecretStore:
    def set_secret(self, secret_id: str, value: str) -> None:
        raise RuntimeError("SECRET_STORE_DETAIL_MUST_NOT_LEAK")

    def get_secret(self, secret_id: str) -> str | None:
        raise RuntimeError("SECRET_STORE_DETAIL_MUST_NOT_LEAK")

    def delete_secret(self, secret_id: str) -> None:
        raise RuntimeError("SECRET_STORE_DETAIL_MUST_NOT_LEAK")


def _service(store: GuardStore) -> ExtensionControlApiService:
    view = ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED,
        4,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )
    return ExtensionControlApiService(
        store=store,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(view),
    )


def test_effective_keeps_base_payload_when_optional_secret_status_fails(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("managed_controls_active", {"complete": True}, "2026-08-25T00:00:00Z")
    store._extension_control_authority_secret_store = _FailingSecretStore()  # pyright: ignore[reportPrivateUsage]

    payload = _service(store).effective()

    assert "managed_controls" not in payload
    assert payload["failures"] == [{"code": "managed-controls-status-unavailable"}]
    assert "SECRET_STORE_DETAIL_MUST_NOT_LEAK" not in json.dumps(payload)


def test_effective_degrades_safely_for_malformed_active_managed_json(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("managed_controls_active", {"complete": True}, "2026-08-25T00:00:00Z")
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        connection.execute(
            "update sync_state set payload_json = ? where state_key = ?",
            ("{malformed-active-json", "managed_controls_active"),
        )

    payload = _service(store).effective()

    assert "managed_controls" not in payload
    assert payload["failures"] == [{"code": "managed-controls-status-unavailable"}]
