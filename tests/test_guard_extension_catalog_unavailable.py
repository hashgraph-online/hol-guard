"""Native `catalog_unavailable` replies are an unavailable downgrade, not malformed metadata."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_execution
from codex_plugin_scanner.guard.runtime import extension_catalog_handshake
from codex_plugin_scanner.guard.runtime.extension_catalog_pages import native_call, observed_view
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import ExtensionCatalogUnavailableError

SCHEMA = "guard-cloud-catalog-result.v2"
SESSION = {
    "extensionCatalogViewDigest": "a" * 64,
    "extensionCatalogEnforcementDigest": "b" * 64,
    "extensionCatalogGeneratedAt": "2026-10-26T00:00:00Z",
}


def _reply(monkeypatch, error: str) -> None:
    monkeypatch.setattr(native_execution, "_resident_request", lambda **_: {"schema": SCHEMA, "error": error})


def test_unavailable_reply_raises_unavailable(monkeypatch, tmp_path: Path) -> None:
    _reply(monkeypatch, "catalog_unavailable")
    with pytest.raises(ExtensionCatalogUnavailableError):
        native_call(tmp_path, action="observe")


def test_invalid_reply_still_fails_closed(monkeypatch, tmp_path: Path) -> None:
    _reply(monkeypatch, "catalog_invalid")
    with pytest.raises(ValueError, match="rejected metadata"):
        native_call(tmp_path, action="observe")


def test_evicted_view_downgrades_a_requested_upload(monkeypatch, tmp_path: Path) -> None:
    # The session names a view the shared cache no longer holds, for example
    # after the daemon published a newer one while pairing waited on Cloud.
    _reply(monkeypatch, "catalog_unavailable")
    observation, body = extension_catalog_handshake._observe(
        lambda _generated_at: observed_view(SESSION, tmp_path),
        {"generated_at": "2026-10-26T00:00:00Z", "purpose": "upload", "idempotency_key": "k"},
    )
    assert observation == {"outcome": "unavailable"}
    assert body is None


def test_evicted_view_downgrades_the_v2_transfer(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime import runner

    _reply(monkeypatch, "catalog_unavailable")
    result = runner._sync_extension_catalog_from_runtime_handshake(
        guard_home=tmp_path,
        auth_context={},
        runtime_sync_url="https://example.test/api/guard/runtime/sessions/sync",
        runtime_response={"extensionCatalogSync": {"protocolVersion": 2}},
        session_payload=SESSION,
    )
    assert result["extension_catalog_sync_status"] == "downgraded"
    assert result["extension_catalog_sync_reason"] == "catalog_runtime_unavailable"


def test_unavailable_after_the_transfer_is_not_a_downgrade(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime import extension_catalog_pages, extension_catalog_transfer, runner

    monkeypatch.setattr(extension_catalog_pages, "observed_view", lambda *_: object())

    def lost_lease(**_):
        raise ExtensionCatalogUnavailableError("lease released by a restarted resident")

    monkeypatch.setattr(extension_catalog_transfer, "sync_catalog_view", lost_lease)
    with pytest.raises(ExtensionCatalogUnavailableError):
        runner._sync_extension_catalog_from_runtime_handshake(
            guard_home=tmp_path,
            auth_context={},
            runtime_sync_url="https://example.test/api/guard/runtime/sessions/sync",
            runtime_response={"extensionCatalogSync": {"protocolVersion": 2}},
            session_payload=SESSION,
        )
