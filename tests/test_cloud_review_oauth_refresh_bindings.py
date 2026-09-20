"""HGP-168: OAuth refresh keeps review bindings without exposing tokens."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review, exact_cloud_review_status
from tests.guard_exact_cloud_review_support import connected_exact_review_store


def test_normal_refresh_resumes_without_tokens_in_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.cloud_review_sync_auth._with_cloud_review_sync_identity",
        lambda _store, auth_context: {**auth_context, "oauth_subject_hash": "subj"},
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.runner._resolve_guard_sync_auth_context",
        lambda _store, force_refresh=False: {"sync_url": "https://hol.example/sync", "access_token": "secret-token"},
    )
    # Bind identity helper still checks store binding; use the real helper path via status instead.
    status = exact_cloud_review_status(store)
    encoded = repr(status)
    assert "secret-token" not in encoded
    assert "refresh-token" not in encoded
    assert status["enabled"] is True


def test_changed_grant_cannot_inherit_old_capability(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    original = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(original, dict)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.exact_cloud_review._oauth_binding",
        lambda _store: {
            "deviceId": original.get("device_id"),
            "dpopThumbprint": original.get("dpop_public_jwk_thumbprint"),
            "grantId": "grant-other",
            "installationId": store.get_or_create_installation_id(),
            "machineId": original.get("machine_id"),
            "runtimeId": original.get("runtime_id") or "hol-guard",
            "workspaceId": original.get("workspace_id"),
        },
    )
    status = exact_cloud_review_status(store)
    assert status["enabled"] is False
    assert status["reason"] in {"cloud_review_capability_binding_mismatch", "cloud_review_capability_revoked"}
