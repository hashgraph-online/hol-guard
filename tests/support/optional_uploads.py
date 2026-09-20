"""Explicit current-source setup for optional-upload compatibility tests."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

import pytest

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.oauth_connection_authority import OAuthConnectionSnapshot
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.workspace_preference_authority import (
    accept_workspace_preference_response,
    capture_workspace_preference_state,
)

OPTIONAL_UPLOAD_WORKSPACE = "00000000-0000-4000-8000-000000000042"
_LEGACY_RESPONSE_TIME = "2026-07-01T00:00:00+00:00"


def seed_optional_upload_source(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    *,
    workspace_id: str = OPTIONAL_UPLOAD_WORKSPACE,
    issuer: str = "https://hol.org",
    access_token: str = "synthetic-access",
) -> None:
    """Install a complete cached source without granting upload consent."""
    assert str(UUID(workspace_id)) == workspace_id
    key = generate_dpop_key_pair()
    monkeypatch.setattr(runner, "_test_sync_auth_context_override", None)
    monkeypatch.delenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", raising=False)
    store.set_oauth_local_credentials(
        issuer=issuer,
        client_id="guard-local-daemon",
        refresh_token="synthetic-refresh",
        access_token=access_token,
        access_token_expires_at="2099-01-01T00:00:00+00:00",
        dpop_private_key_pem=key.private_key_pem,
        dpop_public_jwk=key.public_jwk,
        dpop_public_jwk_thumbprint=key.public_jwk_thumbprint,
        grant_id="synthetic-grant",
        machine_id="synthetic-machine",
        workspace_id=workspace_id,
        now=_LEGACY_RESPONSE_TIME,
    )


def confirm_legacy_optional_uploads(store: GuardStore) -> dict[str, object]:
    """Record a prior valid response for the source selected by the real resolver."""
    observed: list[OAuthConnectionSnapshot] = []
    auth_context = runner._resolve_guard_sync_auth_context(store, connection_observer=observed.append)
    assert len(observed) == 1
    assert set(auth_context) == {"sync_url", "access_token", "dpop_key_material"}
    captured = capture_workspace_preference_state(store, required_connection=observed[0])
    accepted = accept_workspace_preference_response(
        store,
        captured,
        {"syncedAt": _LEGACY_RESPONSE_TIME, "receiptsStored": 0},
        sent_revision=None,
    )
    assert accepted.state.mode == "legacy"
    assert accepted.receipt_accepted
    return auth_context


def enable_optional_upload_settings(store: GuardStore, *, receipt_redaction_level: str = "full") -> None:
    """Express the positive fixture's local consent and privacy ceiling."""
    update_guard_settings(
        store.guard_home,
        {
            "sync": True,
            "telemetry": True,
            "receipt_redaction_level": receipt_redaction_level,
        },
        cloud_sync_entitled=True,
        skip_approval_gate=True,
    )


def prepare_optional_uploads(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    *,
    issuer: str = "https://hol.org",
    sync_url: str | None = None,
    access_token: str = "synthetic-access",
    receipt_redaction_level: str = "full",
) -> None:
    """Prepare cached authority, local consent, and a prior valid legacy response."""
    if sync_url is not None:
        parsed = urlsplit(sync_url)
        issuer = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))

        def fixture_endpoint(selected_issuer: str) -> str:
            assert selected_issuer == issuer
            return sync_url

        monkeypatch.setattr(runner, "_oauth_sync_url_from_issuer", fixture_endpoint)
    seed_optional_upload_source(store, monkeypatch, issuer=issuer, access_token=access_token)
    enable_optional_upload_settings(store, receipt_redaction_level=receipt_redaction_level)
    confirm_legacy_optional_uploads(store)
